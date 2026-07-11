package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cirocosta/vota/internal/app"
	"github.com/cirocosta/vota/internal/audit"
	"github.com/cirocosta/vota/internal/crypto/election"
	"github.com/cirocosta/vota/internal/crypto/lrs"
	"github.com/cirocosta/vota/internal/httpclient"
	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/store"
)

const adminToken = "test-admin-token-never-log"

func TestHTTPWorkflowContract(t *testing.T) {
	api, service, _ := testAPI(t, Config{})
	server := httptest.NewServer(api)
	defer server.Close()
	client, err := httpclient.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	value := fixtureManifest(t)

	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/polls", bytes.NewReader(mustCanonical(t, value)))
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	assertErrorResponse(t, response, http.StatusUnauthorized, "unauthorized")

	if _, created, err := client.PublishPoll(context.Background(), value, adminToken); err != nil || !created {
		t.Fatalf("publish created = %v, error = %v", created, err)
	}
	if _, created, err := client.PublishPoll(context.Background(), value, adminToken); err != nil || created {
		t.Fatalf("publish retry created = %v, error = %v", created, err)
	}
	status, err := client.Poll(context.Background(), value.PollID)
	if err != nil || status.State != "open" || status.Manifest.PollID != value.PollID {
		t.Fatalf("poll status = %+v, error = %v", status, err)
	}
	if _, err := client.Tally(context.Background(), value.PollID); httpErrorStatusCode(err) != "404:tally_unavailable" {
		t.Fatalf("unavailable tally error = %v", err)
	}
	ballot := fixtureBallot(t)
	receipt, created, err := client.SubmitBallot(context.Background(), ballot)
	if err != nil || !created {
		t.Fatalf("submit created = %v, error = %v", created, err)
	}
	retry, created, err := client.SubmitBallot(context.Background(), ballot)
	if err != nil || created || retry != receipt {
		t.Fatalf("submit retry created = %v, error = %v", created, err)
	}
	storedReceipt, err := client.Receipt(context.Background(), value.PollID, ballot.BallotHash)
	if err != nil || storedReceipt != receipt {
		t.Fatalf("receipt = %+v, error = %v", storedReceipt, err)
	}
	privateKey, signerIndex := fixtureCredential(t, value, "voter-0")
	doubleVote, err := app.CastBallot(value, privateKey, signerIndex, 0, newHashReader("http-double-vote"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.SubmitBallot(context.Background(), doubleVote); httpErrorStatusCode(err) != "409:double_vote" {
		t.Fatalf("double vote error = %v", err)
	}
	aggregate, err := client.ClosePoll(context.Background(), value.PollID, adminToken)
	if err != nil || aggregate.BallotCount != 1 {
		t.Fatalf("aggregate = %+v, error = %v", aggregate, err)
	}
	otherKey, otherIndex := fixtureCredential(t, value, "voter-1")
	closedBallot, _ := app.CastBallot(value, otherKey, otherIndex, 0, newHashReader("http-closed-ballot"))
	if _, _, err := client.SubmitBallot(context.Background(), closedBallot); httpErrorStatusCode(err) != "409:poll_closed" {
		t.Fatalf("closed poll error = %v", err)
	}
	secrets := fixtureTrusteeSecrets(t)
	for index := range 2 {
		share := fixtureShare(t, value, aggregate, index, secrets[index])
		if tally, created, err := client.SubmitTrusteeShare(context.Background(), share); err != nil || !created || tally != nil {
			t.Fatalf("share %d tally = %+v, created = %v, error = %v", index, tally, created, err)
		}
	}
	if _, err := client.Tally(context.Background(), value.PollID); httpErrorCode(err) != "privacy_threshold_not_met" {
		t.Fatalf("tally error = %v", err)
	}
	bundle, err := client.Audit(context.Background(), value.PollID)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if _, err := audit.ParseBundle(bundle, service.CheckpointPublicKey()); err != nil {
		t.Fatalf("verify audit: %v", err)
	}
}

func TestHTTPInputLimitsAndCanonicalJSON(t *testing.T) {
	api, _, _ := testAPI(t, Config{MaxBodyBytes: 64})
	server := httptest.NewServer(api)
	defer server.Close()

	tests := []struct {
		name        string
		contentType string
		body        string
		status      int
		code        string
	}{
		{"content type", "text/plain", `{}`, http.StatusUnsupportedMediaType, "unsupported_content_type"},
		{"too large", "application/json", strings.Repeat(" ", 65), http.StatusRequestEntityTooLarge, "request_too_large"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/polls/x/ballots", strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			assertErrorResponse(t, response, test.status, test.code)
		})
	}

	api, _, _ = testAPI(t, Config{})
	server.Config.Handler = api
	value := fixtureManifest(t)
	pretty, _ := json.MarshalIndent(value, "", "  ")
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/polls", bytes.NewReader(pretty))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+adminToken)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	assertErrorResponse(t, response, http.StatusUnprocessableEntity, "noncanonical_manifest")
}

func TestReadinessTimeoutAndHealth(t *testing.T) {
	api, _, _ := testAPI(t, Config{
		RequestTimeout: 10 * time.Millisecond,
		Ready: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	})
	server := httptest.NewServer(api)
	defer server.Close()
	response, err := server.Client().Get(server.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	assertErrorResponse(t, response, http.StatusServiceUnavailable, "not_ready")
	response, err = server.Client().Get(server.URL + "/healthz")
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("health status = %v, error = %v", response.Status, err)
	}
	_ = response.Body.Close()
}

func TestVerificationConcurrencyLimit(t *testing.T) {
	database := openStore(t)
	normal := newService(t, database, nil)
	value := fixtureManifest(t)
	if _, _, err := normal.PublishPoll(context.Background(), mustCanonical(t, value)); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	blocked := newService(t, database, func() error {
		once.Do(func() { close(entered) })
		<-release
		return nil
	})
	api, err := New(Config{Service: blocked, AdminTokenHashes: [][32]byte{HashAdminToken(adminToken)}, VerificationConcurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api)
	defer server.Close()
	body := mustCanonical(t, fixtureBallot(t))
	firstDone := make(chan *http.Response, 1)
	go func() {
		request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/polls/"+value.PollID+"/ballots", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response, _ := server.Client().Do(request)
		firstDone <- response
	}()
	<-entered
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/polls/"+value.PollID+"/ballots", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	assertErrorResponse(t, response, http.StatusServiceUnavailable, "verification_busy")
	close(release)
	response = <-firstDone
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("first status = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	metrics := api.Metrics()
	if metrics.RejectedBusy != 1 || metrics.ActiveVerifications != 0 {
		t.Fatalf("metrics = %+v", metrics)
	}
}

func TestIncompleteBodyDoesNotConsumeVerificationSlot(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{name: "ballot", path: "/v1/polls/%s/ballots"},
		{name: "trustee share", path: "/v1/polls/%s/tally-shares"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api, service, _ := testAPI(t, Config{VerificationConcurrency: 1})
			value := fixtureManifest(t)
			if _, _, err := service.PublishPoll(context.Background(), mustCanonical(t, value)); err != nil {
				t.Fatal(err)
			}

			body := &blockingRequestBody{
				entered: make(chan struct{}),
				release: make(chan struct{}),
			}
			blockedRequest := httptest.NewRequest(http.MethodPost, fmt.Sprintf(test.path, value.PollID), body)
			blockedRequest.Header.Set("Content-Type", "application/json")
			blockedResponse := httptest.NewRecorder()
			blockedDone := make(chan int, 1)
			go func() {
				api.ServeHTTP(blockedResponse, blockedRequest)
				blockedDone <- blockedResponse.Code
			}()

			select {
			case <-body.entered:
			case <-time.After(time.Second):
				close(body.release)
				t.Fatal("timed out waiting for blocked body read")
			}

			active := api.Metrics().ActiveVerifications
			ballotRequest := httptest.NewRequest(
				http.MethodPost,
				"/v1/polls/"+value.PollID+"/ballots",
				bytes.NewReader(mustCanonical(t, fixtureBallot(t))),
			)
			ballotRequest.Header.Set("Content-Type", "application/json")
			ballotResponse := httptest.NewRecorder()
			api.ServeHTTP(ballotResponse, ballotRequest)

			close(body.release)
			blockedStatus := <-blockedDone

			if active != 0 {
				t.Fatalf("active verifications during body read = %d, want 0", active)
			}
			if ballotResponse.Code != http.StatusCreated {
				t.Fatalf("ballot status = %d, want %d", ballotResponse.Code, http.StatusCreated)
			}
			if blockedStatus != http.StatusUnprocessableEntity {
				t.Fatalf("blocked status = %d, want %d", blockedStatus, http.StatusUnprocessableEntity)
			}
		})
	}
}

func TestLogsAndMetricsExcludeSensitiveFields(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	api, _, _ := testAPI(t, Config{Logger: logger})
	server := httptest.NewServer(api)
	defer server.Close()
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/polls", bytes.NewReader(mustCanonical(t, fixtureManifest(t))))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+adminToken)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	output := logs.String()
	for _, prohibited := range []string{adminToken, "nullifier", "ballot_hash", "choice", "127.0.0.1"} {
		if strings.Contains(output, prohibited) {
			t.Fatalf("log contains %q: %s", prohibited, output)
		}
	}
	metrics := mustCanonical(t, api.Metrics())
	for _, field := range []string{"http_requests_total", "http_errors_total", "verification_active", "verification_rejected_total"} {
		if !bytes.Contains(metrics, []byte(field)) {
			t.Fatalf("metrics omit %q", field)
		}
	}
}

func TestServerTimeoutDefaultsAndShutdown(t *testing.T) {
	api, _, _ := testAPI(t, Config{})
	server := NewServer(ServerConfig{Address: "127.0.0.1:0", Handler: api})
	if server.ReadHeaderTimeout == 0 || server.ReadTimeout == 0 || server.WriteTimeout == 0 || server.IdleTimeout == 0 || server.MaxHeaderBytes == 0 {
		t.Fatalf("server limits = %+v", server)
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := Shutdown(ctx, server); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := <-done; err != nil && err != http.ErrServerClosed {
		t.Fatalf("serve: %v", err)
	}
}

func testAPI(tb testing.TB, config Config) (*API, *app.Service, *store.Store) {
	tb.Helper()
	database := openStore(tb)
	service := newService(tb, database, nil)
	config.Service = service
	config.AdminTokenHashes = [][32]byte{HashAdminToken(adminToken)}
	api, err := New(config)
	if err != nil {
		tb.Fatalf("new API: %v", err)
	}
	return api, service, database
}

func openStore(tb testing.TB) *store.Store {
	tb.Helper()
	database, err := store.Open(context.Background(), filepath.Join(tb.TempDir(), "vota.db"))
	if err != nil {
		tb.Fatalf("open store: %v", err)
	}
	tb.Cleanup(func() { _ = database.Close() })
	return database
}

func newService(tb testing.TB, database *store.Store, beforeCommit func() error) *app.Service {
	tb.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xa1}, ed25519.SeedSize))
	service, err := app.NewService(database, key, app.ServiceOptions{
		Now:          func() time.Time { return time.Date(2026, 8, 1, 13, 0, 0, 0, time.UTC) },
		BeforeCommit: beforeCommit,
	})
	if err != nil {
		tb.Fatalf("new service: %v", err)
	}
	return service
}

func fixtureManifest(tb testing.TB) protocol.Manifest {
	tb.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "manifest", "canonical.json"))
	if err != nil {
		tb.Fatal(err)
	}
	frozen, err := manifest.Parse(bytes.TrimSpace(data))
	if err != nil {
		tb.Fatal(err)
	}
	return frozen.Manifest()
}

func fixtureBallot(tb testing.TB) protocol.BallotEnvelope {
	tb.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "app", "ballot.json"))
	if err != nil {
		tb.Fatal(err)
	}
	ballot, err := app.ParseBallot(bytes.TrimSpace(data))
	if err != nil {
		tb.Fatal(err)
	}
	return ballot
}

func fixtureTrusteeSecrets(tb testing.TB) []election.TrusteeSecretShare {
	tb.Helper()
	contributions := make([]election.DealerContribution, 3)
	public := make([]election.PublicContribution, 3)
	for index := range 3 {
		contribution, err := election.GenerateDealerContribution(index+1, 3, 2, newHashReader(fmt.Sprintf("dealer-%d", index)))
		if err != nil {
			tb.Fatal(err)
		}
		contributions[index] = contribution
		public[index] = contribution.Public()
	}
	secrets := make([]election.TrusteeSecretShare, 3)
	for recipient := 1; recipient <= 3; recipient++ {
		shares := make([]election.DealerShare, 3)
		for dealer := range 3 {
			shares[dealer], _ = contributions[dealer].ShareFor(recipient)
		}
		secret, err := election.FinalizeTrusteeShare(public, shares, recipient)
		if err != nil {
			tb.Fatal(err)
		}
		secrets[recipient-1] = secret
	}
	return secrets
}

func fixtureShare(tb testing.TB, value protocol.Manifest, aggregate protocol.EncryptedAggregate, index int, secret election.TrusteeSecretShare) protocol.TrusteeShare {
	tb.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(0x51 + index)}, ed25519.SeedSize))
	share, err := app.CreateTrusteeShare(value, aggregate, fmt.Sprintf("trustee-%d", index+1), secret, key, newHashReader(fmt.Sprintf("http-share-%d", index)))
	if err != nil {
		tb.Fatal(err)
	}
	return share
}

func mustCanonical(tb testing.TB, value any) []byte {
	tb.Helper()
	encoded, err := protocol.MarshalCanonical(value)
	if err != nil {
		tb.Fatal(err)
	}
	return encoded
}

func assertErrorResponse(tb testing.TB, response *http.Response, status int, code string) {
	tb.Helper()
	defer response.Body.Close()
	if response.StatusCode != status {
		body, _ := io.ReadAll(response.Body)
		tb.Fatalf("status = %d, want %d, body = %s", response.StatusCode, status, body)
	}
	var envelope struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		tb.Fatal(err)
	}
	if envelope.Error.Code != code || envelope.Error.RequestID == "" {
		tb.Fatalf("error = %+v", envelope.Error)
	}
}

func httpErrorCode(err error) string {
	if typed, ok := err.(*httpclient.Error); ok {
		return typed.Code
	}
	return ""
}

func httpErrorStatusCode(err error) string {
	if typed, ok := err.(*httpclient.Error); ok {
		return fmt.Sprintf("%d:%s", typed.Status, typed.Code)
	}
	return ""
}

type blockingRequestBody struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (body *blockingRequestBody) Read([]byte) (int, error) {
	body.once.Do(func() { close(body.entered) })
	<-body.release
	return 0, io.EOF
}

func fixtureCredential(tb testing.TB, value protocol.Manifest, seed string) (lrs.PrivateKey, int) {
	tb.Helper()
	privateKey, publicKey, err := lrs.GenerateKey(newHashReader(seed))
	if err != nil {
		tb.Fatal(err)
	}
	encoded := fmt.Sprintf("ristretto255:%x", publicKey)
	for index, member := range value.EligibleKeys {
		if member == encoded {
			return privateKey, index
		}
	}
	tb.Fatalf("credential %q not found", seed)
	return lrs.PrivateKey{}, -1
}

type hashReader struct {
	seed    []byte
	counter uint64
	buffer  []byte
}

func newHashReader(seed string) io.Reader { return &hashReader{seed: []byte(seed)} }

func (reader *hashReader) Read(output []byte) (int, error) {
	written := 0
	for written < len(output) {
		if len(reader.buffer) == 0 {
			input := append([]byte(nil), reader.seed...)
			input = append(input, byte(reader.counter>>56), byte(reader.counter>>48), byte(reader.counter>>40), byte(reader.counter>>32), byte(reader.counter>>24), byte(reader.counter>>16), byte(reader.counter>>8), byte(reader.counter))
			digest := sha512.Sum512(input)
			reader.buffer = append(reader.buffer[:0], digest[:]...)
			reader.counter++
		}
		count := copy(output[written:], reader.buffer)
		reader.buffer = reader.buffer[count:]
		written += count
	}
	return written, nil
}
