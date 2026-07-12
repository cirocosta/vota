package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cirocosta/vota/internal/crypto/blind"
	"github.com/cirocosta/vota/internal/sequencer"
	"github.com/cirocosta/vota/internal/sequencerstore"
	"golang.org/x/crypto/ssh"
)

func TestSequencerAPIRejectsNoncanonicalAndOversizedBodiesWithoutLoggingThem(t *testing.T) {
	service := testSequencerService(t)
	var logs bytes.Buffer
	api, err := NewSequencer(SequencerConfig{Service: service, MaxBodyBytes: 64, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api)
	defer server.Close()

	secret := "do-not-log-this-credential"
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v2/polls", strings.NewReader(`{ "question": "`+secret+`" }`))
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("noncanonical status = %d", response.StatusCode)
	}

	request, _ = http.NewRequest(http.MethodPost, server.URL+"/v2/polls", strings.NewReader(strings.Repeat("x", 65)))
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d", response.StatusCode)
	}
	if strings.Contains(logs.String(), secret) || strings.Contains(logs.String(), strings.Repeat("x", 20)) {
		t.Fatalf("request body leaked to logs: %s", logs.String())
	}
}

func TestSequencerReadiness(t *testing.T) {
	api, err := NewSequencer(SequencerConfig{Service: testSequencerService(t), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	api.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != `{"status":"ready"}` {
		t.Fatalf("readiness = %d %s", response.Code, response.Body.String())
	}
}

func testSequencerService(tb testing.TB) *sequencer.Service {
	tb.Helper()
	store, err := sequencerstore.Open(context.Background(), ":memory:")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = store.Close() })
	issuer, err := rsa.GenerateKey(rand.Reader, blind.MinRSAKeyBits)
	if err != nil {
		tb.Fatal(err)
	}
	_, checkpoint, _ := ed25519.GenerateKey(rand.Reader)
	_, adminPrivate, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := ssh.NewPublicKey(adminPrivate.Public())
	service, err := sequencer.New(sequencer.Config{Store: store, IssuerPrivateKey: issuer, CheckpointPrivateKey: checkpoint, AdminPublicKeys: []string{string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(admin)))}})
	if err != nil {
		tb.Fatal(err)
	}
	return service
}
