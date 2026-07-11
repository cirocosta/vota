package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cirocosta/vota/internal/auditverify"
	"github.com/cirocosta/vota/internal/cli/admin"
	serverconfig "github.com/cirocosta/vota/internal/cli/server"
	"github.com/cirocosta/vota/internal/cli/trustee"
	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
)

const testPassphrase = "e2e-passphrase"

func TestAnonymousPollWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess workflow")
	}
	repository := repositoryRoot(t)
	directory := t.TempDir()
	binary := filepath.Join(directory, "vota")
	build := exec.Command("go", "build", "-o", binary, "./cmd/vota")
	build.Dir = repository
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}

	participants := make([]trustee.Participant, 3)
	trusteeKeys := make([]string, 3)
	for index := range 3 {
		trusteeKeys[index] = filepath.Join(directory, fmt.Sprintf("trustee-%d.key", index+1))
		publicPath := filepath.Join(directory, fmt.Sprintf("trustee-%d.public.json", index+1))
		run(t, binary, "", testPassphrase, "trustee", "key", "create", "--id", fmt.Sprintf("trustee-%d", index+1), "--out", trusteeKeys[index], "--public-out", publicPath, "--passphrase-fd", "3")
		readJSON(t, publicPath, &participants[index])
	}
	slices.SortFunc(participants, func(a, b trustee.Participant) int { return strings.Compare(a.ID, b.ID) })
	ceremonyConfig := trustee.CeremonyConfig{SchemaVersion: protocol.SchemaVersion, Protocol: protocol.ProtocolVersion, Quorum: 2, Trustees: participants}
	ceremonyConfigPath := filepath.Join(directory, "ceremony.config.json")
	ceremonyRequestPath := filepath.Join(directory, "ceremony.request.json")
	writeJSON(t, ceremonyConfigPath, ceremonyConfig)
	run(t, binary, "", "", "trustee", "ceremony", "init", "--config", ceremonyConfigPath, "--out", ceremonyRequestPath)
	contributionDirectory := filepath.Join(directory, "contributions")
	if err := os.Mkdir(contributionDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := range 3 {
		run(t, binary, "", testPassphrase, "trustee", "ceremony", "contribute", "--input", ceremonyRequestPath, "--key", trusteeKeys[index], "--out", filepath.Join(contributionDirectory, fmt.Sprintf("trustee-%d.json", index+1)), "--passphrase-fd", "3")
	}
	finalTrusteeKeys := make([]string, 3)
	var publicCeremony trustee.PublicCeremony
	for index := range 3 {
		finalTrusteeKeys[index] = filepath.Join(directory, fmt.Sprintf("trustee-%d.final.key", index+1))
		publicPath := filepath.Join(directory, fmt.Sprintf("ceremony-%d.public.json", index+1))
		run(t, binary, "", testPassphrase, "trustee", "ceremony", "finalize", "--input-dir", contributionDirectory, "--request", ceremonyRequestPath, "--key", trusteeKeys[index], "--out", finalTrusteeKeys[index], "--public-out", publicPath, "--passphrase-fd", "3")
		if index == 0 {
			readJSON(t, publicPath, &publicCeremony)
		}
	}

	adminKey := filepath.Join(directory, "admin.key")
	run(t, binary, "", testPassphrase, "admin", "key", "create", "--out", adminKey, "--passphrase-fd", "3")
	trustees := make([]admin.TrusteeConfig, len(publicCeremony.Trustees))
	for index, member := range publicCeremony.Trustees {
		trustees[index] = admin.TrusteeConfig{ID: member.ID, SigningKey: member.SigningKey, Commitment: member.Commitment}
	}
	now := time.Now().UTC().Truncate(time.Second)
	pollConfig := admin.PollConfig{
		Question: "Which option?",
		Choices:  []protocol.Choice{{ID: "a", Label: "Alpha"}, {ID: "b", Label: "Beta"}, {ID: "c", Label: "Gamma"}},
		Trustees: trustees, TrusteeQuorum: 2, PrivacyThreshold: 3,
		OpensAt: now.Add(-time.Hour).Format(time.RFC3339), ClosesAt: now.Add(time.Hour).Format(time.RFC3339),
	}
	pollConfigPath := filepath.Join(directory, "poll.config.json")
	draftPath := filepath.Join(directory, "poll.draft.json")
	writeJSON(t, pollConfigPath, pollConfig)
	run(t, binary, "", testPassphrase, "poll", "create", "--config", pollConfigPath, "--admin-key", adminKey, "--out", draftPath, "--passphrase-fd", "3")

	identityPaths := make([]string, 5)
	for index := range 5 {
		identityPaths[index] = filepath.Join(directory, fmt.Sprintf("voter-%d.key", index+1))
		enrollmentPath := filepath.Join(directory, fmt.Sprintf("voter-%d.enrollment.json", index+1))
		run(t, binary, "", testPassphrase, "identity", "create", "--poll", draftPath, "--out", identityPaths[index], "--passphrase-fd", "3")
		run(t, binary, "", testPassphrase, "identity", "enroll", "export", "--identity", identityPaths[index], "--out", enrollmentPath, "--passphrase-fd", "3")
		run(t, binary, "", "", "poll", "eligible", "add", "--draft", draftPath, "--enrollment", enrollmentPath)
	}
	manifestPath := filepath.Join(directory, "manifest.json")
	run(t, binary, "", testPassphrase, "poll", "freeze", "--yes", "--draft", draftPath, "--admin-key", adminKey, "--out", manifestPath, "--passphrase-fd", "3")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := manifest.Parse(manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	poll := frozen.Manifest()

	address := freeAddress(t)
	adminToken := "e2e-admin-token"
	tokenHash := sha256.Sum256([]byte(adminToken))
	collectorConfig := serverconfig.Config{
		ListenAddress: address, DatabasePath: filepath.Join(directory, "vota.sqlite"),
		PublicBaseURL: "http://" + address, AdminTokenHashes: []string{"sha256:" + hex.EncodeToString(tokenHash[:])},
		CheckpointKeyPath: filepath.Join(directory, "checkpoint.key"), ShutdownTimeout: "2s",
	}
	collectorConfigPath := filepath.Join(directory, "server.json")
	writeJSON(t, collectorConfigPath, collectorConfig)
	serverLogPath := filepath.Join(directory, "server.log")
	serverLog, err := os.Create(serverLogPath)
	if err != nil {
		t.Fatal(err)
	}
	server := exec.Command(binary, "serve", "--config", collectorConfigPath)
	server.Stdout = serverLog
	server.Stderr = serverLog
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if server.Process != nil {
			_ = server.Process.Signal(os.Interrupt)
			_, _ = server.Process.Wait()
		}
		_ = serverLog.Close()
	})
	waitHealthy(t, "http://"+address)
	baseURL := "http://" + address
	run(t, binary, "", adminToken, "poll", "publish", "--manifest", manifestPath, "--server", baseURL, "--admin-token-fd", "3")

	ballotPaths := make([]string, 3)
	for index, choice := range []string{"a", "b", "a"} {
		ballotPaths[index] = filepath.Join(directory, fmt.Sprintf("ballot-%d.json", index+1))
		castOutput := run(t, binary, choice+"\n", testPassphrase, "vote", "cast", "--choice-stdin", "--poll", manifestPath, "--identity", identityPaths[index], "--out", ballotPaths[index], "--passphrase-fd", "3")
		for _, label := range []string{"Alpha", "Beta", "Gamma"} {
			if strings.Contains(castOutput, label) {
				t.Fatalf("cast output disclosed choice label %q: %s", label, castOutput)
			}
		}
		receiptPath := filepath.Join(directory, fmt.Sprintf("receipt-%d.json", index+1))
		run(t, binary, "", "", "vote", "submit", "--ballot", ballotPaths[index], "--server", baseURL, "--receipt", receiptPath)
	}

	doubleBallot := filepath.Join(directory, "double-vote.json")
	run(t, binary, "c\n", testPassphrase, "vote", "cast", "--choice-stdin", "--poll", manifestPath, "--identity", identityPaths[0], "--out", doubleBallot, "--passphrase-fd", "3")
	if output, err := runError(binary, "", "", "vote", "submit", "--ballot", doubleBallot, "--server", baseURL, "--receipt", filepath.Join(directory, "double.receipt.json")); err == nil || !strings.Contains(output, "double_vote") {
		t.Fatalf("double vote output = %q, error = %v", output, err)
	}
	ineligibleIdentity := filepath.Join(directory, "ineligible.key")
	run(t, binary, "", testPassphrase, "identity", "create", "--poll", poll.PollDraftID, "--out", ineligibleIdentity, "--passphrase-fd", "3")
	if output, err := runError(binary, "a\n", testPassphrase, "vote", "cast", "--choice-stdin", "--poll", manifestPath, "--identity", ineligibleIdentity, "--out", filepath.Join(directory, "ineligible-ballot.json"), "--passphrase-fd", "3"); err == nil || !strings.Contains(output, "identity_not_eligible") {
		t.Fatalf("ineligible output = %q, error = %v", output, err)
	}

	aggregateOutput := run(t, binary, "", adminToken, "poll", "close", "--poll", poll.PollID, "--server", baseURL, "--admin-token-fd", "3", "--json")
	aggregatePath := filepath.Join(directory, "aggregate.json")
	if err := os.WriteFile(aggregatePath, []byte(strings.TrimSpace(aggregateOutput)), 0o644); err != nil {
		t.Fatal(err)
	}
	for index := range 2 {
		sharePath := filepath.Join(directory, fmt.Sprintf("share-%d.json", index+1))
		run(t, binary, "", testPassphrase, "trustee", "tally-share", "--poll", manifestPath, "--aggregate", aggregatePath, "--key", finalTrusteeKeys[index], "--out", sharePath, "--passphrase-fd", "3")
		run(t, binary, "", "", "tally", "submit-share", "--share", sharePath, "--server", baseURL)
	}
	tallyPath := filepath.Join(directory, "tally.json")
	run(t, binary, "", "", "tally", "get", "--poll", poll.PollID, "--server", baseURL, "--out", tallyPath)
	var tally protocol.Tally
	readJSON(t, tallyPath, &tally)
	if len(tally.Totals) != 3 || tally.Totals[0].Total != 2 || tally.Totals[1].Total != 1 || tally.Totals[2].Total != 0 {
		t.Fatalf("tally totals = %+v", tally.Totals)
	}

	recordDirectory := filepath.Join(directory, "audit-record")
	run(t, binary, "", "", "audit", "export", "--poll", poll.PollID, "--server", baseURL, "--out", recordDirectory)
	verificationOutput := run(t, binary, "", "", "audit", "verify", "--record", recordDirectory, "--json")
	var report auditverify.Report
	if err := protocol.DecodeStrict([]byte(verificationOutput), &report); err != nil {
		t.Fatalf("decode audit report: %v\n%s", err, verificationOutput)
	}
	if report.PollID != poll.PollID || report.AcceptedBallotCount != 3 || len(report.ValidTrusteeIDs) != 2 {
		t.Fatalf("audit report = %+v", report)
	}

	for _, path := range append(ballotPaths, filepath.Join(recordDirectory, "record.json")) {
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"private_key", "passphrase", "selected_choice"} {
			if bytes.Contains(encoded, []byte(forbidden)) {
				t.Fatalf("public artifact %s contains %q", path, forbidden)
			}
		}
	}

	if err := server.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if err := server.Wait(); err != nil {
		t.Fatalf("server shutdown: %v", err)
	}
	_ = serverLog.Close()
	server.Process = nil
	logs, err := os.ReadFile(serverLogPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, prohibited := range []string{adminToken, testPassphrase, "nullifier", "ballot_hash"} {
		if bytes.Contains(logs, []byte(prohibited)) {
			t.Fatalf("server logs contain %q", prohibited)
		}
	}
}

func run(tb testing.TB, binary, stdin, secret string, arguments ...string) string {
	tb.Helper()
	output, err := runError(binary, stdin, secret, arguments...)
	if err != nil {
		tb.Fatalf("vota %s: %v\n%s", strings.Join(arguments, " "), err, output)
	}
	return output
}

func runError(binary, stdin, secret string, arguments ...string) (string, error) {
	command := exec.Command(binary, arguments...)
	command.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	var secretFile *os.File
	if secret != "" {
		var err error
		secretFile, err = os.CreateTemp("", "vota-e2e-secret-*")
		if err != nil {
			return "", err
		}
		defer os.Remove(secretFile.Name())
		defer secretFile.Close()
		if _, err := secretFile.WriteString(secret + "\n"); err != nil {
			return "", err
		}
		if _, err := secretFile.Seek(0, 0); err != nil {
			return "", err
		}
		command.ExtraFiles = []*os.File{secretFile}
	}
	err := command.Run()
	if err != nil {
		return stdout.String() + stderr.String(), err
	}
	return stdout.String(), nil
}

func writeJSON(tb testing.TB, path string, value any) {
	tb.Helper()
	encoded, err := protocol.MarshalCanonical(value)
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		tb.Fatal(err)
	}
}

func readJSON(tb testing.TB, path string, target any) {
	tb.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	if err := protocol.DecodeStrict(encoded, target); err != nil {
		tb.Fatal(err)
	}
}

func freeAddress(tb testing.TB) string {
	tb.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func waitHealthy(tb testing.TB, baseURL string) {
	tb.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(baseURL + "/healthz")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	tb.Fatal("collector did not become healthy")
}

func repositoryRoot(tb testing.TB) string {
	tb.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		tb.Fatal("resolve source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}
