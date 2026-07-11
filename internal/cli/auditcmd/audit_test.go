package auditcmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cirocosta/vota/internal/app"
	"github.com/cirocosta/vota/internal/audit"
	"github.com/cirocosta/vota/internal/httpclient"
	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/spf13/cobra"
)

func TestExportAndOfflineVerifyCommands(t *testing.T) {
	encoded, pollID := openRecord(t)
	collector := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/polls/"+pollID+"/audit" {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(encoded)
	}))
	defer collector.Close()
	options := Options{HTTPClient: func(server string) (*httpclient.Client, error) { return httpclient.New(server, collector.Client()) }}
	recordDirectory := filepath.Join(t.TempDir(), "record")
	export := commandRoot(options)
	export.SetArgs([]string{"audit", "export", "--poll", pollID, "--server", collector.URL, "--out", recordDirectory})
	if err := export.Execute(); err != nil {
		t.Fatalf("export: %v", err)
	}
	written, err := os.ReadFile(filepath.Join(recordDirectory, "record.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written, encoded) {
		t.Fatal("exported record changed")
	}
	verify := commandRoot(options)
	var output bytes.Buffer
	verify.SetOut(&output)
	verify.SetArgs([]string{"audit", "verify", "--record", recordDirectory, "--json"})
	if err := verify.Execute(); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(output.String(), `"poll_id":"`+pollID+`"`) || !strings.Contains(output.String(), `"event_count":1`) {
		t.Fatalf("verification output = %s", output.String())
	}
	compare := commandRoot(options)
	compare.SetArgs([]string{"audit", "compare", "--first", recordDirectory, "--second", recordDirectory})
	if err := compare.Execute(); err != nil {
		t.Fatalf("compare: %v", err)
	}
}

func TestCompareCommandRejectsForkWithSparseCheckpoints(t *testing.T) {
	first, second := sparseForkRecords(t)
	directory := t.TempDir()
	firstPath := filepath.Join(directory, "first.json")
	secondPath := filepath.Join(directory, "second.json")
	if err := os.WriteFile(firstPath, first, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, second, 0o600); err != nil {
		t.Fatal(err)
	}
	command := commandRoot(Options{})
	command.SetArgs([]string{"audit", "compare", "--first", firstPath, "--second", secondPath})
	if err := command.Execute(); audit.ErrorCode(err) != "audit_fork_detected" {
		t.Fatalf("compare error = %v", err)
	}
}

func openRecord(tb testing.TB) ([]byte, string) {
	tb.Helper()
	manifestBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "manifest", "canonical.json"))
	if err != nil {
		tb.Fatal(err)
	}
	frozen, err := manifest.Parse(manifestBytes)
	if err != nil {
		tb.Fatal(err)
	}
	value := frozen.Manifest()
	manifestHash, err := app.ManifestHash(value)
	if err != nil {
		tb.Fatal(err)
	}
	event, err := audit.Genesis(value.PollID, "poll_published", manifestHash, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC))
	if err != nil {
		tb.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	checkpoint, err := audit.CreateCheckpoint(privateKey, []protocol.AuditEvent{event})
	if err != nil {
		tb.Fatal(err)
	}
	encoded, err := audit.Export(audit.Bundle{
		SchemaVersion: protocol.SchemaVersion, Protocol: protocol.ProtocolVersion,
		Manifest: value, Events: []protocol.AuditEvent{event}, Checkpoints: []protocol.Checkpoint{checkpoint},
	}, privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		tb.Fatal(err)
	}
	return encoded, value.PollID
}

func sparseForkRecords(tb testing.TB) ([]byte, []byte) {
	tb.Helper()
	manifestBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "manifest", "canonical.json"))
	if err != nil {
		tb.Fatal(err)
	}
	frozen, err := manifest.Parse(manifestBytes)
	if err != nil {
		tb.Fatal(err)
	}
	value := frozen.Manifest()
	when := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	genesis, err := audit.Genesis(value.PollID, "poll_published", hashValue("manifest"), when)
	if err != nil {
		tb.Fatal(err)
	}
	left, err := audit.Append([]protocol.AuditEvent{genesis}, value.PollID, "ballot_accepted", hashValue("left"), when.Add(time.Minute))
	if err != nil {
		tb.Fatal(err)
	}
	right, err := audit.Append([]protocol.AuditEvent{genesis}, value.PollID, "ballot_accepted", hashValue("right"), when.Add(time.Minute))
	if err != nil {
		tb.Fatal(err)
	}
	tail, err := audit.Append([]protocol.AuditEvent{genesis, right}, value.PollID, "ballot_accepted", hashValue("tail"), when.Add(2*time.Minute))
	if err != nil {
		tb.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	return exportSparseBundle(tb, value, []protocol.AuditEvent{genesis, left}, privateKey),
		exportSparseBundle(tb, value, []protocol.AuditEvent{genesis, right, tail}, privateKey)
}

func exportSparseBundle(tb testing.TB, value protocol.Manifest, events []protocol.AuditEvent, privateKey ed25519.PrivateKey) []byte {
	tb.Helper()
	checkpoint, err := audit.CreateCheckpoint(privateKey, events)
	if err != nil {
		tb.Fatal(err)
	}
	encoded, err := audit.Export(audit.Bundle{
		SchemaVersion: protocol.SchemaVersion,
		Protocol:      protocol.ProtocolVersion,
		Manifest:      value,
		Events:        events,
		Checkpoints:   []protocol.Checkpoint{checkpoint},
	}, privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		tb.Fatal(err)
	}
	return encoded
}

func hashValue(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func commandRoot(options Options) *cobra.Command {
	root := &cobra.Command{Use: "vota", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(Command(options))
	return root
}
