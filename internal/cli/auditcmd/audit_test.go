package auditcmd

import (
	"bytes"
	"crypto/ed25519"
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

func commandRoot(options Options) *cobra.Command {
	root := &cobra.Command{Use: "vota", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(Command(options))
	return root
}
