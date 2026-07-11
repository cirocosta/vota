package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
)

func TestGenesisAppendCheckpointAndReceipt(t *testing.T) {
	t.Parallel()

	frozen := testManifest(t)
	pollID := frozen.Manifest().PollID
	events := testEvents(t, pollID)
	head, err := Replay(events)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if head != events[1].EventHash || events[0].PreviousHash != zeroHash {
		t.Fatalf("head = %s, events = %+v", head, events)
	}
	privateKey := checkpointPrivateKey()
	checkpoint, err := CreateCheckpoint(privateKey, events)
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if err := VerifyCheckpoint(publicKey, checkpoint); err != nil {
		t.Fatalf("verify checkpoint: %v", err)
	}
	receipt, err := CreateReceipt(privateKey, events[1].ObjectHash, events[1], checkpoint)
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if err := VerifyReceipt(publicKey, receipt, events[1], checkpoint); err != nil {
		t.Fatalf("verify receipt: %v", err)
	}
	receiptBytes, err := protocol.MarshalCanonical(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptFixture, err := os.ReadFile(filepath.Join("..", "..", "testdata", "audit", "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(receiptBytes, bytes.TrimSpace(receiptFixture)) {
		t.Fatalf("receipt differs from fixture: %s", receiptBytes)
	}
	mutated := receipt
	mutated.BallotHash = hashValue("other-ballot")
	if err := VerifyReceipt(publicKey, mutated, events[1], checkpoint); ErrorCode(err) != "receipt_binding_mismatch" {
		t.Fatalf("receipt mutation error = %v", err)
	}
}

func TestReplayRejectsEveryChainMutation(t *testing.T) {
	t.Parallel()

	events := testEvents(t, testManifest(t).Manifest().PollID)
	tests := []struct {
		name   string
		mutate func([]protocol.AuditEvent) []protocol.AuditEvent
	}{
		{"delete", func(values []protocol.AuditEvent) []protocol.AuditEvent { return values[1:] }},
		{"insert", func(values []protocol.AuditEvent) []protocol.AuditEvent {
			return append(values[:1], append([]protocol.AuditEvent{values[0]}, values[1:]...)...)
		}},
		{"reorder", func(values []protocol.AuditEvent) []protocol.AuditEvent {
			values[0], values[1] = values[1], values[0]
			return values
		}},
		{"object", func(values []protocol.AuditEvent) []protocol.AuditEvent {
			values[1].ObjectHash = hashValue("changed")
			return values
		}},
		{"type", func(values []protocol.AuditEvent) []protocol.AuditEvent {
			values[1].Type = "poll_closed"
			return values
		}},
		{"time", func(values []protocol.AuditEvent) []protocol.AuditEvent {
			values[1].AcceptedAt = "2026-07-11T12:00:00-04:00"
			return values
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := test.mutate(append([]protocol.AuditEvent(nil), events...))
			if _, err := Replay(mutated); ErrorCode(err) != "audit_chain_mismatch" {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestBundleExportParseAndPublicSchema(t *testing.T) {
	t.Parallel()

	frozen := testManifest(t)
	events := testEvents(t, frozen.Manifest().PollID)
	privateKey := checkpointPrivateKey()
	firstCheckpoint, err := CreateCheckpoint(privateKey, events[:1])
	if err != nil {
		t.Fatal(err)
	}
	secondCheckpoint, err := CreateCheckpoint(privateKey, events)
	if err != nil {
		t.Fatal(err)
	}
	bundle := Bundle{
		SchemaVersion: protocol.SchemaVersion,
		Protocol:      protocol.ProtocolVersion,
		Manifest:      frozen.Manifest(),
		Events:        events,
		Checkpoints:   []protocol.Checkpoint{firstCheckpoint, secondCheckpoint},
	}
	encoded, err := Export(bundle, privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	fixture, err := os.ReadFile(filepath.Join("..", "..", "testdata", "audit", "reference.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if !bytes.Equal(encoded, bytes.TrimSpace(fixture)) {
		t.Fatalf("bundle differs from reference fixture:\n%s", encoded)
	}
	parsed, err := ParseBundle(encoded, privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.Events) != 2 || parsed.Events[1].EventHash != events[1].EventHash {
		t.Fatalf("parsed events = %+v", parsed.Events)
	}
	for _, forbidden := range []string{"private_key", "plaintext", "selected_choice", "passphrase"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("public bundle contains %q", forbidden)
		}
	}
}

func TestCompareCheckpointsDetectsFork(t *testing.T) {
	t.Parallel()

	pollID := testManifest(t).Manifest().PollID
	firstEvents := testEvents(t, pollID)
	secondEvents := append([]protocol.AuditEvent(nil), firstEvents[:1]...)
	forked, err := Append(secondEvents, pollID, "ballot_accepted", hashValue("forked-ballot"), time.Date(2026, 7, 11, 12, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	secondEvents = append(secondEvents, forked)
	privateKey := checkpointPrivateKey()
	first, _ := CreateCheckpoint(privateKey, firstEvents)
	second, _ := CreateCheckpoint(privateKey, secondEvents)
	if err := CompareCheckpoints(privateKey.Public().(ed25519.PublicKey), first, second); ErrorCode(err) != "audit_fork_detected" {
		t.Fatalf("fork error = %v", err)
	}
}

func testManifest(tb testing.TB) manifest.Frozen {
	tb.Helper()
	encoded, err := os.ReadFile(filepath.Join("..", "..", "testdata", "manifest", "canonical.json"))
	if err != nil {
		tb.Fatalf("read manifest: %v", err)
	}
	frozen, err := manifest.Parse(bytes.TrimSpace(encoded))
	if err != nil {
		tb.Fatalf("parse manifest: %v", err)
	}
	return frozen
}

func testEvents(tb testing.TB, pollID string) []protocol.AuditEvent {
	tb.Helper()
	first, err := Genesis(pollID, "poll_published", hashValue("manifest"), time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC))
	if err != nil {
		tb.Fatalf("genesis: %v", err)
	}
	second, err := Append([]protocol.AuditEvent{first}, pollID, "ballot_accepted", hashValue("ballot"), time.Date(2026, 7, 11, 12, 1, 0, 0, time.UTC))
	if err != nil {
		tb.Fatalf("append: %v", err)
	}
	return []protocol.AuditEvent{first, second}
}

func checkpointPrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x91}, ed25519.SeedSize))
}

func hashValue(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func TestBundleFieldInventory(t *testing.T) {
	t.Parallel()

	fields := []string{"schema_version", "protocol", "checkpoint_key", "manifest", "events", "ballots", "aggregate", "shares", "tally", "checkpoints"}
	slices.Sort(fields)
	encoded, err := protocol.MarshalCanonical(Bundle{})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range fields {
		if !strings.Contains(string(encoded), `"`+field+`"`) {
			t.Fatalf("bundle schema omits %q", field)
		}
	}
}
