package sequenceraudit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/sequencer"
)

func TestDeterministicClosedPollFixture(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("testdata", "closed-poll.json"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := DecodeAndVerify(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var record sequencer.BallotRecord
	if err := protocol.DecodeStrict(bundle.Events[1].Artifact, &record); err != nil {
		t.Fatal(err)
	}
	if !ContainsReceipt(bundle, record.CredentialHash) {
		t.Fatal("fixture receipt is not included")
	}
	reencoded, err := Encode(bundle)
	if err != nil {
		t.Fatal(err)
	}
	decodedAgain, err := DecodeAndVerify(reencoded)
	if err != nil {
		t.Fatal(err)
	}
	reencodedAgain, err := Encode(decodedAgain)
	if err != nil || !bytes.Equal(reencoded, reencodedAgain) {
		t.Fatal("audit encoding is not deterministic")
	}

	mutated := bundle
	mutated.Events = append([]sequencer.AuditEvent(nil), bundle.Events...)
	mutated.Events[1].Artifact = append([]byte(nil), mutated.Events[1].Artifact...)
	mutated.Events[1].Artifact[0] ^= 1
	if _, err := Encode(mutated); err == nil {
		t.Fatal("modified fixture accepted")
	}
}
