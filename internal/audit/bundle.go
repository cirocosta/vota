package audit

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
)

const MaxBundleBytes = 32 << 20

type Bundle struct {
	SchemaVersion int                          `json:"schema_version"`
	Protocol      string                       `json:"protocol"`
	CheckpointKey string                       `json:"checkpoint_key"`
	Manifest      protocol.Manifest            `json:"manifest"`
	Events        []protocol.AuditEvent        `json:"events"`
	Ballots       []protocol.BallotEnvelope    `json:"ballots"`
	Aggregate     *protocol.EncryptedAggregate `json:"aggregate"`
	Shares        []protocol.TrusteeShare      `json:"shares"`
	Tally         *protocol.Tally              `json:"tally"`
	Checkpoints   []protocol.Checkpoint        `json:"checkpoints"`
}

// Export verifies and canonicalizes a public audit-chain bundle.
func Export(bundle Bundle, checkpointKey ed25519.PublicKey) ([]byte, error) {
	bundle.CheckpointKey = "ed25519:" + hex.EncodeToString(checkpointKey)
	if bundle.Ballots == nil {
		bundle.Ballots = []protocol.BallotEnvelope{}
	}
	if bundle.Shares == nil {
		bundle.Shares = []protocol.TrusteeShare{}
	}
	if err := VerifyBundle(bundle, checkpointKey); err != nil {
		return nil, err
	}
	encoded, err := protocol.MarshalCanonical(bundle)
	if err != nil {
		return nil, &Error{Code: "audit_export_failed", Err: err}
	}
	return encoded, nil
}

// ParseBundle strictly decodes and verifies an exported bundle.
func ParseBundle(encoded []byte, expectedKeys ...ed25519.PublicKey) (Bundle, error) {
	var bundle Bundle
	if err := protocol.DecodeStrictLimit(encoded, &bundle, MaxBundleBytes); err != nil {
		return Bundle{}, &Error{Code: "invalid_audit_bundle", Err: err}
	}
	checkpointKey, err := bundleCheckpointKey(bundle)
	if err != nil {
		return Bundle{}, err
	}
	if len(expectedKeys) > 1 || (len(expectedKeys) == 1 && !checkpointKey.Equal(expectedKeys[0])) {
		return Bundle{}, &Error{Code: "checkpoint_key_mismatch"}
	}
	if err := VerifyBundle(bundle, checkpointKey); err != nil {
		return Bundle{}, err
	}
	canonical, err := protocol.MarshalCanonical(bundle)
	if err != nil {
		return Bundle{}, &Error{Code: "invalid_audit_bundle", Err: err}
	}
	if !bytes.Equal(encoded, canonical) {
		return Bundle{}, &Error{Code: "noncanonical_audit_bundle"}
	}
	return bundle, nil
}

// VerifyBundle checks the manifest, complete chain, and every checkpoint.
func VerifyBundle(bundle Bundle, checkpointKey ed25519.PublicKey) error {
	if bundle.SchemaVersion != protocol.SchemaVersion || bundle.Protocol != protocol.ProtocolVersion {
		return &Error{Code: "invalid_audit_bundle"}
	}
	embeddedKey, err := bundleCheckpointKey(bundle)
	if err != nil {
		return err
	}
	if !embeddedKey.Equal(checkpointKey) {
		return &Error{Code: "checkpoint_key_mismatch"}
	}
	if err := manifest.Verify(bundle.Manifest); err != nil {
		return &Error{Code: "invalid_manifest", Err: err}
	}
	if len(bundle.Events) == 0 {
		return &Error{Code: "empty_audit_chain"}
	}
	if len(bundle.Checkpoints) == 0 {
		return &Error{Code: "checkpoint_chain_mismatch"}
	}
	if _, err := Replay(bundle.Events); err != nil {
		return err
	}
	for index, event := range bundle.Events {
		if event.PollID != bundle.Manifest.PollID {
			return &Error{Code: "audit_chain_mismatch", Err: fmt.Errorf("event %d poll", index)}
		}
	}
	previousSequence := uint64(0)
	for _, checkpoint := range bundle.Checkpoints {
		if checkpoint.PollID != bundle.Manifest.PollID || checkpoint.Sequence <= previousSequence || checkpoint.Sequence > uint64(len(bundle.Events)) || checkpoint.EventHash != bundle.Events[checkpoint.Sequence-1].EventHash {
			return &Error{Code: "checkpoint_chain_mismatch"}
		}
		if err := VerifyCheckpoint(checkpointKey, checkpoint); err != nil {
			return err
		}
		previousSequence = checkpoint.Sequence
	}
	if previousSequence != uint64(len(bundle.Events)) {
		return &Error{Code: "checkpoint_chain_mismatch"}
	}
	return nil
}

// CompareBundles detects divergent events in two independently verified
// histories. A strict prefix is compatible because a later checkpoint may
// extend an earlier signed history.
func CompareBundles(first, second Bundle) error {
	firstKey, err := bundleCheckpointKey(first)
	if err != nil {
		return err
	}
	secondKey, err := bundleCheckpointKey(second)
	if err != nil {
		return err
	}
	if first.Manifest.PollID != second.Manifest.PollID || !firstKey.Equal(secondKey) {
		return &Error{Code: "incomparable_audit_records"}
	}
	if err := VerifyBundle(first, firstKey); err != nil {
		return err
	}
	if err := VerifyBundle(second, secondKey); err != nil {
		return err
	}
	sharedEvents := min(len(first.Events), len(second.Events))
	for index := range sharedEvents {
		if first.Events[index].EventHash != second.Events[index].EventHash {
			return &Error{Code: "audit_fork_detected", Err: fmt.Errorf("sequence %d", index+1)}
		}
	}
	bySequence := make(map[uint64]protocol.Checkpoint, len(first.Checkpoints))
	for _, checkpoint := range first.Checkpoints {
		bySequence[checkpoint.Sequence] = checkpoint
	}
	for _, checkpoint := range second.Checkpoints {
		if previous, exists := bySequence[checkpoint.Sequence]; exists {
			if err := CompareCheckpoints(firstKey, previous, checkpoint); err != nil {
				return err
			}
		}
	}
	return nil
}

func bundleCheckpointKey(bundle Bundle) (ed25519.PublicKey, error) {
	decoded, err := protocol.DecodeFixedHex("ed25519", bundle.CheckpointKey, ed25519.PublicKeySize)
	if err != nil {
		return nil, &Error{Code: "invalid_checkpoint_key"}
	}
	return ed25519.PublicKey(decoded), nil
}
