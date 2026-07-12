// Package sequenceraudit encodes and verifies closed anonymous ballot logs.
package sequenceraudit

import (
	"fmt"

	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/sequencer"
)

func Encode(bundle sequencer.AuditBundle) ([]byte, error) {
	if err := sequencer.VerifyAudit(bundle); err != nil {
		return nil, err
	}
	return protocol.MarshalCanonical(bundle)
}

func DecodeAndVerify(encoded []byte) (sequencer.AuditBundle, error) {
	var bundle sequencer.AuditBundle
	if err := protocol.DecodeStrict(encoded, &bundle); err != nil {
		return sequencer.AuditBundle{}, fmt.Errorf("decode audit bundle: %w", err)
	}
	if err := sequencer.VerifyAudit(bundle); err != nil {
		return sequencer.AuditBundle{}, err
	}
	return bundle, nil
}

func ContainsReceipt(bundle sequencer.AuditBundle, credentialHash string) bool {
	for _, event := range bundle.Events {
		if event.Type != "ballot_accepted" {
			continue
		}
		var record sequencer.BallotRecord
		if protocol.DecodeStrict(event.Artifact, &record) == nil && record.CredentialHash == credentialHash {
			return true
		}
	}
	return false
}

func Compare(first, second sequencer.AuditBundle) error {
	if err := sequencer.VerifyAudit(first); err != nil {
		return err
	}
	if err := sequencer.VerifyAudit(second); err != nil {
		return err
	}
	if first.Poll.PollID != second.Poll.PollID || first.CheckpointPublicKey != second.CheckpointPublicKey {
		return fmt.Errorf("audit histories describe different polls")
	}
	bySequence := make(map[uint64]sequencer.Checkpoint, len(first.Checkpoints))
	for _, checkpoint := range first.Checkpoints {
		bySequence[checkpoint.Sequence] = checkpoint
	}
	for _, checkpoint := range second.Checkpoints {
		if existing, ok := bySequence[checkpoint.Sequence]; ok && existing.EventHash != checkpoint.EventHash {
			return fmt.Errorf("audit_fork_detected")
		}
	}
	return nil
}
