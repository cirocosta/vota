package sequencer

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"

	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/sequencerstore"
)

func (service *Service) Audit(ctx context.Context, pollID string) (AuditBundle, error) {
	pollState, err := service.store.Poll(ctx, pollID)
	if err != nil {
		return AuditBundle{}, err
	}
	if pollState.State != "closed" {
		return AuditBundle{}, &Error{Code: "poll_not_closed"}
	}
	poll, err := service.Poll(ctx, pollID)
	if err != nil {
		return AuditBundle{}, err
	}
	events, err := service.store.BallotEvents(ctx, pollID)
	if err != nil {
		return AuditBundle{}, err
	}
	storedCheckpoints, err := service.store.Checkpoints(ctx, pollID)
	if err != nil {
		return AuditBundle{}, err
	}
	tally, err := service.Result(ctx, pollID)
	if err != nil {
		return AuditBundle{}, err
	}
	bundle := AuditBundle{SchemaVersion: SchemaVersion, Protocol: Protocol, Poll: poll, Tally: tally, CheckpointPublicKey: base64.RawURLEncoding.EncodeToString(service.checkpointPublic)}
	for _, event := range events {
		bundle.Events = append(bundle.Events, AuditEvent{Sequence: event.Sequence, Type: event.Type, PreviousHash: event.PreviousHash, EventHash: event.EventHash, Artifact: event.Artifact, Receipt: event.Receipt})
	}
	for _, stored := range storedCheckpoints {
		var checkpoint Checkpoint
		if err := protocol.DecodeStrict(stored.Artifact, &checkpoint); err != nil {
			return AuditBundle{}, &Error{Code: "invalid_stored_checkpoint", Err: err}
		}
		bundle.Checkpoints = append(bundle.Checkpoints, checkpoint)
	}
	return bundle, nil
}

func VerifyAudit(bundle AuditBundle) error {
	if bundle.SchemaVersion != SchemaVersion || bundle.Protocol != Protocol || bundle.Poll.PollID == "" || bundle.Poll.PollID != bundle.Tally.PollID {
		return &Error{Code: "invalid_audit_bundle"}
	}
	publicKey, err := decodeBase64(bundle.CheckpointPublicKey, ed25519.PublicKeySize)
	if err != nil || bundle.Poll.CheckpointPublicKey != bundle.CheckpointPublicKey {
		return &Error{Code: "invalid_audit_key", Err: err}
	}
	key := ed25519.PublicKey(publicKey)
	if err := VerifyPoll(key, bundle.Poll); err != nil {
		return err
	}
	if err := VerifyTally(key, bundle.Tally); err != nil {
		return err
	}
	if len(bundle.Events) == 0 || len(bundle.Events) != len(bundle.Checkpoints) {
		return &Error{Code: "audit_sequence_gap"}
	}
	storeEvents := make([]sequencerstore.BallotEvent, len(bundle.Events))
	seenCredentials := make(map[string]struct{})
	totals := make(map[string]int)
	ballotCount := 0
	for index, event := range bundle.Events {
		storeEvents[index] = sequencerstore.BallotEvent{PollID: bundle.Poll.PollID, Sequence: event.Sequence, Type: event.Type, PreviousHash: event.PreviousHash, EventHash: event.EventHash, Artifact: event.Artifact, Receipt: event.Receipt}
		checkpoint := bundle.Checkpoints[index]
		if checkpoint.Sequence != event.Sequence || checkpoint.EventHash != event.EventHash {
			return &Error{Code: "checkpoint_binding_mismatch"}
		}
		if err := VerifyCheckpoint(key, checkpoint); err != nil {
			return err
		}
		switch event.Type {
		case "poll_created":
			if index != 0 {
				return &Error{Code: "invalid_poll_created_event"}
			}
		case "ballot_accepted":
			var record BallotRecord
			if err := protocol.DecodeStrict(event.Artifact, &record); err != nil || record.PollID != bundle.Poll.PollID || record.Sequence != event.Sequence {
				return &Error{Code: "invalid_ballot_event", Err: err}
			}
			if _, duplicate := seenCredentials[record.CredentialHash]; duplicate {
				return &Error{Code: "duplicate_credential"}
			}
			_, verifiedHash, err := verifyWireCredential(bundle.Poll, record.Credential)
			if err != nil || verifiedHash != record.CredentialHash {
				return &Error{Code: "invalid_credential", Err: err}
			}
			seenCredentials[record.CredentialHash] = struct{}{}
			if !choiceExists(bundle.Poll.Choices, record.ChoiceID) {
				return &Error{Code: "invalid_choice"}
			}
			var receipt Receipt
			if err := protocol.DecodeStrict(event.Receipt, &receipt); err != nil || receipt.EventHash != event.EventHash || receipt.CredentialHash != record.CredentialHash {
				return &Error{Code: "invalid_receipt", Err: err}
			}
			if err := VerifyReceipt(key, receipt); err != nil {
				return err
			}
			totals[record.ChoiceID]++
			ballotCount++
		case "poll_closed":
			if index != len(bundle.Events)-1 || !bytesEqualCanonical(event.Artifact, bundle.Tally) {
				return &Error{Code: "invalid_close_event"}
			}
		default:
			return &Error{Code: "invalid_event_type"}
		}
	}
	if _, err := sequencerstore.ReplayBallot(storeEvents); err != nil {
		return err
	}
	if bundle.Tally.BallotCount != ballotCount || len(bundle.Tally.Totals) != len(bundle.Poll.Choices) {
		return &Error{Code: "tally_mismatch"}
	}
	for _, total := range bundle.Tally.Totals {
		if totals[total.ChoiceID] != total.Total {
			return &Error{Code: "tally_mismatch"}
		}
	}
	return nil
}

func VerifyPoll(publicKey ed25519.PublicKey, poll Poll) error {
	signature := poll.Signature
	poll.Signature = ""
	return verifyValue(publicKey, "vota:poll-artifact:v1", poll, signature)
}

func VerifyPollArtifact(poll Poll) error {
	publicKey, err := decodeBase64(poll.CheckpointPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return &Error{Code: "invalid_checkpoint_public_key", Err: err}
	}
	return VerifyPoll(ed25519.PublicKey(publicKey), poll)
}

func VerifyCheckpoint(publicKey ed25519.PublicKey, checkpoint Checkpoint) error {
	signature := checkpoint.Signature
	checkpoint.Signature = ""
	return verifyValue(publicKey, "vota:checkpoint:v1", checkpoint, signature)
}

func verifyCreditCheckpoint(publicKey ed25519.PublicKey, checkpoint Checkpoint) error {
	signature := checkpoint.Signature
	checkpoint.Signature = ""
	return verifyValue(publicKey, "vota:credit-checkpoint:v1", checkpoint, signature)
}

func VerifyReceipt(publicKey ed25519.PublicKey, receipt Receipt) error {
	if receipt.Checkpoint.PollID != receipt.PollID || receipt.Checkpoint.Sequence != receipt.Sequence || receipt.Checkpoint.EventHash != receipt.EventHash {
		return &Error{Code: "receipt_binding_mismatch"}
	}
	if err := VerifyCheckpoint(publicKey, receipt.Checkpoint); err != nil {
		return err
	}
	signature := receipt.Signature
	receipt.Signature = ""
	return verifyValue(publicKey, "vota:receipt:v1", receipt, signature)
}

func VerifyTally(publicKey ed25519.PublicKey, tally Tally) error {
	signature := tally.Signature
	tally.Signature = ""
	return verifyValue(publicKey, "vota:tally:v1", tally, signature)
}

func choiceExists(choices []Choice, choiceID string) bool {
	for _, choice := range choices {
		if choice.ID == choiceID {
			return true
		}
	}
	return false
}

func bytesEqualCanonical(encoded []byte, value any) bool {
	expected, err := protocol.MarshalCanonical(value)
	return err == nil && string(encoded) == string(expected)
}

func (service *Service) Ready(ctx context.Context) error {
	if err := service.store.Ping(ctx); err != nil {
		return err
	}
	polls, err := service.store.Polls(ctx)
	if err != nil {
		return err
	}
	for _, poll := range polls {
		var pollArtifact Poll
		if err := protocol.DecodeStrict(poll.Artifact, &pollArtifact); err != nil {
			return &Error{Code: "invalid_stored_poll", Err: err}
		}
		if err := VerifyPollArtifact(pollArtifact); err != nil {
			return err
		}
		creditEvents, err := service.store.CreditEvents(ctx, poll.PollID)
		if err != nil {
			return err
		}
		if _, err := sequencerstore.ReplayCredit(creditEvents); err != nil {
			return err
		}
		for _, event := range creditEvents {
			var checkpoint Checkpoint
			if err := protocol.DecodeStrict(event.Signature, &checkpoint); err != nil || checkpoint.PollID != poll.PollID || checkpoint.Sequence != event.Sequence || checkpoint.EventHash != event.EventHash {
				return &Error{Code: "invalid_credit_checkpoint", Err: err}
			}
			if err := verifyCreditCheckpoint(service.checkpointPublic, checkpoint); err != nil {
				return err
			}
		}
		ballotEvents, err := service.store.BallotEvents(ctx, poll.PollID)
		if err != nil {
			return err
		}
		if _, err := sequencerstore.ReplayBallot(ballotEvents); err != nil {
			return err
		}
		claimed, spent, err := service.store.ProjectionCounts(ctx, poll.PollID)
		if err != nil {
			return err
		}
		accepted := 0
		seenCredentials := make(map[string]struct{})
		for _, event := range ballotEvents {
			if event.Type != "ballot_accepted" {
				continue
			}
			var record BallotRecord
			var receipt Receipt
			if err := protocol.DecodeStrict(event.Artifact, &record); err != nil || record.Sequence != event.Sequence || record.PollID != poll.PollID || !choiceExists(pollArtifact.Choices, record.ChoiceID) {
				return &Error{Code: "invalid_stored_ballot", Err: err}
			}
			if _, duplicate := seenCredentials[record.CredentialHash]; duplicate {
				return &Error{Code: "duplicate_credential"}
			}
			_, verifiedHash, err := verifyWireCredential(pollArtifact, record.Credential)
			if err != nil || verifiedHash != record.CredentialHash {
				return &Error{Code: "invalid_credential", Err: err}
			}
			seenCredentials[record.CredentialHash] = struct{}{}
			if err := protocol.DecodeStrict(event.Receipt, &receipt); err != nil || receipt.EventHash != event.EventHash || receipt.CredentialHash != record.CredentialHash {
				return &Error{Code: "invalid_stored_receipt", Err: err}
			}
			if err := VerifyReceipt(service.checkpointPublic, receipt); err != nil {
				return err
			}
			accepted++
		}
		if len(creditEvents) != claimed || accepted != spent {
			return &Error{Code: "projection_count_mismatch"}
		}
		checkpoints, err := service.store.Checkpoints(ctx, poll.PollID)
		if err != nil || len(checkpoints) != len(ballotEvents) {
			return &Error{Code: "checkpoint_projection_mismatch", Err: err}
		}
		for index, stored := range checkpoints {
			var checkpoint Checkpoint
			if err := protocol.DecodeStrict(stored.Artifact, &checkpoint); err != nil || checkpoint.EventHash != ballotEvents[index].EventHash {
				return &Error{Code: "invalid_stored_checkpoint", Err: err}
			}
			if err := VerifyCheckpoint(service.checkpointPublic, checkpoint); err != nil {
				return err
			}
		}
		if poll.State == "closed" {
			bundle, err := service.Audit(ctx, poll.PollID)
			if err != nil {
				return err
			}
			if err := VerifyAudit(bundle); err != nil {
				return err
			}
		}
	}
	return nil
}
