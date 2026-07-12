package sequencer

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"

	"github.com/cirocosta/vota/internal/crypto/sshsig"
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
	if err := VerifyTallyForPoll(bundle.Poll, bundle.Tally); err != nil {
		return err
	}
	if len(bundle.Events) == 0 || len(bundle.Events) != len(bundle.Checkpoints) {
		return &Error{Code: "audit_sequence_gap"}
	}
	storeEvents := make([]sequencerstore.BallotEvent, len(bundle.Events))
	pollArtifact, err := protocol.MarshalCanonical(bundle.Poll)
	if err != nil {
		return &Error{Code: "invalid_audit_bundle", Err: err}
	}
	pollArtifactHash := hashBytes("vota:poll-artifact:v1", pollArtifact)
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
			var record pollCreatedRecord
			if index != 0 || protocol.DecodeStrict(event.Artifact, &record) != nil || record.Type != "poll_created" || record.PollHash != pollArtifactHash {
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
			if err := protocol.DecodeStrict(event.Receipt, &receipt); err != nil || receipt.PollID != bundle.Poll.PollID || receipt.Sequence != event.Sequence || receipt.EventHash != event.EventHash || receipt.CredentialHash != record.CredentialHash || receipt.ChoiceID != record.ChoiceID {
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

func VerifyReceiptForBallot(poll Poll, request BallotRequest, receipt Receipt) error {
	publicKey, err := decodeBase64(poll.CheckpointPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return &Error{Code: "invalid_checkpoint_public_key", Err: err}
	}
	_, expectedHash, err := verifyWireCredential(poll, request.Credential)
	if err != nil {
		return err
	}
	if receipt.SchemaVersion != SchemaVersion || receipt.Protocol != Protocol || receipt.PollID != poll.PollID || receipt.CredentialHash != expectedHash || receipt.ChoiceID != request.ChoiceID {
		return &Error{Code: "receipt_binding_mismatch"}
	}
	return VerifyReceipt(ed25519.PublicKey(publicKey), receipt)
}

func VerifyTally(publicKey ed25519.PublicKey, tally Tally) error {
	signature := tally.Signature
	tally.Signature = ""
	return verifyValue(publicKey, "vota:tally:v1", tally, signature)
}

func VerifyTallyForPoll(poll Poll, tally Tally) error {
	publicKey, err := decodeBase64(poll.CheckpointPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return &Error{Code: "invalid_checkpoint_public_key", Err: err}
	}
	if tally.SchemaVersion != SchemaVersion || tally.Protocol != Protocol || tally.PollID != poll.PollID || len(tally.Totals) != len(poll.Choices) || tally.BallotCount < 0 {
		return &Error{Code: "tally_mismatch"}
	}
	choices := make(map[string]struct{}, len(poll.Choices))
	for _, choice := range poll.Choices {
		choices[choice.ID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(tally.Totals))
	totalVotes := 0
	for _, total := range tally.Totals {
		if total.Total < 0 {
			return &Error{Code: "tally_mismatch"}
		}
		if _, exists := choices[total.ChoiceID]; !exists {
			return &Error{Code: "tally_mismatch"}
		}
		if _, duplicate := seen[total.ChoiceID]; duplicate {
			return &Error{Code: "tally_mismatch"}
		}
		if total.Total > tally.BallotCount-totalVotes {
			return &Error{Code: "tally_mismatch"}
		}
		seen[total.ChoiceID] = struct{}{}
		totalVotes += total.Total
	}
	if totalVotes != tally.BallotCount {
		return &Error{Code: "tally_mismatch"}
	}
	return VerifyTally(ed25519.PublicKey(publicKey), tally)
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
		if err := service.requireIssuer(poll); err != nil {
			return err
		}
		if err := VerifyPollArtifact(pollArtifact); err != nil {
			return err
		}
		if err := service.verifyPollProjection(ctx, poll, pollArtifact); err != nil {
			return err
		}
		creditEvents, err := service.store.CreditEvents(ctx, poll.PollID)
		if err != nil {
			return err
		}
		if _, err := sequencerstore.ReplayCredit(creditEvents); err != nil {
			return err
		}
		seenCredits := make(map[string]struct{}, len(creditEvents))
		for _, event := range creditEvents {
			var record creditRecord
			if err := protocol.DecodeStrict(event.Artifact, &record); err != nil || record.Type != "credit_claimed" || record.SSHFingerprint == "" {
				return &Error{Code: "projection_content_mismatch", Err: err}
			}
			if _, duplicate := seenCredits[record.SSHFingerprint]; duplicate {
				return &Error{Code: "projection_content_mismatch"}
			}
			seenCredits[record.SSHFingerprint] = struct{}{}
			credit, err := service.store.Credit(ctx, poll.PollID, record.SSHFingerprint)
			if err != nil || credit.IssuanceRequestID != record.IssuanceRequestID || credit.BlindedMessageHash != record.BlindedMessageHash || hashBytes("vota:blind-signature:v1", credit.BlindSignature) != record.BlindSignatureHash {
				return &Error{Code: "projection_content_mismatch", Err: err}
			}
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
		closedEvent := false
		for index, event := range ballotEvents {
			switch event.Type {
			case "poll_created":
				var record pollCreatedRecord
				if index != 0 || protocol.DecodeStrict(event.Artifact, &record) != nil || record.Type != "poll_created" || record.PollHash != poll.ArtifactHash {
					return &Error{Code: "poll_state_mismatch"}
				}
			case "ballot_accepted":
				if index == 0 || closedEvent {
					return &Error{Code: "poll_state_mismatch"}
				}
			case "poll_closed":
				if index == 0 || index != len(ballotEvents)-1 || closedEvent {
					return &Error{Code: "poll_state_mismatch"}
				}
				closedEvent = true
			default:
				return &Error{Code: "poll_state_mismatch"}
			}
		}
		if len(ballotEvents) == 0 || closedEvent != (poll.State == "closed") || (poll.State == "open" && poll.ClosedAt != "") || (poll.State == "closed" && poll.ClosedAt == "") {
			return &Error{Code: "poll_state_mismatch"}
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
			projected, found, err := service.store.BallotByCredential(ctx, poll.PollID, record.CredentialHash)
			if err != nil || !found || projected.Sequence != event.Sequence || projected.EventHash != event.EventHash {
				return &Error{Code: "projection_content_mismatch", Err: err}
			}
			if err := protocol.DecodeStrict(event.Receipt, &receipt); err != nil || receipt.EventHash != event.EventHash || receipt.CredentialHash != record.CredentialHash || receipt.ChoiceID != record.ChoiceID {
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
			if poll.ClosedAt != bundle.Tally.ClosedAt {
				return &Error{Code: "poll_state_mismatch"}
			}
		} else if _, err := service.store.Tally(ctx, poll.PollID); sequencerstore.ErrorCode(err) != "result_unavailable" {
			return &Error{Code: "poll_state_mismatch", Err: err}
		}
	}
	return nil
}

func (service *Service) verifyPollProjection(ctx context.Context, stored sequencerstore.Poll, artifact Poll) error {
	if artifact.SchemaVersion != SchemaVersion || artifact.Protocol != Protocol || stored.PollID != artifact.PollID || stored.ArtifactHash != hashBytes("vota:poll-artifact:v1", stored.Artifact) || stored.ClosesAt != artifact.ClosesAt || stored.EligibilityCommitment != artifact.EligibilityCommitment {
		return &Error{Code: "projection_content_mismatch"}
	}
	choices, err := service.store.Choices(ctx, stored.PollID)
	if err != nil || len(choices) != len(artifact.Choices) {
		return &Error{Code: "projection_content_mismatch", Err: err}
	}
	for index, choice := range choices {
		if choice.Position != index || choice.ChoiceID != artifact.Choices[index].ID || choice.Label != artifact.Choices[index].Label {
			return &Error{Code: "projection_content_mismatch"}
		}
	}
	credits, err := service.store.Credits(ctx, stored.PollID)
	if err != nil || len(credits) != artifact.EligibleCount {
		return &Error{Code: "projection_content_mismatch", Err: err}
	}
	encodedKeys := make([]string, len(credits))
	for index, credit := range credits {
		key, err := sshsig.ParsePublicKey([]byte(credit.SSHPublicKey))
		if err != nil {
			return &Error{Code: "projection_content_mismatch", Err: err}
		}
		fingerprint, err := sshsig.Fingerprint(key)
		if err != nil || fingerprint != credit.SSHFingerprint {
			return &Error{Code: "projection_content_mismatch", Err: err}
		}
		encodedKeys[index] = credit.SSHPublicKey
	}
	_, commitment, err := normalizeMembers(encodedKeys)
	if err != nil || commitment != artifact.EligibilityCommitment {
		return &Error{Code: "projection_content_mismatch", Err: err}
	}
	return nil
}
