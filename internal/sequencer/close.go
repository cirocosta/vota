package sequencer

import (
	"context"

	"github.com/cirocosta/vota/internal/crypto/sshsig"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/sequencerstore"
)

func (service *Service) ClosePoll(ctx context.Context, pollID string, request ClosePollRequest) (Tally, bool, error) {
	adminKey, err := sshsig.ParsePublicKey([]byte(request.AdminPublicKey))
	if err != nil {
		return Tally{}, false, &Error{Code: "invalid_admin_key", Err: err}
	}
	canonical, _ := sshsig.CanonicalPublicKey(adminKey)
	if string(canonical) != request.AdminPublicKey {
		return Tally{}, false, &Error{Code: "invalid_admin_key"}
	}
	fingerprint, _ := sshsig.Fingerprint(adminKey)
	if _, authorized := service.adminFingerprints[fingerprint]; !authorized {
		return Tally{}, false, &Error{Code: "admin_not_authorized"}
	}
	message, _ := ClosePollMessage(pollID, request.AdminPublicKey)
	signature, err := decodeBase64(request.SSHSIG, -1)
	if err != nil || sshsig.Verify(adminKey, AdminNamespace, message, signature) != nil {
		return Tally{}, false, &Error{Code: "invalid_ssh_signature", Err: err}
	}
	signedPoll, err := service.Poll(ctx, pollID)
	if err != nil {
		return Tally{}, false, err
	}

	var tally Tally
	created := false
	err = service.store.Transaction(ctx, func(tx *sequencerstore.Tx) error {
		poll, err := tx.Poll(ctx, pollID)
		if err != nil {
			return err
		}
		if poll.State == "closed" {
			stored, err := tx.Tally(ctx, pollID)
			if err != nil {
				return err
			}
			if err := protocol.DecodeStrict(stored.Artifact, &tally); err != nil {
				return err
			}
			return VerifyTallyForPoll(signedPoll, tally)
		}
		if poll.State != "open" || poll.ClosesAt != signedPoll.ClosesAt {
			return &Error{Code: "poll_not_open"}
		}
		totals := make([]ChoiceTotal, len(signedPoll.Choices))
		positions := make(map[string]int, len(signedPoll.Choices))
		for index, choice := range signedPoll.Choices {
			totals[index] = ChoiceTotal{ChoiceID: choice.ID}
			positions[choice.ID] = index
		}
		events, err := tx.BallotEvents(ctx, pollID)
		if err != nil {
			return err
		}
		ballotCount := 0
		for _, event := range events {
			if event.Type == "poll_closed" {
				return &Error{Code: "poll_not_open"}
			}
			if event.Type != "ballot_accepted" {
				continue
			}
			var record BallotRecord
			if err := protocol.DecodeStrict(event.Artifact, &record); err != nil {
				return &Error{Code: "invalid_stored_ballot", Err: err}
			}
			position, exists := positions[record.ChoiceID]
			if !exists {
				return &Error{Code: "invalid_stored_ballot"}
			}
			totals[position].Total++
			ballotCount++
		}
		now := canonicalTime(service.now())
		tally = Tally{SchemaVersion: SchemaVersion, Protocol: Protocol, PollID: pollID, BallotCount: ballotCount, Totals: totals, ClosedAt: now}
		tally.Signature, err = service.signValue("vota:tally:v1", tally)
		if err != nil {
			return err
		}
		tallyArtifact, _ := protocol.MarshalCanonical(tally)
		sequence, previous, err := tx.NextBallotEvent(ctx, pollID)
		if err != nil {
			return err
		}
		eventHash := sequencerstore.EventHash("ballot", pollID, sequence, previous, tallyArtifact)
		checkpoint, encodedCheckpoint, err := service.checkpoint(pollID, sequence, eventHash)
		if err != nil {
			return err
		}
		event := sequencerstore.BallotEvent{PollID: pollID, Sequence: sequence, Type: "poll_closed", PreviousHash: previous, EventHash: eventHash, Artifact: tallyArtifact, RecordedAt: now}
		if err := tx.InsertBallotEvent(ctx, event); err != nil {
			return err
		}
		if err := tx.SaveCheckpoint(ctx, sequencerstore.Checkpoint{PollID: pollID, BallotSequence: sequence, EventHash: checkpoint.EventHash, Artifact: encodedCheckpoint}); err != nil {
			return err
		}
		if err := tx.ClosePoll(ctx, pollID, now); err != nil {
			return err
		}
		if err := tx.SaveTally(ctx, sequencerstore.Tally{PollID: pollID, Artifact: tallyArtifact, CreatedAt: now}); err != nil {
			return err
		}
		created = true
		return nil
	})
	return tally, created, err
}

func (service *Service) Result(ctx context.Context, pollID string) (Tally, error) {
	storedPoll, err := service.store.Poll(ctx, pollID)
	if err != nil {
		return Tally{}, err
	}
	if storedPoll.State != "closed" {
		return Tally{}, &Error{Code: "result_unavailable"}
	}
	poll, err := service.Poll(ctx, pollID)
	if err != nil {
		return Tally{}, err
	}
	stored, err := service.store.Tally(ctx, pollID)
	if err != nil {
		return Tally{}, err
	}
	var tally Tally
	if err := protocol.DecodeStrict(stored.Artifact, &tally); err != nil {
		return Tally{}, &Error{Code: "invalid_stored_tally", Err: err}
	}
	if err := VerifyTallyForPoll(poll, tally); err != nil {
		return Tally{}, &Error{Code: "invalid_stored_tally", Err: err}
	}
	return tally, nil
}
