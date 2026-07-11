package app

import (
	"context"
	"time"

	"github.com/cirocosta/vota/internal/audit"
	"github.com/cirocosta/vota/internal/crypto/election"
	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/store"
)

// ClosePoll closes voting and publishes the deterministic encrypted aggregate.
func (service *Service) ClosePoll(ctx context.Context, pollID string) (protocol.EncryptedAggregate, bool, error) {
	var result protocol.EncryptedAggregate
	created := false
	now := service.now().UTC()
	err := service.store.Transaction(ctx, func(tx *store.Tx) error {
		poll, err := tx.Poll(ctx, pollID)
		if err != nil {
			return &Error{Code: store.ErrorCode(err), Err: err}
		}
		if poll.State != "open" {
			if len(poll.Aggregate) == 0 {
				return &Error{Code: "poll_closed"}
			}
			result, err = ParseAggregate(poll.Aggregate)
			if err != nil {
				return err
			}
			records, err := tx.Ballots(ctx, pollID)
			if err != nil {
				return &Error{Code: store.ErrorCode(err), Err: err}
			}
			hashes := make([]string, len(records))
			for index, record := range records {
				hashes[index] = record.BallotHash
			}
			return validateAggregateBallotOrder(hashes, result)
		}
		frozen, err := manifest.Parse(poll.Manifest)
		if err != nil {
			return &Error{Code: "invalid_stored_manifest", Err: err}
		}
		value := frozen.Manifest()
		binding, electionKey, _, err := artifactContext(value, poll.ManifestHash)
		if err != nil {
			return err
		}
		records, err := tx.Ballots(ctx, pollID)
		if err != nil {
			return &Error{Code: store.ErrorCode(err), Err: err}
		}
		if len(records) == 0 {
			return &Error{Code: "no_accepted_ballots"}
		}
		ballots := make([]election.EncryptedBallot, len(records))
		ballotHashes := make([]string, len(records))
		for index, record := range records {
			var ballot protocol.BallotEnvelope
			if err := protocol.DecodeStrict(record.Artifact, &ballot); err != nil {
				return &Error{Code: "invalid_stored_ballot", Err: err}
			}
			ballots[index], err = electionBallot(value, ballot)
			if err != nil {
				return err
			}
			ballotHashes[index] = record.BallotHash
		}
		aggregate, err := election.AggregateBallots(binding, electionKey, ballots)
		if err != nil {
			return &Error{Code: "aggregate_failed", Err: err}
		}
		result, err = protocolAggregate(pollID, ballotHashes, aggregate)
		if err != nil {
			return err
		}
		encodedAggregate, err := MarshalAggregate(result)
		if err != nil {
			return err
		}
		if err := tx.ClosePoll(ctx, pollID, now.Format(time.RFC3339)); err != nil {
			return &Error{Code: store.ErrorCode(err), Err: err}
		}
		if err := tx.SaveAggregate(ctx, pollID, result.AggregateHash, encodedAggregate); err != nil {
			return &Error{Code: store.ErrorCode(err), Err: err}
		}
		events, err := loadEvents(ctx, tx, pollID)
		if err != nil {
			return err
		}
		closedEvent, err := audit.Append(events, pollID, "poll_closed", result.AggregateHash, now)
		if err != nil {
			return &Error{Code: audit.ErrorCode(err), Err: err}
		}
		if err := insertEvent(ctx, tx, closedEvent); err != nil {
			return err
		}
		events = append(events, closedEvent)
		aggregateEvent, err := audit.Append(events, pollID, "aggregate_published", result.AggregateHash, now)
		if err != nil {
			return &Error{Code: audit.ErrorCode(err), Err: err}
		}
		events = append(events, aggregateEvent)
		checkpoint, err := audit.CreateCheckpoint(service.checkpointPrivateKey, events)
		if err != nil {
			return &Error{Code: audit.ErrorCode(err), Err: err}
		}
		if err := insertEventAndCheckpoint(ctx, tx, aggregateEvent, checkpoint); err != nil {
			return err
		}
		created = true
		return service.runBeforeCommit()
	})
	if err != nil {
		return protocol.EncryptedAggregate{}, false, err
	}
	return result, created, nil
}

func insertEvent(ctx context.Context, tx *store.Tx, event protocol.AuditEvent) error {
	encoded, err := protocol.MarshalCanonical(event)
	if err != nil {
		return &Error{Code: "audit_event_encode_failed", Err: err}
	}
	if err := tx.InsertEvent(ctx, store.Event{PollID: event.PollID, Sequence: event.Sequence, EventHash: event.EventHash, Artifact: encoded, AcceptedAt: event.AcceptedAt}); err != nil {
		return &Error{Code: store.ErrorCode(err), Err: err}
	}
	return nil
}
