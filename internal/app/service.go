package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/cirocosta/vota/internal/audit"
	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/store"
)

type Service struct {
	store                *store.Store
	checkpointPrivateKey ed25519.PrivateKey
	now                  func() time.Time
	beforeCommit         func() error
}

type ServiceOptions struct {
	Now          func() time.Time
	BeforeCommit func() error
}

func NewService(database *store.Store, checkpointPrivateKey ed25519.PrivateKey, options ServiceOptions) (*Service, error) {
	if database == nil {
		return nil, &Error{Code: "nil_store"}
	}
	if len(checkpointPrivateKey) != ed25519.PrivateKeySize {
		return nil, &Error{Code: "invalid_checkpoint_private_key"}
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Service{
		store:                database,
		checkpointPrivateKey: append(ed25519.PrivateKey(nil), checkpointPrivateKey...),
		now:                  options.Now,
		beforeCommit:         options.BeforeCommit,
	}, nil
}

func (service *Service) CheckpointPublicKey() ed25519.PublicKey {
	publicKey := service.checkpointPrivateKey.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), publicKey...)
}

// PublishPoll verifies and atomically publishes an immutable manifest.
func (service *Service) PublishPoll(ctx context.Context, encoded []byte) (protocol.Manifest, bool, error) {
	frozen, err := manifest.Parse(encoded)
	if err != nil {
		return protocol.Manifest{}, false, &Error{Code: "invalid_manifest", Err: err}
	}
	canonical, err := frozen.MarshalCanonical()
	if err != nil {
		return protocol.Manifest{}, false, &Error{Code: "invalid_manifest", Err: err}
	}
	if !bytes.Equal(encoded, canonical) {
		return protocol.Manifest{}, false, &Error{Code: "noncanonical_manifest"}
	}
	value := frozen.Manifest()
	manifestHash, err := ManifestHash(value)
	if err != nil {
		return protocol.Manifest{}, false, err
	}
	created := false
	now := service.now().UTC()
	err = service.store.Transaction(ctx, func(tx *store.Tx) error {
		existing, lookupErr := tx.Poll(ctx, value.PollID)
		if lookupErr == nil {
			if existing.ManifestHash == manifestHash && bytes.Equal(existing.Manifest, canonical) {
				return nil
			}
			return &Error{Code: "poll_conflict"}
		}
		if store.ErrorCode(lookupErr) != "poll_not_found" {
			return &Error{Code: store.ErrorCode(lookupErr), Err: lookupErr}
		}
		if err := tx.InsertPoll(ctx, store.Poll{
			PollID:       value.PollID,
			ManifestHash: manifestHash,
			Manifest:     canonical,
			State:        "open",
			CreatedAt:    now.Format(time.RFC3339),
		}); err != nil {
			return &Error{Code: store.ErrorCode(err), Err: err}
		}
		event, err := audit.Genesis(value.PollID, "poll_published", manifestHash, now)
		if err != nil {
			return &Error{Code: audit.ErrorCode(err), Err: err}
		}
		checkpoint, err := audit.CreateCheckpoint(service.checkpointPrivateKey, []protocol.AuditEvent{event})
		if err != nil {
			return &Error{Code: audit.ErrorCode(err), Err: err}
		}
		if err := insertEventAndCheckpoint(ctx, tx, event, checkpoint); err != nil {
			return err
		}
		created = true
		return service.runBeforeCommit()
	})
	if err != nil {
		return protocol.Manifest{}, false, err
	}
	return value, created, nil
}

// AcceptBallot verifies and atomically appends one anonymous ballot and receipt.
func (service *Service) AcceptBallot(ctx context.Context, ballot protocol.BallotEnvelope) (protocol.Receipt, bool, error) {
	poll, err := service.store.Poll(ctx, ballot.PollID)
	if err != nil {
		return protocol.Receipt{}, false, &Error{Code: store.ErrorCode(err), Err: err}
	}
	frozen, err := manifest.Parse(poll.Manifest)
	if err != nil {
		return protocol.Receipt{}, false, &Error{Code: "invalid_stored_manifest", Err: err}
	}
	value := frozen.Manifest()
	now := service.now().UTC()
	if err := validateVotingWindow(value, now); err != nil {
		return protocol.Receipt{}, false, err
	}
	if err := VerifyBallot(value, ballot); err != nil {
		return protocol.Receipt{}, false, err
	}
	encodedBallot, err := MarshalBallot(ballot)
	if err != nil {
		return protocol.Receipt{}, false, err
	}
	var receipt protocol.Receipt
	created := false
	err = service.store.Transaction(ctx, func(tx *store.Tx) error {
		current, err := tx.Poll(ctx, ballot.PollID)
		if err != nil {
			return &Error{Code: store.ErrorCode(err), Err: err}
		}
		if current.State != "open" {
			return &Error{Code: "poll_closed"}
		}
		if existing, lookupErr := tx.BallotByHash(ctx, ballot.PollID, ballot.BallotHash); lookupErr == nil {
			if !bytes.Equal(existing.Artifact, encodedBallot) {
				return &Error{Code: "ballot_conflict"}
			}
			if err := protocol.DecodeStrict(existing.Receipt, &receipt); err != nil {
				return &Error{Code: "invalid_stored_receipt", Err: err}
			}
			return nil
		} else if store.ErrorCode(lookupErr) != "ballot_not_found" {
			return &Error{Code: store.ErrorCode(lookupErr), Err: lookupErr}
		}
		if existing, lookupErr := tx.BallotByNullifier(ctx, ballot.PollID, ballot.Nullifier); lookupErr == nil {
			if existing.BallotHash != ballot.BallotHash {
				return &Error{Code: "double_vote"}
			}
		} else if store.ErrorCode(lookupErr) != "ballot_not_found" {
			return &Error{Code: store.ErrorCode(lookupErr), Err: lookupErr}
		}
		events, err := loadEvents(ctx, tx, ballot.PollID)
		if err != nil {
			return err
		}
		event, err := audit.Append(events, ballot.PollID, "ballot_accepted", ballot.BallotHash, now)
		if err != nil {
			return &Error{Code: audit.ErrorCode(err), Err: err}
		}
		events = append(events, event)
		checkpoint, err := audit.CreateCheckpoint(service.checkpointPrivateKey, events)
		if err != nil {
			return &Error{Code: audit.ErrorCode(err), Err: err}
		}
		receipt, err = audit.CreateReceipt(service.checkpointPrivateKey, ballot.BallotHash, event, checkpoint)
		if err != nil {
			return &Error{Code: audit.ErrorCode(err), Err: err}
		}
		encodedReceipt, err := protocol.MarshalCanonical(receipt)
		if err != nil {
			return &Error{Code: "receipt_encode_failed", Err: err}
		}
		if err := insertEventAndCheckpoint(ctx, tx, event, checkpoint); err != nil {
			return err
		}
		if err := tx.InsertBallot(ctx, store.Ballot{
			PollID:     ballot.PollID,
			BallotHash: ballot.BallotHash,
			Nullifier:  ballot.Nullifier,
			Artifact:   encodedBallot,
			Sequence:   event.Sequence,
			AcceptedAt: event.AcceptedAt,
			Receipt:    encodedReceipt,
		}); err != nil {
			return &Error{Code: store.ErrorCode(err), Err: err}
		}
		created = true
		return service.runBeforeCommit()
	})
	if err != nil {
		return protocol.Receipt{}, false, err
	}
	return receipt, created, nil
}

func (service *Service) Receipt(ctx context.Context, pollID, ballotHash string) (protocol.Receipt, error) {
	ballot, err := service.store.BallotByHash(ctx, pollID, ballotHash)
	if err != nil {
		return protocol.Receipt{}, &Error{Code: store.ErrorCode(err), Err: err}
	}
	var receipt protocol.Receipt
	if err := protocol.DecodeStrict(ballot.Receipt, &receipt); err != nil {
		return protocol.Receipt{}, &Error{Code: "invalid_stored_receipt", Err: err}
	}
	return receipt, nil
}

func validateVotingWindow(value protocol.Manifest, now time.Time) error {
	opensAt, err := protocol.ParseCanonicalTime(value.OpensAt)
	if err != nil {
		return &Error{Code: "invalid_poll_window", Err: err}
	}
	closesAt, err := protocol.ParseCanonicalTime(value.ClosesAt)
	if err != nil {
		return &Error{Code: "invalid_poll_window", Err: err}
	}
	if now.Before(opensAt) {
		return &Error{Code: "poll_not_open"}
	}
	if !now.Before(closesAt) {
		return &Error{Code: "poll_closed"}
	}
	return nil
}

func insertEventAndCheckpoint(ctx context.Context, tx *store.Tx, event protocol.AuditEvent, checkpoint protocol.Checkpoint) error {
	eventBytes, err := protocol.MarshalCanonical(event)
	if err != nil {
		return &Error{Code: "audit_event_encode_failed", Err: err}
	}
	checkpointBytes, err := protocol.MarshalCanonical(checkpoint)
	if err != nil {
		return &Error{Code: "checkpoint_encode_failed", Err: err}
	}
	if err := tx.InsertEvent(ctx, store.Event{PollID: event.PollID, Sequence: event.Sequence, EventHash: event.EventHash, Artifact: eventBytes, AcceptedAt: event.AcceptedAt}); err != nil {
		return &Error{Code: store.ErrorCode(err), Err: err}
	}
	if err := tx.InsertCheckpoint(ctx, store.Checkpoint{PollID: checkpoint.PollID, Sequence: checkpoint.Sequence, CheckpointHash: checkpoint.CheckpointHash, Artifact: checkpointBytes}); err != nil {
		return &Error{Code: store.ErrorCode(err), Err: err}
	}
	return nil
}

func loadEvents(ctx context.Context, tx *store.Tx, pollID string) ([]protocol.AuditEvent, error) {
	records, err := tx.Events(ctx, pollID)
	if err != nil {
		return nil, &Error{Code: store.ErrorCode(err), Err: err}
	}
	events := make([]protocol.AuditEvent, len(records))
	for index, record := range records {
		if err := protocol.DecodeStrict(record.Artifact, &events[index]); err != nil {
			return nil, &Error{Code: "invalid_stored_event", Err: fmt.Errorf("sequence %d: %w", record.Sequence, err)}
		}
	}
	if _, err := audit.Replay(events); err != nil {
		return nil, &Error{Code: "invalid_stored_event", Err: err}
	}
	return events, nil
}

func (service *Service) runBeforeCommit() error {
	if service.beforeCommit == nil {
		return nil
	}
	if err := service.beforeCommit(); err != nil {
		return &Error{Code: "injected_failure", Err: err}
	}
	return nil
}
