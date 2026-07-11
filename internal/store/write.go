package store

import (
	"context"
)

func (tx *Tx) InsertPoll(ctx context.Context, poll Poll) error {
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO polls(poll_id, manifest_hash, manifest, state, created_at) VALUES (?, ?, ?, ?, ?)`, poll.PollID, poll.ManifestHash, poll.Manifest, poll.State, poll.CreatedAt)
	if err != nil {
		if isConstraint(err) {
			return &Error{Code: "poll_conflict", Err: err}
		}
		return &Error{Code: "poll_write_failed", Err: err}
	}
	return nil
}

func (tx *Tx) InsertEvent(ctx context.Context, event Event) error {
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO audit_events(poll_id, sequence, event_hash, event, accepted_at) VALUES (?, ?, ?, ?, ?)`, event.PollID, event.Sequence, event.EventHash, event.Artifact, event.AcceptedAt)
	if err != nil {
		if isConstraint(err) {
			return &Error{Code: "duplicate_audit_event", Err: err}
		}
		return &Error{Code: "audit_event_write_failed", Err: err}
	}
	return nil
}

func (tx *Tx) InsertBallot(ctx context.Context, ballot Ballot) error {
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO ballots(poll_id, ballot_hash, nullifier, artifact, sequence, accepted_at) VALUES (?, ?, ?, ?, ?, ?)`, ballot.PollID, ballot.BallotHash, ballot.Nullifier, ballot.Artifact, ballot.Sequence, ballot.AcceptedAt)
	if err != nil {
		if isConstraint(err) {
			if existing, lookupErr := tx.ballotByNullifier(ctx, ballot.PollID, ballot.Nullifier); lookupErr == nil && existing.BallotHash != ballot.BallotHash {
				return &Error{Code: "double_vote", Err: err}
			}
			return &Error{Code: "duplicate_ballot", Err: err}
		}
		return &Error{Code: "ballot_write_failed", Err: err}
	}
	return nil
}

func (tx *Tx) ClosePoll(ctx context.Context, pollID, closedAt string) error {
	result, err := tx.tx.ExecContext(ctx, `UPDATE polls SET state = 'closed', closed_at = ? WHERE poll_id = ? AND state = 'open'`, closedAt, pollID)
	if err != nil {
		return &Error{Code: "poll_write_failed", Err: err}
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return &Error{Code: "poll_not_open"}
	}
	return nil
}

func (tx *Tx) SaveAggregate(ctx context.Context, pollID, aggregateHash string, aggregate []byte) error {
	result, err := tx.tx.ExecContext(ctx, `UPDATE polls SET aggregate_hash = ?, aggregate = ? WHERE poll_id = ? AND state = 'closed' AND aggregate_hash IS NULL`, aggregateHash, aggregate, pollID)
	if err != nil {
		if isConstraint(err) {
			return &Error{Code: "aggregate_conflict", Err: err}
		}
		return &Error{Code: "aggregate_write_failed", Err: err}
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return &Error{Code: "aggregate_conflict"}
	}
	return nil
}

func (tx *Tx) InsertCheckpoint(ctx context.Context, checkpoint Checkpoint) error {
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO checkpoints(poll_id, sequence, checkpoint_hash, artifact) VALUES (?, ?, ?, ?)`, checkpoint.PollID, checkpoint.Sequence, checkpoint.CheckpointHash, checkpoint.Artifact)
	if err != nil {
		if isConstraint(err) {
			return &Error{Code: "checkpoint_conflict", Err: err}
		}
		return &Error{Code: "checkpoint_write_failed", Err: err}
	}
	return nil
}

func (tx *Tx) InsertTrusteeShare(ctx context.Context, share TrusteeShare) error {
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO trustee_shares(poll_id, trustee_id, aggregate_hash, artifact_hash, artifact, submitted_at) VALUES (?, ?, ?, ?, ?, ?)`, share.PollID, share.TrusteeID, share.AggregateHash, share.ArtifactHash, share.Artifact, share.SubmittedAt)
	if err != nil {
		if isConstraint(err) {
			return &Error{Code: "duplicate_trustee_share", Err: err}
		}
		return &Error{Code: "trustee_share_write_failed", Err: err}
	}
	return nil
}

func (tx *Tx) InsertTally(ctx context.Context, tally Tally) error {
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO tallies(poll_id, aggregate_hash, evidence_hash, artifact, created_at) VALUES (?, ?, ?, ?, ?)`, tally.PollID, tally.AggregateHash, tally.EvidenceHash, tally.Artifact, tally.CreatedAt)
	if err != nil {
		if isConstraint(err) {
			return &Error{Code: "tally_conflict", Err: err}
		}
		return &Error{Code: "tally_write_failed", Err: err}
	}
	result, err := tx.tx.ExecContext(ctx, `UPDATE polls SET state = 'tallied' WHERE poll_id = ? AND state = 'closed'`, tally.PollID)
	if err != nil {
		return &Error{Code: "poll_write_failed", Err: err}
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return &Error{Code: "poll_not_closed"}
	}
	return nil
}
