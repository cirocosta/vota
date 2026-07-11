package store

import (
	"context"
	"database/sql"
	"errors"
)

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (store *Store) Poll(ctx context.Context, pollID string) (Poll, error) {
	return pollByID(ctx, store.db, pollID)
}

func (tx *Tx) Poll(ctx context.Context, pollID string) (Poll, error) {
	return pollByID(ctx, tx.tx, pollID)
}

func pollByID(ctx context.Context, query queryer, pollID string) (Poll, error) {
	var poll Poll
	var closedAt, aggregateHash sql.NullString
	var aggregate []byte
	err := query.QueryRowContext(ctx, `SELECT poll_id, manifest_hash, manifest, state, created_at, closed_at, aggregate_hash, aggregate FROM polls WHERE poll_id = ?`, pollID).Scan(
		&poll.PollID, &poll.ManifestHash, &poll.Manifest, &poll.State, &poll.CreatedAt, &closedAt, &aggregateHash, &aggregate,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Poll{}, &Error{Code: "poll_not_found"}
	}
	if err != nil {
		return Poll{}, &Error{Code: "poll_read_failed", Err: err}
	}
	poll.ClosedAt = closedAt.String
	poll.AggregateHash = aggregateHash.String
	poll.Aggregate = aggregate
	return poll, nil
}

func (store *Store) BallotByHash(ctx context.Context, pollID, ballotHash string) (Ballot, error) {
	return ballotByField(ctx, store.db, `ballot_hash`, pollID, ballotHash)
}

func (store *Store) BallotByNullifier(ctx context.Context, pollID, nullifier string) (Ballot, error) {
	return ballotByField(ctx, store.db, `nullifier`, pollID, nullifier)
}

func (tx *Tx) ballotByNullifier(ctx context.Context, pollID, nullifier string) (Ballot, error) {
	return ballotByField(ctx, tx.tx, `nullifier`, pollID, nullifier)
}

func ballotByField(ctx context.Context, query queryer, field, pollID, value string) (Ballot, error) {
	var ballot Ballot
	err := query.QueryRowContext(ctx, `SELECT poll_id, ballot_hash, nullifier, artifact, sequence, accepted_at FROM ballots WHERE poll_id = ? AND `+field+` = ?`, pollID, value).Scan(
		&ballot.PollID, &ballot.BallotHash, &ballot.Nullifier, &ballot.Artifact, &ballot.Sequence, &ballot.AcceptedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Ballot{}, &Error{Code: "ballot_not_found"}
	}
	if err != nil {
		return Ballot{}, &Error{Code: "ballot_read_failed", Err: err}
	}
	return ballot, nil
}

func (store *Store) Ballots(ctx context.Context, pollID string) ([]Ballot, error) {
	return ballots(ctx, store.db, pollID)
}

func (tx *Tx) Ballots(ctx context.Context, pollID string) ([]Ballot, error) {
	return ballots(ctx, tx.tx, pollID)
}

func ballots(ctx context.Context, query queryer, pollID string) ([]Ballot, error) {
	rows, err := query.QueryContext(ctx, `SELECT poll_id, ballot_hash, nullifier, artifact, sequence, accepted_at FROM ballots WHERE poll_id = ? ORDER BY sequence`, pollID)
	if err != nil {
		return nil, &Error{Code: "ballot_read_failed", Err: err}
	}
	defer rows.Close()
	var ballots []Ballot
	for rows.Next() {
		var ballot Ballot
		if err := rows.Scan(&ballot.PollID, &ballot.BallotHash, &ballot.Nullifier, &ballot.Artifact, &ballot.Sequence, &ballot.AcceptedAt); err != nil {
			return nil, &Error{Code: "ballot_read_failed", Err: err}
		}
		ballots = append(ballots, ballot)
	}
	if err := rows.Err(); err != nil {
		return nil, &Error{Code: "ballot_read_failed", Err: err}
	}
	return ballots, nil
}

func (store *Store) Events(ctx context.Context, pollID string) ([]Event, error) {
	return events(ctx, store.db, pollID)
}

func (tx *Tx) Events(ctx context.Context, pollID string) ([]Event, error) {
	return events(ctx, tx.tx, pollID)
}

func events(ctx context.Context, query queryer, pollID string) ([]Event, error) {
	rows, err := query.QueryContext(ctx, `SELECT poll_id, sequence, event_hash, event, accepted_at FROM audit_events WHERE poll_id = ? ORDER BY sequence`, pollID)
	if err != nil {
		return nil, &Error{Code: "audit_event_read_failed", Err: err}
	}
	defer rows.Close()
	var events []Event
	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.PollID, &event.Sequence, &event.EventHash, &event.Artifact, &event.AcceptedAt); err != nil {
			return nil, &Error{Code: "audit_event_read_failed", Err: err}
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, &Error{Code: "audit_event_read_failed", Err: err}
	}
	return events, nil
}

func (tx *Tx) NextSequence(ctx context.Context, pollID string) (uint64, error) {
	var sequence uint64
	if err := tx.tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence), 0) + 1 FROM audit_events WHERE poll_id = ?`, pollID).Scan(&sequence); err != nil {
		return 0, &Error{Code: "audit_event_read_failed", Err: err}
	}
	return sequence, nil
}

func (store *Store) LatestCheckpoint(ctx context.Context, pollID string) (Checkpoint, error) {
	var checkpoint Checkpoint
	err := store.db.QueryRowContext(ctx, `SELECT poll_id, sequence, checkpoint_hash, artifact FROM checkpoints WHERE poll_id = ? ORDER BY sequence DESC LIMIT 1`, pollID).Scan(
		&checkpoint.PollID, &checkpoint.Sequence, &checkpoint.CheckpointHash, &checkpoint.Artifact,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Checkpoint{}, &Error{Code: "checkpoint_not_found"}
	}
	if err != nil {
		return Checkpoint{}, &Error{Code: "checkpoint_read_failed", Err: err}
	}
	return checkpoint, nil
}

func (store *Store) Tally(ctx context.Context, pollID string) (Tally, error) {
	var tally Tally
	err := store.db.QueryRowContext(ctx, `SELECT poll_id, aggregate_hash, evidence_hash, artifact, created_at FROM tallies WHERE poll_id = ?`, pollID).Scan(
		&tally.PollID, &tally.AggregateHash, &tally.EvidenceHash, &tally.Artifact, &tally.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Tally{}, &Error{Code: "tally_not_found"}
	}
	if err != nil {
		return Tally{}, &Error{Code: "tally_read_failed", Err: err}
	}
	return tally, nil
}

func (store *Store) TrusteeShares(ctx context.Context, pollID string) ([]TrusteeShare, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT poll_id, trustee_id, aggregate_hash, artifact_hash, artifact, submitted_at FROM trustee_shares WHERE poll_id = ? ORDER BY trustee_id`, pollID)
	if err != nil {
		return nil, &Error{Code: "trustee_share_read_failed", Err: err}
	}
	defer rows.Close()
	var shares []TrusteeShare
	for rows.Next() {
		var share TrusteeShare
		if err := rows.Scan(&share.PollID, &share.TrusteeID, &share.AggregateHash, &share.ArtifactHash, &share.Artifact, &share.SubmittedAt); err != nil {
			return nil, &Error{Code: "trustee_share_read_failed", Err: err}
		}
		shares = append(shares, share)
	}
	if err := rows.Err(); err != nil {
		return nil, &Error{Code: "trustee_share_read_failed", Err: err}
	}
	return shares, nil
}
