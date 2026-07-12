package sequencerstore

import (
	"context"
	"database/sql"
	"errors"
)

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type Stats struct {
	OpenPolls      int `json:"open_polls"`
	ClosedPolls    int `json:"closed_polls"`
	CreditsClaimed int `json:"credits_claimed"`
	VotesAccepted  int `json:"votes_accepted"`
}

func (store *Store) Stats(ctx context.Context) (Stats, error) {
	var stats Stats
	queries := []struct {
		statement string
		target    *int
	}{
		{`SELECT COUNT(*) FROM polls WHERE state = 'open'`, &stats.OpenPolls},
		{`SELECT COUNT(*) FROM polls WHERE state = 'closed'`, &stats.ClosedPolls},
		{`SELECT COUNT(*) FROM poll_credits WHERE issuance_request_id IS NOT NULL`, &stats.CreditsClaimed},
		{`SELECT COUNT(*) FROM ballot_events WHERE event_type = 'ballot_accepted'`, &stats.VotesAccepted},
	}
	for _, query := range queries {
		if err := store.db.QueryRowContext(ctx, query.statement).Scan(query.target); err != nil {
			return Stats{}, &Error{Code: "diagnose_failed", Err: err}
		}
	}
	return stats, nil
}

func (store *Store) ProjectionCounts(ctx context.Context, pollID string) (claimed, spent int, err error) {
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM poll_credits WHERE poll_id = ? AND issuance_request_id IS NOT NULL`, pollID).Scan(&claimed); err != nil {
		return 0, 0, &Error{Code: "projection_read_failed", Err: err}
	}
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM spent_credentials WHERE poll_id = ?`, pollID).Scan(&spent); err != nil {
		return 0, 0, &Error{Code: "projection_read_failed", Err: err}
	}
	return claimed, spent, nil
}

func (store *Store) Poll(ctx context.Context, pollID string) (Poll, error) {
	return poll(ctx, store.db, pollID)
}

func (store *Store) Polls(ctx context.Context) ([]Poll, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT poll_id FROM polls WHERE issuer_key_id IS NOT NULL ORDER BY poll_id`)
	if err != nil {
		return nil, &Error{Code: "poll_read_failed", Err: err}
	}
	defer rows.Close()
	var output []Poll
	for rows.Next() {
		var pollID string
		if err := rows.Scan(&pollID); err != nil {
			return nil, &Error{Code: "poll_read_failed", Err: err}
		}
		value, err := poll(ctx, store.db, pollID)
		if err != nil {
			return nil, err
		}
		output = append(output, value)
	}
	return output, rows.Err()
}

func (tx *Tx) Poll(ctx context.Context, pollID string) (Poll, error) {
	return poll(ctx, tx.tx, pollID)
}

func poll(ctx context.Context, query queryer, pollID string) (Poll, error) {
	var value Poll
	var closedAt sql.NullString
	err := query.QueryRowContext(ctx, `SELECT poll_id, artifact_hash, artifact, state, created_at, closes_at, closed_at, issuer_key_id, eligibility_commitment FROM polls WHERE poll_id = ?`, pollID).Scan(&value.PollID, &value.ArtifactHash, &value.Artifact, &value.State, &value.CreatedAt, &value.ClosesAt, &closedAt, &value.IssuerKeyID, &value.EligibilityCommitment)
	if errors.Is(err, sql.ErrNoRows) {
		return Poll{}, &Error{Code: "poll_not_found"}
	}
	if err != nil {
		return Poll{}, &Error{Code: "poll_read_failed", Err: err}
	}
	value.ClosedAt = closedAt.String
	return value, nil
}

func (store *Store) Choices(ctx context.Context, pollID string) ([]Choice, error) {
	return choices(ctx, store.db, pollID)
}

func (tx *Tx) Choices(ctx context.Context, pollID string) ([]Choice, error) {
	return choices(ctx, tx.tx, pollID)
}

func choices(ctx context.Context, query queryer, pollID string) ([]Choice, error) {
	rows, err := query.QueryContext(ctx, `SELECT poll_id, choice_id, label, position FROM poll_choices WHERE poll_id = ? ORDER BY position`, pollID)
	if err != nil {
		return nil, &Error{Code: "choice_read_failed", Err: err}
	}
	defer rows.Close()
	var output []Choice
	for rows.Next() {
		var value Choice
		if err := rows.Scan(&value.PollID, &value.ChoiceID, &value.Label, &value.Position); err != nil {
			return nil, &Error{Code: "choice_read_failed", Err: err}
		}
		output = append(output, value)
	}
	return output, rows.Err()
}

func (tx *Tx) Credit(ctx context.Context, pollID, fingerprint string) (Credit, error) {
	var value Credit
	var requestID, blindedHash, claimedAt sql.NullString
	var signature []byte
	err := tx.tx.QueryRowContext(ctx, `SELECT poll_id, ssh_fingerprint, ssh_public_key, issuance_request_id, blinded_message_hash, blind_signature, claimed_at FROM poll_credits WHERE poll_id = ? AND ssh_fingerprint = ?`, pollID, fingerprint).Scan(&value.PollID, &value.SSHFingerprint, &value.SSHPublicKey, &requestID, &blindedHash, &signature, &claimedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Credit{}, &Error{Code: "not_eligible"}
	}
	if err != nil {
		return Credit{}, &Error{Code: "credit_read_failed", Err: err}
	}
	value.IssuanceRequestID = requestID.String
	value.BlindedMessageHash = blindedHash.String
	value.BlindSignature = signature
	value.ClaimedAt = claimedAt.String
	return value, nil
}

func (tx *Tx) NextCreditEvent(ctx context.Context, pollID string) (uint64, string, error) {
	return nextEvent(ctx, tx.tx, "credit_events", pollID)
}

func (tx *Tx) NextBallotEvent(ctx context.Context, pollID string) (uint64, string, error) {
	return nextEvent(ctx, tx.tx, "ballot_events", pollID)
}

func nextEvent(ctx context.Context, query queryer, table, pollID string) (uint64, string, error) {
	var sequence uint64
	var previous sql.NullString
	err := query.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence), 0) + 1, (SELECT event_hash FROM `+table+` WHERE poll_id = ? ORDER BY sequence DESC LIMIT 1) FROM `+table+` WHERE poll_id = ?`, pollID, pollID).Scan(&sequence, &previous)
	if err != nil {
		return 0, "", &Error{Code: "event_read_failed", Err: err}
	}
	if !previous.Valid {
		previous.String = emptyHash
	}
	return sequence, previous.String, nil
}

func (store *Store) CreditEvents(ctx context.Context, pollID string) ([]CreditEvent, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT poll_id, sequence, previous_hash, event_hash, artifact, signature, recorded_at FROM credit_events WHERE poll_id = ? ORDER BY sequence`, pollID)
	if err != nil {
		return nil, &Error{Code: "event_read_failed", Err: err}
	}
	defer rows.Close()
	var output []CreditEvent
	for rows.Next() {
		var value CreditEvent
		if err := rows.Scan(&value.PollID, &value.Sequence, &value.PreviousHash, &value.EventHash, &value.Artifact, &value.Signature, &value.RecordedAt); err != nil {
			return nil, &Error{Code: "event_read_failed", Err: err}
		}
		output = append(output, value)
	}
	return output, rows.Err()
}

func (store *Store) BallotEvents(ctx context.Context, pollID string) ([]BallotEvent, error) {
	return ballotEvents(ctx, store.db, pollID)
}

func (tx *Tx) BallotEvents(ctx context.Context, pollID string) ([]BallotEvent, error) {
	return ballotEvents(ctx, tx.tx, pollID)
}

func (tx *Tx) BallotByCredential(ctx context.Context, pollID, credentialHash string) (BallotEvent, bool, error) {
	var value BallotEvent
	err := tx.tx.QueryRowContext(ctx, `
		SELECT event.poll_id, event.sequence, event.event_type, event.previous_hash,
		       event.event_hash, event.artifact, event.receipt, event.recorded_at
		FROM spent_credentials AS spent
		JOIN ballot_events AS event
		  ON event.poll_id = spent.poll_id
		 AND event.sequence = spent.ballot_sequence
		WHERE spent.poll_id = ? AND spent.credential_hash = ?
	`, pollID, credentialHash).Scan(
		&value.PollID, &value.Sequence, &value.Type, &value.PreviousHash,
		&value.EventHash, &value.Artifact, &value.Receipt, &value.RecordedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return BallotEvent{}, false, nil
	}
	if err != nil {
		return BallotEvent{}, false, &Error{Code: "event_read_failed", Err: err}
	}
	return value, true, nil
}

func ballotEvents(ctx context.Context, query queryer, pollID string) ([]BallotEvent, error) {
	rows, err := query.QueryContext(ctx, `SELECT poll_id, sequence, event_type, previous_hash, event_hash, artifact, receipt, recorded_at FROM ballot_events WHERE poll_id = ? ORDER BY sequence`, pollID)
	if err != nil {
		return nil, &Error{Code: "event_read_failed", Err: err}
	}
	defer rows.Close()
	var output []BallotEvent
	for rows.Next() {
		var value BallotEvent
		if err := rows.Scan(&value.PollID, &value.Sequence, &value.Type, &value.PreviousHash, &value.EventHash, &value.Artifact, &value.Receipt, &value.RecordedAt); err != nil {
			return nil, &Error{Code: "event_read_failed", Err: err}
		}
		output = append(output, value)
	}
	return output, rows.Err()
}

func (store *Store) Tally(ctx context.Context, pollID string) (Tally, error) {
	return tally(ctx, store.db, pollID)
}

func (tx *Tx) Tally(ctx context.Context, pollID string) (Tally, error) {
	return tally(ctx, tx.tx, pollID)
}

func tally(ctx context.Context, query queryer, pollID string) (Tally, error) {
	var value Tally
	err := query.QueryRowContext(ctx, `SELECT poll_id, artifact, created_at FROM poll_tallies WHERE poll_id = ?`, pollID).Scan(&value.PollID, &value.Artifact, &value.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Tally{}, &Error{Code: "result_unavailable"}
	}
	if err != nil {
		return Tally{}, &Error{Code: "tally_read_failed", Err: err}
	}
	return value, nil
}

func (store *Store) Checkpoints(ctx context.Context, pollID string) ([]Checkpoint, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT poll_id, ballot_sequence, event_hash, artifact FROM sequencer_checkpoints WHERE poll_id = ? ORDER BY ballot_sequence`, pollID)
	if err != nil {
		return nil, &Error{Code: "checkpoint_read_failed", Err: err}
	}
	defer rows.Close()
	var output []Checkpoint
	for rows.Next() {
		var value Checkpoint
		if err := rows.Scan(&value.PollID, &value.BallotSequence, &value.EventHash, &value.Artifact); err != nil {
			return nil, &Error{Code: "checkpoint_read_failed", Err: err}
		}
		output = append(output, value)
	}
	return output, rows.Err()
}
