package sequencerstore

import "context"

func (tx *Tx) InsertPoll(ctx context.Context, poll Poll) error {
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO polls(poll_id, artifact_hash, artifact, state, created_at, closes_at, issuer_key_id, eligibility_commitment) VALUES (?, ?, ?, 'open', ?, ?, ?, ?)`, poll.PollID, poll.ArtifactHash, poll.Artifact, poll.CreatedAt, poll.ClosesAt, poll.IssuerKeyID, poll.EligibilityCommitment)
	if err != nil {
		if isConstraint(err) {
			return &Error{Code: "poll_conflict", Err: err}
		}
		return &Error{Code: "poll_write_failed", Err: err}
	}
	return nil
}

func (tx *Tx) InsertChoice(ctx context.Context, choice Choice) error {
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO poll_choices(poll_id, choice_id, label, position) VALUES (?, ?, ?, ?)`, choice.PollID, choice.ChoiceID, choice.Label, choice.Position)
	if err != nil {
		return &Error{Code: "choice_write_failed", Err: err}
	}
	return nil
}

func (tx *Tx) InsertCredit(ctx context.Context, credit Credit) error {
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO poll_credits(poll_id, ssh_fingerprint, ssh_public_key) VALUES (?, ?, ?)`, credit.PollID, credit.SSHFingerprint, credit.SSHPublicKey)
	if err != nil {
		if isConstraint(err) {
			return &Error{Code: "duplicate_eligible_key", Err: err}
		}
		return &Error{Code: "credit_write_failed", Err: err}
	}
	return nil
}

func (tx *Tx) ClaimCredit(ctx context.Context, pollID, fingerprint, requestID, blindedHash string, signature []byte, claimedAt string) error {
	result, err := tx.tx.ExecContext(ctx, `UPDATE poll_credits SET issuance_request_id = ?, blinded_message_hash = ?, blind_signature = ?, claimed_at = ? WHERE poll_id = ? AND ssh_fingerprint = ? AND issuance_request_id IS NULL`, requestID, blindedHash, signature, claimedAt, pollID, fingerprint)
	if err != nil {
		return &Error{Code: "credit_write_failed", Err: err}
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return &Error{Code: "credit_already_claimed"}
	}
	return nil
}

func (tx *Tx) InsertCreditEvent(ctx context.Context, event CreditEvent) error {
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO credit_events(poll_id, sequence, previous_hash, event_hash, artifact, signature, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, event.PollID, event.Sequence, event.PreviousHash, event.EventHash, event.Artifact, event.Signature, event.RecordedAt)
	if err != nil {
		return &Error{Code: "credit_event_write_failed", Err: err}
	}
	return nil
}

func (tx *Tx) InsertBallotEvent(ctx context.Context, event BallotEvent) error {
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO ballot_events(poll_id, sequence, event_type, previous_hash, event_hash, artifact, receipt, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, event.PollID, event.Sequence, event.Type, event.PreviousHash, event.EventHash, event.Artifact, nullableBytes(event.Receipt), event.RecordedAt)
	if err != nil {
		return &Error{Code: "ballot_event_write_failed", Err: err}
	}
	return nil
}

func (tx *Tx) SpendCredential(ctx context.Context, pollID, credentialHash string, sequence uint64) error {
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO spent_credentials(poll_id, credential_hash, ballot_sequence) VALUES (?, ?, ?)`, pollID, credentialHash, sequence)
	if err != nil {
		if isConstraint(err) {
			return &Error{Code: "credential_already_spent", Err: err}
		}
		return &Error{Code: "credential_write_failed", Err: err}
	}
	return nil
}

func (tx *Tx) SaveCheckpoint(ctx context.Context, checkpoint Checkpoint) error {
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO sequencer_checkpoints(poll_id, ballot_sequence, event_hash, artifact) VALUES (?, ?, ?, ?)`, checkpoint.PollID, checkpoint.BallotSequence, checkpoint.EventHash, checkpoint.Artifact)
	if err != nil {
		return &Error{Code: "checkpoint_write_failed", Err: err}
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

func (tx *Tx) SaveTally(ctx context.Context, tally Tally) error {
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO poll_tallies(poll_id, artifact, created_at) VALUES (?, ?, ?)`, tally.PollID, tally.Artifact, tally.CreatedAt)
	if err != nil {
		if isConstraint(err) {
			return &Error{Code: "tally_final", Err: err}
		}
		return &Error{Code: "tally_write_failed", Err: err}
	}
	return nil
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}
