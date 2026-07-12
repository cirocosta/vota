package sequencerstore

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestIndependentStreamsAndReplay(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	err = store.Transaction(ctx, func(tx *Tx) error {
		poll := Poll{PollID: "poll", ArtifactHash: "sha256:poll", Artifact: []byte(`{"poll_id":"poll"}`), CreatedAt: "2026-07-12T12:00:00Z", ClosesAt: "2026-07-12T13:00:00Z", IssuerKeyID: "issuer", EligibilityCommitment: "sha256:members"}
		if err := tx.InsertPoll(ctx, poll); err != nil {
			return err
		}
		if err := tx.InsertChoice(ctx, Choice{PollID: "poll", ChoiceID: "yes", Label: "Yes"}); err != nil {
			return err
		}
		if err := tx.InsertCredit(ctx, Credit{PollID: "poll", SSHFingerprint: "SHA256:key", SSHPublicKey: "ssh-ed25519 key"}); err != nil {
			return err
		}
		creditArtifact := []byte(`{"type":"credit_claimed"}`)
		credit := CreditEvent{PollID: "poll", Sequence: 1, PreviousHash: EmptyHash(), Artifact: creditArtifact, Signature: []byte("signed"), RecordedAt: poll.CreatedAt}
		credit.EventHash = EventHash("credit", credit.PollID, credit.Sequence, credit.PreviousHash, credit.Artifact)
		if err := tx.InsertCreditEvent(ctx, credit); err != nil {
			return err
		}
		ballotArtifact := []byte(`{"type":"poll_created"}`)
		ballot := BallotEvent{PollID: "poll", Sequence: 1, Type: "poll_created", PreviousHash: EmptyHash(), Artifact: ballotArtifact, RecordedAt: poll.CreatedAt}
		ballot.EventHash = EventHash("ballot", ballot.PollID, ballot.Sequence, ballot.PreviousHash, ballot.Artifact)
		return tx.InsertBallotEvent(ctx, ballot)
	})
	if err != nil {
		t.Fatal(err)
	}
	creditEvents, _ := store.CreditEvents(ctx, "poll")
	ballotEvents, _ := store.BallotEvents(ctx, "poll")
	if _, err := ReplayCredit(creditEvents); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayBallot(ballotEvents); err != nil {
		t.Fatal(err)
	}
	if creditEvents[0].EventHash == ballotEvents[0].EventHash {
		t.Fatal("independent streams share a hash")
	}
	ballotEvents[0].Artifact[0] ^= 1
	if _, err := ReplayBallot(ballotEvents); ErrorCode(err) != "event_hash_mismatch" {
		t.Fatalf("mutation error = %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE ballot_events SET artifact = X'00' WHERE poll_id = 'poll' AND sequence = 1`); err != nil {
		t.Fatal(err)
	}
	storedEvents, err := store.BallotEvents(ctx, "poll")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayBallot(storedEvents); ErrorCode(err) != "event_hash_mismatch" {
		t.Fatalf("stored mutation error = %v", err)
	}
}

func TestMigrationFailureIsReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.sqlite")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TABLE schema_migrations (wrong INTEGER) STRICT`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path); ErrorCode(err) != "migration_failed" {
		t.Fatalf("migration error = %v", err)
	}
}

func TestReplayRejectsSequenceAndChainMutations(t *testing.T) {
	first := BallotEvent{PollID: "poll", Sequence: 1, PreviousHash: EmptyHash(), Artifact: []byte("one")}
	first.EventHash = EventHash("ballot", first.PollID, first.Sequence, first.PreviousHash, first.Artifact)
	second := BallotEvent{PollID: "poll", Sequence: 2, PreviousHash: first.EventHash, Artifact: []byte("two")}
	second.EventHash = EventHash("ballot", second.PollID, second.Sequence, second.PreviousHash, second.Artifact)
	if _, err := ReplayBallot([]BallotEvent{first, second}); err != nil {
		t.Fatal(err)
	}
	for name, events := range map[string][]BallotEvent{
		"gap":       {first, {PollID: second.PollID, Sequence: 3, PreviousHash: second.PreviousHash, EventHash: second.EventHash, Artifact: second.Artifact}},
		"fork":      {first, {PollID: second.PollID, Sequence: 2, PreviousHash: EmptyHash(), EventHash: second.EventHash, Artifact: second.Artifact}},
		"duplicate": {first, first},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReplayBallot(events); err == nil {
				t.Fatal("mutation accepted")
			}
		})
	}
}

func TestClaimAndSpendUniqueness(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Transaction(ctx, func(tx *Tx) error {
		if err := tx.InsertPoll(ctx, Poll{PollID: "poll", ArtifactHash: "hash", Artifact: []byte("poll"), CreatedAt: "now", ClosesAt: "later", IssuerKeyID: "issuer", EligibilityCommitment: "members"}); err != nil {
			return err
		}
		return tx.InsertCredit(ctx, Credit{PollID: "poll", SSHFingerprint: "fingerprint", SSHPublicKey: "key"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Transaction(ctx, func(tx *Tx) error {
		return tx.ClaimCredit(ctx, "poll", "fingerprint", "request", "blinded", []byte("signature"), "now")
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Transaction(ctx, func(tx *Tx) error {
		return tx.ClaimCredit(ctx, "poll", "fingerprint", "other", "other", []byte("signature"), "now")
	}); ErrorCode(err) != "credit_already_claimed" {
		t.Fatalf("claim error = %v", err)
	}
	if err := store.Transaction(ctx, func(tx *Tx) error {
		return tx.SpendCredential(ctx, "poll", "credential", 1)
	}); err == nil {
		t.Fatal("spend without ballot event succeeded")
	}
}
