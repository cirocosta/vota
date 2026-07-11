package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestMigrationsAreIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vota.db")
	for attempt := range 2 {
		store, err := Open(ctx, path)
		if err != nil {
			t.Fatalf("open attempt %d: %v", attempt, err)
		}
		var migrations int
		if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&migrations); err != nil {
			t.Fatalf("count migrations: %v", err)
		}
		if migrations != 1 {
			t.Fatalf("migration count = %d", migrations)
		}
		var foreignKeys int
		if err := store.db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
			t.Fatalf("foreign keys: %v", err)
		}
		if foreignKeys != 1 {
			t.Fatal("foreign keys are disabled")
		}
		if err := store.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}
}

func TestTransactionFaultRollsBackBallotAndEvent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := openTestStore(t)
	insertTestPoll(t, store)
	injected := errors.New("injected before commit")
	err := store.transaction(ctx, func(tx *Tx) error {
		if err := tx.InsertEvent(ctx, testEvent(1)); err != nil {
			return err
		}
		return tx.InsertBallot(ctx, testBallot(1, "ballot-1", "nullifier-1"))
	}, func() error { return injected })
	if !errors.Is(err, injected) {
		t.Fatalf("transaction error = %v", err)
	}
	assertCount(t, store, "audit_events", 0)
	assertCount(t, store, "ballots", 0)

	if err := store.Transaction(ctx, func(tx *Tx) error {
		if err := tx.InsertEvent(ctx, testEvent(1)); err != nil {
			return err
		}
		return tx.InsertBallot(ctx, testBallot(1, "ballot-1", "nullifier-1"))
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	assertCount(t, store, "audit_events", 1)
	assertCount(t, store, "ballots", 1)
}

func TestUniquenessConstraintsReturnStableCodes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := openTestStore(t)
	insertTestPoll(t, store)
	insertEventAndBallot(t, store, testEvent(1), testBallot(1, "ballot-1", "nullifier-1"))

	tests := []struct {
		name   string
		ballot Ballot
		code   string
	}{
		{"same ballot", testBallot(2, "ballot-1", "nullifier-2"), "duplicate_ballot"},
		{"same nullifier", testBallot(2, "ballot-2", "nullifier-1"), "double_vote"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := store.Transaction(ctx, func(tx *Tx) error {
				if err := tx.InsertEvent(ctx, testEvent(2)); err != nil {
					return err
				}
				return tx.InsertBallot(ctx, test.ballot)
			})
			if ErrorCode(err) != test.code {
				t.Fatalf("error = %v, code = %q", err, ErrorCode(err))
			}
			assertCount(t, store, "audit_events", 1)
		})
	}

	share := TrusteeShare{PollID: "poll-1", TrusteeID: "t1", AggregateHash: "aggregate-1", ArtifactHash: "share-1", Artifact: []byte("share"), SubmittedAt: "2026-07-11T12:00:00Z"}
	if err := store.Transaction(ctx, func(tx *Tx) error { return tx.InsertTrusteeShare(ctx, share) }); err != nil {
		t.Fatalf("insert share: %v", err)
	}
	if err := store.Transaction(ctx, func(tx *Tx) error { return tx.InsertTrusteeShare(ctx, share) }); ErrorCode(err) != "duplicate_trustee_share" {
		t.Fatalf("duplicate share error = %v", err)
	}
}

func TestBallotRequiresAuditEvent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := openTestStore(t)
	insertTestPoll(t, store)
	err := store.Transaction(ctx, func(tx *Tx) error {
		return tx.InsertBallot(ctx, testBallot(1, "ballot-1", "nullifier-1"))
	})
	if ErrorCode(err) != "transaction_commit_failed" {
		t.Fatalf("error = %v", err)
	}
	assertCount(t, store, "ballots", 0)
}

func TestRecordsSurviveRestart(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "restart.db")
	first, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open first: %v", err)
	}
	insertTestPoll(t, first)
	insertEventAndBallot(t, first, testEvent(1), testBallot(1, "ballot-1", "nullifier-1"))
	if err := first.Close(); err != nil {
		t.Fatalf("close first: %v", err)
	}

	second, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open second: %v", err)
	}
	defer func() {
		if err := second.Close(); err != nil {
			t.Errorf("close second: %v", err)
		}
	}()
	ballot, err := second.BallotByNullifier(ctx, "poll-1", "nullifier-1")
	if err != nil {
		t.Fatalf("read ballot: %v", err)
	}
	if ballot.BallotHash != "ballot-1" || ballot.Sequence != 1 {
		t.Fatalf("ballot = %+v", ballot)
	}
	events, err := second.Events(ctx, "poll-1")
	if err != nil || len(events) != 1 || events[0].EventHash != "event-1" {
		t.Fatalf("events = %+v, error = %v", events, err)
	}
}

func TestConcurrentDuplicateNullifierHasOneWinner(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	insertTestPoll(t, store)

	const workers = 50
	start := make(chan struct{})
	var successes atomic.Int64
	var doubleVotes atomic.Int64
	var unexpected atomic.Value
	var wait sync.WaitGroup
	for index := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			sequence := uint64(index + 1)
			err := store.Transaction(ctx, func(tx *Tx) error {
				if err := tx.InsertEvent(ctx, testEvent(sequence)); err != nil {
					return err
				}
				return tx.InsertBallot(ctx, testBallot(sequence, fmt.Sprintf("ballot-%d", index), "shared-nullifier"))
			})
			if err == nil {
				successes.Add(1)
				return
			}
			switch ErrorCode(err) {
			case "double_vote":
				doubleVotes.Add(1)
			default:
				unexpected.CompareAndSwap(nil, err)
			}
		}()
	}
	close(start)
	wait.Wait()
	if value := unexpected.Load(); value != nil {
		t.Fatalf("unexpected error: %v", value)
	}
	if successes.Load() != 1 || doubleVotes.Load() != workers-1 {
		t.Fatalf("successes = %d, double votes = %d", successes.Load(), doubleVotes.Load())
	}
	assertCount(t, store, "ballots", 1)
	assertCount(t, store, "audit_events", 1)
}

func openTestStore(tb testing.TB) *Store {
	tb.Helper()
	store, err := Open(context.Background(), filepath.Join(tb.TempDir(), "vota.db"))
	if err != nil {
		tb.Fatalf("open: %v", err)
	}
	tb.Cleanup(func() {
		if err := store.Close(); err != nil {
			tb.Errorf("close: %v", err)
		}
	})
	return store
}

func insertTestPoll(tb testing.TB, store *Store) {
	tb.Helper()
	poll := Poll{PollID: "poll-1", ManifestHash: "manifest-1", Manifest: []byte("manifest"), State: "open", CreatedAt: "2026-07-11T12:00:00Z"}
	if err := store.Transaction(context.Background(), func(tx *Tx) error { return tx.InsertPoll(context.Background(), poll) }); err != nil {
		tb.Fatalf("insert poll: %v", err)
	}
}

func insertEventAndBallot(tb testing.TB, store *Store, event Event, ballot Ballot) {
	tb.Helper()
	if err := store.Transaction(context.Background(), func(tx *Tx) error {
		if err := tx.InsertEvent(context.Background(), event); err != nil {
			return err
		}
		return tx.InsertBallot(context.Background(), ballot)
	}); err != nil {
		tb.Fatalf("insert event and ballot: %v", err)
	}
}

func testEvent(sequence uint64) Event {
	return Event{PollID: "poll-1", Sequence: sequence, EventHash: fmt.Sprintf("event-%d", sequence), Artifact: []byte("event"), AcceptedAt: "2026-07-11T12:00:00Z"}
}

func testBallot(sequence uint64, hash, nullifier string) Ballot {
	return Ballot{PollID: "poll-1", BallotHash: hash, Nullifier: nullifier, Artifact: []byte("ballot"), Sequence: sequence, AcceptedAt: "2026-07-11T12:00:00Z"}
}

func assertCount(tb testing.TB, store *Store, table string, want int) {
	tb.Helper()
	var got int
	if err := store.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM `+table).Scan(&got); err != nil {
		tb.Fatalf("count %s: %v", table, err)
	}
	if got != want {
		tb.Fatalf("%s count = %d, want %d", table, got, want)
	}
}
