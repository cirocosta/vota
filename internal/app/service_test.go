package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cirocosta/vota/internal/audit"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/store"
)

func TestPublishAcceptAndIdempotentRetry(t *testing.T) {
	t.Parallel()

	service, database := testService(t, nil)
	value := testManifest(t)
	manifestBytes, _ := protocol.MarshalCanonical(value)
	if _, created, err := service.PublishPoll(context.Background(), manifestBytes); err != nil || !created {
		t.Fatalf("publish created = %v, error = %v", created, err)
	}
	if _, created, err := service.PublishPoll(context.Background(), manifestBytes); err != nil || created {
		t.Fatalf("retry created = %v, error = %v", created, err)
	}
	privateKey, signerIndex := eligibleCredential(t, value, "voter-0")
	ballot, err := CastBallot(value, privateKey, signerIndex, 1, newHashReader("service-ballot"))
	if err != nil {
		t.Fatal(err)
	}
	receipt, created, err := service.AcceptBallot(context.Background(), ballot)
	if err != nil || !created {
		t.Fatalf("accept created = %v, error = %v", created, err)
	}
	retry, created, err := service.AcceptBallot(context.Background(), ballot)
	if err != nil || created || retry != receipt {
		t.Fatalf("retry created = %v, receipt = %+v, error = %v", created, retry, err)
	}
	stored, err := service.Receipt(context.Background(), value.PollID, ballot.BallotHash)
	if err != nil || stored != receipt {
		t.Fatalf("stored receipt = %+v, error = %v", stored, err)
	}

	events, err := database.Events(context.Background(), value.PollID)
	if err != nil || len(events) != 2 {
		t.Fatalf("events = %+v, error = %v", events, err)
	}
	checkpoints, err := database.Checkpoints(context.Background(), value.PollID)
	if err != nil || len(checkpoints) != 2 {
		t.Fatalf("checkpoints = %+v, error = %v", checkpoints, err)
	}
	var event protocol.AuditEvent
	var checkpoint protocol.Checkpoint
	if err := protocol.DecodeStrict(events[1].Artifact, &event); err != nil {
		t.Fatal(err)
	}
	if err := protocol.DecodeStrict(checkpoints[1].Artifact, &checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := audit.VerifyReceipt(service.CheckpointPublicKey(), receipt, event, checkpoint); err != nil {
		t.Fatalf("verify receipt: %v", err)
	}
}

func TestAcceptRejectsDoubleVote(t *testing.T) {
	t.Parallel()

	service, _ := testService(t, nil)
	value := publishFixture(t, service)
	privateKey, signerIndex := eligibleCredential(t, value, "voter-1")
	first, _ := CastBallot(value, privateKey, signerIndex, 0, newHashReader("double-first"))
	second, _ := CastBallot(value, privateKey, signerIndex, 1, newHashReader("double-second"))
	if _, _, err := service.AcceptBallot(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.AcceptBallot(context.Background(), second); ErrorCode(err) != "double_vote" {
		t.Fatalf("double vote error = %v", err)
	}
}

func TestInjectedFailureRollsBackServiceWrites(t *testing.T) {
	t.Parallel()

	injected := errors.New("stop before commit")
	service, database := testService(t, func() error { return injected })
	value := testManifest(t)
	manifestBytes, _ := protocol.MarshalCanonical(value)
	if _, _, err := service.PublishPoll(context.Background(), manifestBytes); ErrorCode(err) != "injected_failure" {
		t.Fatalf("publish error = %v", err)
	}
	if _, err := database.Poll(context.Background(), value.PollID); store.ErrorCode(err) != "poll_not_found" {
		t.Fatalf("poll after rollback = %v", err)
	}

	normal, err := NewService(database, checkpointKey(), ServiceOptions{Now: service.now})
	if err != nil {
		t.Fatal(err)
	}
	publishFixture(t, normal)
	privateKey, signerIndex := eligibleCredential(t, value, "voter-0")
	ballot, _ := CastBallot(value, privateKey, signerIndex, 0, newHashReader("rollback-ballot"))
	if _, _, err := service.AcceptBallot(context.Background(), ballot); ErrorCode(err) != "injected_failure" {
		t.Fatalf("accept error = %v", err)
	}
	ballots, _ := database.Ballots(context.Background(), value.PollID)
	events, _ := database.Events(context.Background(), value.PollID)
	if len(ballots) != 0 || len(events) != 1 {
		t.Fatalf("ballots = %d, events = %d", len(ballots), len(events))
	}
}

func TestFiftyConcurrentSameNullifierSubmissions(t *testing.T) {
	service, database := testService(t, nil)
	value := publishFixture(t, service)
	privateKey, signerIndex := eligibleCredential(t, value, "voter-2")
	const workers = 50
	ballots := make([]protocol.BallotEnvelope, workers)
	for index := range workers {
		var err error
		ballots[index], err = CastBallot(value, privateKey, signerIndex, index%2, newHashReader(fmt.Sprintf("concurrent-%d", index)))
		if err != nil {
			t.Fatal(err)
		}
	}
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
			_, created, err := service.AcceptBallot(context.Background(), ballots[index])
			if err == nil && created {
				successes.Add(1)
				return
			}
			if ErrorCode(err) == "double_vote" {
				doubleVotes.Add(1)
				return
			}
			unexpected.CompareAndSwap(nil, fmt.Errorf("created=%v: %w", created, err))
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
	stored, _ := database.Ballots(context.Background(), value.PollID)
	if len(stored) != 1 {
		t.Fatalf("stored ballots = %d", len(stored))
	}
	matched := false
	for _, ballot := range ballots {
		encoded, _ := MarshalBallot(ballot)
		matched = matched || bytes.Equal(encoded, stored[0].Artifact)
	}
	if !matched {
		t.Fatal("stored winner is not one submitted artifact")
	}
}

func TestClosePublishesDeterministicAggregate(t *testing.T) {
	t.Parallel()

	service, database := testService(t, nil)
	value := publishFixture(t, service)
	for index, seed := range []string{"voter-0", "voter-1", "voter-2"} {
		privateKey, signerIndex := eligibleCredential(t, value, seed)
		ballot, err := CastBallot(value, privateKey, signerIndex, index%2, newHashReader(fmt.Sprintf("close-ballot-%d", index)))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := service.AcceptBallot(context.Background(), ballot); err != nil {
			t.Fatal(err)
		}
	}
	aggregate, created, err := service.ClosePoll(context.Background(), value.PollID)
	if err != nil || !created {
		t.Fatalf("close created = %v, error = %v", created, err)
	}
	if aggregate.BallotCount != 3 || len(aggregate.BallotHashes) != 3 || len(aggregate.Ciphertexts) != 2 {
		t.Fatalf("aggregate = %+v", aggregate)
	}
	retry, created, err := service.ClosePoll(context.Background(), value.PollID)
	if err != nil || created || retry.AggregateHash != aggregate.AggregateHash {
		t.Fatalf("retry created = %v, aggregate = %+v, error = %v", created, retry, err)
	}
	record, err := database.Poll(context.Background(), value.PollID)
	if err != nil || record.State != "closed" || record.AggregateHash != aggregate.AggregateHash {
		t.Fatalf("poll = %+v, error = %v", record, err)
	}
	parsed, err := ParseAggregate(record.Aggregate)
	if err != nil || parsed.AggregateHash != aggregate.AggregateHash {
		t.Fatalf("parsed aggregate = %+v, error = %v", parsed, err)
	}
}

func TestCloseAndSubmissionRaceIsAtomic(t *testing.T) {
	service, database := testService(t, nil)
	value := publishFixture(t, service)
	firstKey, firstIndex := eligibleCredential(t, value, "voter-0")
	first, _ := CastBallot(value, firstKey, firstIndex, 0, newHashReader("race-first"))
	if _, _, err := service.AcceptBallot(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	secondKey, secondIndex := eligibleCredential(t, value, "voter-1")
	second, _ := CastBallot(value, secondKey, secondIndex, 1, newHashReader("race-second"))
	start := make(chan struct{})
	var closeAggregate protocol.EncryptedAggregate
	var closeErr, acceptErr error
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		closeAggregate, _, closeErr = service.ClosePoll(context.Background(), value.PollID)
	}()
	go func() {
		defer wait.Done()
		<-start
		_, _, acceptErr = service.AcceptBallot(context.Background(), second)
	}()
	close(start)
	wait.Wait()
	if closeErr != nil {
		t.Fatalf("close error = %v", closeErr)
	}
	if acceptErr != nil && ErrorCode(acceptErr) != "poll_closed" {
		t.Fatalf("accept error = %v", acceptErr)
	}
	stored, err := database.Ballots(context.Background(), value.PollID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != closeAggregate.BallotCount {
		t.Fatalf("stored ballots = %d, aggregate ballots = %d", len(stored), closeAggregate.BallotCount)
	}
	for index := range stored {
		if stored[index].BallotHash != closeAggregate.BallotHashes[index] {
			t.Fatalf("ballot %d hash mismatch", index)
		}
	}
}

func testService(tb testing.TB, beforeCommit func() error) (*Service, *store.Store) {
	tb.Helper()
	database, err := store.Open(context.Background(), filepath.Join(tb.TempDir(), "vota.db"))
	if err != nil {
		tb.Fatalf("open store: %v", err)
	}
	tb.Cleanup(func() {
		if err := database.Close(); err != nil {
			tb.Errorf("close store: %v", err)
		}
	})
	service, err := NewService(database, checkpointKey(), ServiceOptions{
		Now:          func() time.Time { return time.Date(2026, 8, 1, 13, 0, 0, 0, time.UTC) },
		BeforeCommit: beforeCommit,
	})
	if err != nil {
		tb.Fatalf("new service: %v", err)
	}
	return service, database
}

func checkpointKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xa1}, ed25519.SeedSize))
}

func publishFixture(tb testing.TB, service *Service) protocol.Manifest {
	tb.Helper()
	value := testManifest(tb)
	encoded, err := protocol.MarshalCanonical(value)
	if err != nil {
		tb.Fatalf("marshal manifest: %v", err)
	}
	if _, _, err := service.PublishPoll(context.Background(), encoded); err != nil {
		tb.Fatalf("publish: %v", err)
	}
	return value
}
