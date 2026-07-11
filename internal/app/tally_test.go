package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/cirocosta/vota/internal/audit"
	"github.com/cirocosta/vota/internal/crypto/election"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/store"
)

func TestTrusteeQuorumPublishesAggregateOnlyTally(t *testing.T) {
	t.Parallel()

	service, database := testService(t, nil)
	value := publishFixture(t, service)
	selections := []int{0, 1, 0}
	for index, selected := range selections {
		privateKey, signerIndex := eligibleCredential(t, value, fmt.Sprintf("voter-%d", index))
		ballot, err := CastBallot(value, privateKey, signerIndex, selected, newHashReader(fmt.Sprintf("tally-ballot-%d", index)))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := service.AcceptBallot(context.Background(), ballot); err != nil {
			t.Fatal(err)
		}
	}
	aggregate, _, err := service.ClosePoll(context.Background(), value.PollID)
	if err != nil {
		t.Fatal(err)
	}
	secrets := trusteeSecrets(t)
	first := createFixtureShare(t, value, aggregate, 0, secrets[0])
	if tally, created, err := service.SubmitTrusteeShare(context.Background(), first); err != nil || !created || tally != nil {
		t.Fatalf("first share tally = %+v, created = %v, error = %v", tally, created, err)
	}
	second := createFixtureShare(t, value, aggregate, 1, secrets[1])
	tally, created, err := service.SubmitTrusteeShare(context.Background(), second)
	if err != nil || !created || tally == nil {
		t.Fatalf("second share tally = %+v, created = %v, error = %v", tally, created, err)
	}
	if len(tally.Totals) != 2 || tally.Totals[0].Total != 2 || tally.Totals[1].Total != 1 || tally.BallotCount != 3 {
		t.Fatalf("tally = %+v", tally)
	}
	if err := VerifyTally(value, *tally, service.CheckpointPublicKey()); err != nil {
		t.Fatalf("verify tally: %v", err)
	}
	retry, created, err := service.SubmitTrusteeShare(context.Background(), second)
	if err != nil || created || retry == nil || retry.EvidenceHash != tally.EvidenceHash {
		t.Fatalf("retry tally = %+v, created = %v, error = %v", retry, created, err)
	}
	stored, err := service.Tally(context.Background(), value.PollID)
	if err != nil || stored.EvidenceHash != tally.EvidenceHash {
		t.Fatalf("stored tally = %+v, error = %v", stored, err)
	}
	poll, _ := database.Poll(context.Background(), value.PollID)
	if poll.State != "tallied" {
		t.Fatalf("poll state = %q", poll.State)
	}
	bundleBytes, err := service.ExportAudit(context.Background(), value.PollID)
	if err != nil {
		t.Fatalf("export audit: %v", err)
	}
	if _, err := audit.ParseBundle(bundleBytes, service.CheckpointPublicKey()); err != nil {
		t.Fatalf("verify audit: %v", err)
	}
	third := createFixtureShare(t, value, aggregate, 2, secrets[2])
	if _, _, err := service.SubmitTrusteeShare(context.Background(), third); ErrorCode(err) != "tally_final" {
		t.Fatalf("third share error = %v", err)
	}
}

func TestShareRejectsMutationAndStaleAggregate(t *testing.T) {
	t.Parallel()

	service, _ := testService(t, nil)
	value := publishFixture(t, service)
	privateKey, signerIndex := eligibleCredential(t, value, "voter-0")
	ballot, _ := CastBallot(value, privateKey, signerIndex, 0, newHashReader("share-ballot"))
	_, _, _ = service.AcceptBallot(context.Background(), ballot)
	aggregate, _, _ := service.ClosePoll(context.Background(), value.PollID)
	share := createFixtureShare(t, value, aggregate, 0, trusteeSecrets(t)[0])
	mutated := share
	mutated.Proofs = append([]string(nil), share.Proofs...)
	mutated.Proofs[0] = mutated.Proofs[0][:len(mutated.Proofs[0])-2] + "00"
	if err := VerifyTrusteeShare(value, aggregate, mutated); err == nil {
		t.Fatal("mutated proof verified")
	}
	stale := share
	stale.AggregateHash = hashString("stale")
	if err := VerifyTrusteeShare(value, aggregate, stale); ErrorCode(err) != "wrong_aggregate_hash" {
		t.Fatalf("stale error = %v", err)
	}
}

func TestPrivacyThresholdSuppressesSmallTally(t *testing.T) {
	t.Parallel()

	service, database := testService(t, nil)
	value := publishFixture(t, service)
	privateKey, signerIndex := eligibleCredential(t, value, "voter-0")
	ballot, _ := CastBallot(value, privateKey, signerIndex, 0, newHashReader("privacy-ballot"))
	_, _, _ = service.AcceptBallot(context.Background(), ballot)
	aggregate, _, err := service.ClosePoll(context.Background(), value.PollID)
	if err != nil {
		t.Fatal(err)
	}
	secrets := trusteeSecrets(t)
	for index := range 2 {
		share := createFixtureShare(t, value, aggregate, index, secrets[index])
		tally, _, err := service.SubmitTrusteeShare(context.Background(), share)
		if err != nil || tally != nil {
			t.Fatalf("share %d tally = %+v, error = %v", index, tally, err)
		}
	}
	if _, err := database.Tally(context.Background(), value.PollID); store.ErrorCode(err) != "tally_not_found" {
		t.Fatalf("tally lookup error = %v", err)
	}
}

func TestQuorumFailureRollsBackSecondShareAndTally(t *testing.T) {
	t.Parallel()

	normal, database := testService(t, nil)
	value := publishFixture(t, normal)
	for index := range 2 {
		privateKey, signerIndex := eligibleCredential(t, value, fmt.Sprintf("voter-%d", index))
		ballot, _ := CastBallot(value, privateKey, signerIndex, index, newHashReader(fmt.Sprintf("failure-ballot-%d", index)))
		_, _, _ = normal.AcceptBallot(context.Background(), ballot)
	}
	aggregate, _, err := normal.ClosePoll(context.Background(), value.PollID)
	if err != nil {
		t.Fatal(err)
	}
	secrets := trusteeSecrets(t)
	first := createFixtureShare(t, value, aggregate, 0, secrets[0])
	if _, _, err := normal.SubmitTrusteeShare(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	failing, err := NewService(database, checkpointKey(), ServiceOptions{
		Now:          normal.now,
		BeforeCommit: func() error { return fmt.Errorf("injected") },
	})
	if err != nil {
		t.Fatal(err)
	}
	second := createFixtureShare(t, value, aggregate, 1, secrets[1])
	if _, _, err := failing.SubmitTrusteeShare(context.Background(), second); ErrorCode(err) != "injected_failure" {
		t.Fatalf("submit error = %v", err)
	}
	shares, _ := database.TrusteeShares(context.Background(), value.PollID)
	if len(shares) != 1 {
		t.Fatalf("stored shares = %d", len(shares))
	}
	if _, err := database.Tally(context.Background(), value.PollID); store.ErrorCode(err) != "tally_not_found" {
		t.Fatalf("tally error = %v", err)
	}
}

func trusteeSecrets(tb testing.TB) []election.TrusteeSecretShare {
	tb.Helper()
	contributions := make([]election.DealerContribution, 3)
	public := make([]election.PublicContribution, 3)
	for index := range 3 {
		contribution, err := election.GenerateDealerContribution(index+1, 3, 2, newHashReader(fmt.Sprintf("dealer-%d", index)))
		if err != nil {
			tb.Fatalf("dealer %d: %v", index, err)
		}
		contributions[index] = contribution
		public[index] = contribution.Public()
	}
	secrets := make([]election.TrusteeSecretShare, 3)
	for recipient := 1; recipient <= 3; recipient++ {
		shares := make([]election.DealerShare, 3)
		for dealer := range 3 {
			share, err := contributions[dealer].ShareFor(recipient)
			if err != nil {
				tb.Fatal(err)
			}
			shares[dealer] = share
		}
		secret, err := election.FinalizeTrusteeShare(public, shares, recipient)
		if err != nil {
			tb.Fatalf("finalize trustee %d: %v", recipient, err)
		}
		secrets[recipient-1] = secret
	}
	return secrets
}

func createFixtureShare(tb testing.TB, value protocol.Manifest, aggregate protocol.EncryptedAggregate, index int, secret election.TrusteeSecretShare) protocol.TrusteeShare {
	tb.Helper()
	signingPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(0x51 + index)}, ed25519.SeedSize))
	share, err := CreateTrusteeShare(value, aggregate, fmt.Sprintf("trustee-%d", index+1), secret, signingPrivateKey, newHashReader(fmt.Sprintf("trustee-share-%d", index)))
	if err != nil {
		tb.Fatalf("create share %d: %v", index, err)
	}
	return share
}
