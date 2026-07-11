package auditverify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cirocosta/vota/internal/app"
	"github.com/cirocosta/vota/internal/audit"
	"github.com/cirocosta/vota/internal/crypto/election"
	"github.com/cirocosta/vota/internal/crypto/lrs"
	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/store"
)

func TestVerifyCompleteRecordAndMutations(t *testing.T) {
	encoded, expectedPollID := completeRecord(t)
	report, err := Verify(encoded)
	if err != nil {
		t.Fatalf("verify complete record: %v", err)
	}
	if report.PollID != expectedPollID || report.AcceptedBallotCount != 3 || report.EventCount != 9 {
		t.Fatalf("report = %+v", report)
	}
	if len(report.Totals) != 2 || report.Totals[0].Total != 2 || report.Totals[1].Total != 1 {
		t.Fatalf("totals = %+v", report.Totals)
	}

	bundle, err := audit.ParseBundle(encoded)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*audit.Bundle)
		code   string
	}{
		{name: "remove ballot", code: "audit_object_mismatch", mutate: func(value *audit.Bundle) { value.Ballots = value.Ballots[1:] }},
		{name: "duplicate nullifier", code: "duplicate_nullifier", mutate: func(value *audit.Bundle) { value.Ballots[1].Nullifier = value.Ballots[0].Nullifier }},
		{name: "aggregate", code: "aggregate_mismatch", mutate: func(value *audit.Bundle) { value.Aggregate.BallotHashes[0] = value.Aggregate.BallotHashes[1] }},
		{name: "share", code: "invalid_trustee_share", mutate: func(value *audit.Bundle) {
			value.Shares[0].Proofs[0] = value.Shares[0].Proofs[0][:len(value.Shares[0].Proofs[0])-2] + "00"
		}},
		{name: "tally", code: "invalid_tally", mutate: func(value *audit.Bundle) { value.Tally.Totals[0].Total++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var mutated audit.Bundle
			canonical, _ := protocol.MarshalCanonical(bundle)
			if err := protocol.DecodeStrict(canonical, &mutated); err != nil {
				t.Fatal(err)
			}
			test.mutate(&mutated)
			mutatedBytes, _ := protocol.MarshalCanonical(mutated)
			_, err := Verify(mutatedBytes)
			if err == nil || !strings.HasPrefix(err.Error(), test.code) {
				t.Fatalf("error = %v, want %s", err, test.code)
			}
		})
	}
}

func completeRecord(tb testing.TB) ([]byte, string) {
	tb.Helper()
	database, err := store.Open(context.Background(), filepath.Join(tb.TempDir(), "vota.sqlite"))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = database.Close() })
	checkpointPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	now := time.Date(2026, 8, 1, 13, 0, 0, 0, time.UTC)
	service, err := app.NewService(database, checkpointPrivate, app.ServiceOptions{Now: func() time.Time { return now }})
	if err != nil {
		tb.Fatal(err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join("..", "..", "testdata", "manifest", "canonical.json"))
	if err != nil {
		tb.Fatal(err)
	}
	frozen, err := manifest.Parse(manifestBytes)
	if err != nil {
		tb.Fatal(err)
	}
	value := frozen.Manifest()
	if _, _, err := service.PublishPoll(context.Background(), bytes.TrimSpace(manifestBytes)); err != nil {
		tb.Fatal(err)
	}
	for index, selected := range []int{0, 1, 0} {
		privateKey, publicKey, err := lrs.GenerateKey(newHashReader(fmt.Sprintf("voter-%d", index)))
		if err != nil {
			tb.Fatal(err)
		}
		signerIndex := -1
		encodedPublic := "ristretto255:" + hex.EncodeToString(publicKey[:])
		for candidate, eligible := range value.EligibleKeys {
			if eligible == encodedPublic {
				signerIndex = candidate
				break
			}
		}
		ballot, err := app.CastBallot(value, privateKey, signerIndex, selected, newHashReader(fmt.Sprintf("audit-ballot-%d", index)))
		if err != nil {
			tb.Fatal(err)
		}
		if _, _, err := service.AcceptBallot(context.Background(), ballot); err != nil {
			tb.Fatal(err)
		}
	}
	aggregate, _, err := service.ClosePoll(context.Background(), value.PollID)
	if err != nil {
		tb.Fatal(err)
	}
	contributions := make([]election.DealerContribution, 3)
	public := make([]election.PublicContribution, 3)
	for index := range 3 {
		contributions[index], err = election.GenerateDealerContribution(index+1, 3, 2, newHashReader(fmt.Sprintf("dealer-%d", index)))
		if err != nil {
			tb.Fatal(err)
		}
		public[index] = contributions[index].Public()
	}
	for recipient := 1; recipient <= 2; recipient++ {
		dealerShares := make([]election.DealerShare, 3)
		for dealer := range 3 {
			dealerShares[dealer], _ = contributions[dealer].ShareFor(recipient)
		}
		secret, err := election.FinalizeTrusteeShare(public, dealerShares, recipient)
		if err != nil {
			tb.Fatal(err)
		}
		signingPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(0x50 + recipient)}, ed25519.SeedSize))
		share, err := app.CreateTrusteeShare(value, aggregate, fmt.Sprintf("trustee-%d", recipient), secret, signingPrivate, newHashReader(fmt.Sprintf("audit-share-%d", recipient)))
		if err != nil {
			tb.Fatal(err)
		}
		if _, _, err := service.SubmitTrusteeShare(context.Background(), share); err != nil {
			tb.Fatal(err)
		}
	}
	encoded, err := service.ExportAudit(context.Background(), value.PollID)
	if err != nil {
		tb.Fatal(err)
	}
	return encoded, value.PollID
}

type hashReader struct {
	seed    []byte
	counter uint64
	buffer  []byte
}

func newHashReader(seed string) io.Reader { return &hashReader{seed: []byte(seed)} }

func (reader *hashReader) Read(output []byte) (int, error) {
	written := 0
	for written < len(output) {
		if len(reader.buffer) == 0 {
			input := append([]byte(nil), reader.seed...)
			input = append(input, byte(reader.counter>>56), byte(reader.counter>>48), byte(reader.counter>>40), byte(reader.counter>>32), byte(reader.counter>>24), byte(reader.counter>>16), byte(reader.counter>>8), byte(reader.counter))
			digest := sha512.Sum512(input)
			reader.buffer = append(reader.buffer[:0], digest[:]...)
			reader.counter++
		}
		count := copy(output[written:], reader.buffer)
		reader.buffer = reader.buffer[count:]
		written += count
	}
	return written, nil
}
