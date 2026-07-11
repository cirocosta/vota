/*
Encrypted threshold tally:

 1. Three trustees contribute Feldman polynomials. Public commitments produce
    one election key Y. Each trustee receives one private share y_i.
 2. A ballot encrypts one bit per choice and proves every bit is 0 or 1 and
    their sum is exactly 1.
 3. Ciphertexts are added by choice position. No ballot is decrypted.
 4. Two of three trustees prove partial decryptions of the aggregate.
 5. Lagrange interpolation combines those shares and recovers bounded totals.

This example calls Vota's real election package. The printed result contains
only aggregate totals. Production Vota also binds these objects to a signed
manifest, audit events, and trustee signatures.
*/
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/cirocosta/vota/internal/crypto/election"
)

type demonstration struct {
	ballotCount       int
	totals            []int
	oneShareRejected  bool
	allProofsVerified bool
}

func demonstrate(random io.Reader) (demonstration, error) {
	ceremony, secrets, err := createCeremony(random, 3, 2)
	if err != nil {
		return demonstration{}, err
	}
	binding := election.Binding{
		PollID:       sha256.Sum256([]byte("threshold example poll")),
		ManifestHash: sha256.Sum256([]byte("threshold example manifest")),
	}
	selections := []int{0, 1, 0}
	ballots := make([]election.EncryptedBallot, len(selections))
	proofsVerified := true
	for index, selected := range selections {
		ballots[index], err = election.EncryptChoice(binding, ceremony.ElectionKey, 3, selected, random)
		if err != nil {
			return demonstration{}, err
		}
		proofsVerified = proofsVerified && election.VerifyBallot(binding, ceremony.ElectionKey, ballots[index]) == nil
	}
	aggregate, err := election.AggregateBallots(binding, ceremony.ElectionKey, ballots)
	if err != nil {
		return demonstration{}, err
	}
	encodedAggregate, err := aggregate.MarshalBinary()
	if err != nil {
		return demonstration{}, err
	}
	aggregateHash := sha256.Sum256(encodedAggregate)
	shares := make([]election.DecryptionShare, 2)
	for index := range shares {
		shares[index], err = election.CreateDecryptionShare(ceremony, secrets[index], aggregateHash, aggregate, random)
		if err != nil {
			return demonstration{}, err
		}
	}
	_, oneShareErr := election.CombineShares(ceremony, aggregateHash, aggregate, shares[:1])
	totals, err := election.CombineShares(ceremony, aggregateHash, aggregate, shares)
	if err != nil {
		return demonstration{}, err
	}
	return demonstration{
		ballotCount:       len(ballots),
		totals:            totals,
		oneShareRejected:  oneShareErr != nil,
		allProofsVerified: proofsVerified,
	}, nil
}

func createCeremony(random io.Reader, trusteeCount, quorum int) (election.Ceremony, []election.TrusteeSecretShare, error) {
	dealers := make([]election.DealerContribution, trusteeCount)
	public := make([]election.PublicContribution, trusteeCount)
	var err error
	for index := range trusteeCount {
		dealers[index], err = election.GenerateDealerContribution(index+1, trusteeCount, quorum, random)
		if err != nil {
			return election.Ceremony{}, nil, err
		}
		public[index] = dealers[index].Public()
	}
	ceremony, err := election.FinalizePublicCeremony(public)
	if err != nil {
		return election.Ceremony{}, nil, err
	}
	secrets := make([]election.TrusteeSecretShare, trusteeCount)
	for recipient := 1; recipient <= trusteeCount; recipient++ {
		shares := make([]election.DealerShare, trusteeCount)
		for dealer := range trusteeCount {
			shares[dealer], err = dealers[dealer].ShareFor(recipient)
			if err != nil {
				return election.Ceremony{}, nil, err
			}
		}
		secrets[recipient-1], err = election.FinalizeTrusteeShare(public, shares, recipient)
		if err != nil {
			return election.Ceremony{}, nil, err
		}
	}
	return ceremony, secrets, nil
}

func main() {
	result, err := demonstrate(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("verified one-hot ballots: %t\n", result.allProofsVerified)
	fmt.Printf("accepted ballots: %d\n", result.ballotCount)
	fmt.Printf("one trustee is insufficient: %t\n", result.oneShareRejected)
	fmt.Printf("two-of-three aggregate totals: %v\n", result.totals)
}
