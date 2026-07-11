package election

import (
	"fmt"
	"io"
	"slices"

	"github.com/cirocosta/vota/internal/protocol"
	"github.com/gtank/ristretto255"
)

// AggregateBallots verifies and homomorphically adds accepted ballots.
func AggregateBallots(binding Binding, electionKey Point, ballots []EncryptedBallot) (Aggregate, error) {
	if len(ballots) < 1 || len(ballots) > MaxBallots {
		return Aggregate{}, &Error{Code: "invalid_ballot_count"}
	}
	choiceCount := len(ballots[0].Ciphertexts)
	if choiceCount < MinChoices || choiceCount > MaxChoices {
		return Aggregate{}, &Error{Code: "invalid_choice_count"}
	}
	sumsA := make([]*ristretto255.Element, choiceCount)
	sumsB := make([]*ristretto255.Element, choiceCount)
	for index := range choiceCount {
		sumsA[index] = ristretto255.NewIdentityElement()
		sumsB[index] = ristretto255.NewIdentityElement()
	}
	for ballotIndex, ballot := range ballots {
		if len(ballot.Ciphertexts) != choiceCount {
			return Aggregate{}, &Error{Code: "invalid_choice_count"}
		}
		if err := VerifyBallot(binding, electionKey, ballot); err != nil {
			return Aggregate{}, &Error{Code: "invalid_ballot", Err: fmt.Errorf("index %d: %w", ballotIndex, err)}
		}
		for choiceIndex, ciphertext := range ballot.Ciphertexts {
			a, _ := decodePoint(ciphertext.A)
			b, _ := decodePoint(ciphertext.B)
			sumsA[choiceIndex].Add(sumsA[choiceIndex], a)
			sumsB[choiceIndex].Add(sumsB[choiceIndex], b)
		}
	}
	aggregate := Aggregate{BallotCount: len(ballots), Ciphertexts: make([]Ciphertext, choiceCount)}
	for index := range choiceCount {
		aggregate.Ciphertexts[index] = Ciphertext{A: pointBytes(sumsA[index]), B: pointBytes(sumsB[index])}
	}
	return aggregate, nil
}

// CreateDecryptionShare proves a trustee's partial decryption of an aggregate.
func CreateDecryptionShare(
	ceremony Ceremony,
	secret TrusteeSecretShare,
	aggregateHash [32]byte,
	aggregate Aggregate,
	random io.Reader,
) (DecryptionShare, error) {
	if err := validateCeremony(ceremony); err != nil {
		return DecryptionShare{}, err
	}
	index := int(secret.TrusteeIndex)
	if index < 1 || index > ceremony.TrusteeCount {
		return DecryptionShare{}, &Error{Code: "unknown_trustee"}
	}
	if err := validateAggregate(aggregate); err != nil {
		return DecryptionShare{}, err
	}
	secretScalar, err := decodeScalar(secret.Value)
	if err != nil || secretScalar.Equal(ristretto255.NewScalar()) == 1 {
		return DecryptionShare{}, &Error{Code: "invalid_trustee_secret", Err: err}
	}
	publicKey, _ := decodePublicPoint(ceremony.TrusteePublicKeys[index-1])
	if ristretto255.NewIdentityElement().ScalarBaseMult(secretScalar).Equal(publicKey) != 1 {
		return DecryptionShare{}, &Error{Code: "wrong_trustee_secret"}
	}

	share := DecryptionShare{
		TrusteeIndex:  secret.TrusteeIndex,
		AggregateHash: aggregateHash,
		Values:        make([]Point, len(aggregate.Ciphertexts)),
		Proofs:        make([]EqualityProof, len(aggregate.Ciphertexts)),
	}
	for choiceIndex, ciphertext := range aggregate.Ciphertexts {
		a, _ := decodePoint(ciphertext.A)
		value := ristretto255.NewIdentityElement().ScalarMult(secretScalar, a)
		share.Values[choiceIndex] = pointBytes(value)
		fields := decryptionProofFields(ceremony, share.TrusteeIndex, aggregateHash, choiceIndex, ciphertext, share.Values[choiceIndex])
		share.Proofs[choiceIndex], err = proveEquality(
			protocol.DomainDecryptionShareProof,
			fields,
			ristretto255.NewGeneratorElement(), a,
			publicKey, value, secretScalar, random,
		)
		if err != nil {
			return DecryptionShare{}, err
		}
	}
	return share, nil
}

// VerifyDecryptionShare validates one trustee share against an aggregate.
func VerifyDecryptionShare(ceremony Ceremony, aggregateHash [32]byte, aggregate Aggregate, share DecryptionShare) error {
	if err := validateCeremony(ceremony); err != nil {
		return err
	}
	if err := validateAggregate(aggregate); err != nil {
		return err
	}
	index := int(share.TrusteeIndex)
	if index < 1 || index > ceremony.TrusteeCount {
		return &Error{Code: "unknown_trustee"}
	}
	if share.AggregateHash != aggregateHash {
		return &Error{Code: "wrong_aggregate_hash"}
	}
	if len(share.Values) != len(aggregate.Ciphertexts) || len(share.Proofs) != len(aggregate.Ciphertexts) {
		return &Error{Code: "invalid_decryption_share_size"}
	}
	publicKey, _ := decodePublicPoint(ceremony.TrusteePublicKeys[index-1])
	for choiceIndex, ciphertext := range aggregate.Ciphertexts {
		a, _ := decodePoint(ciphertext.A)
		value, err := decodePoint(share.Values[choiceIndex])
		if err != nil {
			return &Error{Code: "invalid_decryption_share", Err: err}
		}
		fields := decryptionProofFields(ceremony, share.TrusteeIndex, aggregateHash, choiceIndex, ciphertext, share.Values[choiceIndex])
		if err := verifyEquality(
			protocol.DomainDecryptionShareProof,
			fields,
			ristretto255.NewGeneratorElement(), a,
			publicKey, value, share.Proofs[choiceIndex],
		); err != nil {
			return &Error{Code: "invalid_decryption_share_proof", Err: fmt.Errorf("choice %d: %w", choiceIndex, err)}
		}
	}
	return nil
}

// CombineShares verifies a quorum and recovers bounded aggregate totals.
func CombineShares(
	ceremony Ceremony,
	aggregateHash [32]byte,
	aggregate Aggregate,
	shares []DecryptionShare,
) ([]int, error) {
	evidence, err := CombineTally(ceremony, aggregateHash, aggregate, shares)
	if err != nil {
		return nil, err
	}
	return evidence.Totals, nil
}

// CombineTally verifies a quorum and returns deterministic tally evidence.
func CombineTally(
	ceremony Ceremony,
	aggregateHash [32]byte,
	aggregate Aggregate,
	shares []DecryptionShare,
) (TallyEvidence, error) {
	if err := validateCeremony(ceremony); err != nil {
		return TallyEvidence{}, err
	}
	if err := validateAggregate(aggregate); err != nil {
		return TallyEvidence{}, err
	}
	if len(shares) < ceremony.Quorum {
		return TallyEvidence{}, &Error{Code: "insufficient_decryption_shares"}
	}
	if len(shares) > ceremony.TrusteeCount {
		return TallyEvidence{}, &Error{Code: "invalid_decryption_share_count"}
	}
	shares = append([]DecryptionShare(nil), shares...)
	slices.SortFunc(shares, func(left, right DecryptionShare) int {
		return int(left.TrusteeIndex) - int(right.TrusteeIndex)
	})
	seen := make(map[uint16]struct{}, len(shares))
	for _, share := range shares {
		if _, exists := seen[share.TrusteeIndex]; exists {
			return TallyEvidence{}, &Error{Code: "duplicate_trustee_share"}
		}
		seen[share.TrusteeIndex] = struct{}{}
		if err := VerifyDecryptionShare(ceremony, aggregateHash, aggregate, share); err != nil {
			return TallyEvidence{}, err
		}
	}

	indices := make([]*ristretto255.Scalar, len(shares))
	for index, share := range shares {
		indices[index] = scalarFromIndex(share.TrusteeIndex)
	}
	coefficients := lagrangeAtZero(indices)
	totals := make([]int, len(aggregate.Ciphertexts))
	for choiceIndex, ciphertext := range aggregate.Ciphertexts {
		combined := ristretto255.NewIdentityElement()
		for shareIndex, share := range shares {
			value, _ := decodePoint(share.Values[choiceIndex])
			term := ristretto255.NewIdentityElement().ScalarMult(coefficients[shareIndex], value)
			combined.Add(combined, term)
		}
		b, _ := decodePoint(ciphertext.B)
		message := subtractPoints(b, combined)
		total, ok := boundedDiscreteLog(message, aggregate.BallotCount)
		if !ok {
			return TallyEvidence{}, &Error{Code: "tally_out_of_range", Err: fmt.Errorf("choice %d", choiceIndex)}
		}
		totals[choiceIndex] = total
	}
	sum := 0
	for _, total := range totals {
		sum += total
	}
	if sum != aggregate.BallotCount {
		return TallyEvidence{}, &Error{Code: "tally_invariant_failed"}
	}
	trusteeIndices := make([]uint16, len(shares))
	for index, share := range shares {
		trusteeIndices[index] = share.TrusteeIndex
	}
	return TallyEvidence{
		AggregateHash:  aggregateHash,
		BallotCount:    aggregate.BallotCount,
		Totals:         totals,
		TrusteeIndices: trusteeIndices,
	}, nil
}

func validateCeremony(ceremony Ceremony) error {
	if ceremony.TrusteeCount < MinTrustees || ceremony.TrusteeCount > MaxTrustees || len(ceremony.TrusteePublicKeys) != ceremony.TrusteeCount {
		return &Error{Code: "invalid_trustee_count"}
	}
	if ceremony.Quorum < MinTrustees || ceremony.Quorum > ceremony.TrusteeCount {
		return &Error{Code: "invalid_quorum"}
	}
	if _, err := decodePublicPoint(ceremony.ElectionKey); err != nil {
		return &Error{Code: "invalid_election_key", Err: err}
	}
	for index, key := range ceremony.TrusteePublicKeys {
		if _, err := decodePublicPoint(key); err != nil {
			return &Error{Code: "invalid_trustee_public_key", Err: fmt.Errorf("index %d: %w", index, err)}
		}
	}
	return nil
}

func validateAggregate(aggregate Aggregate) error {
	if aggregate.BallotCount < 1 || aggregate.BallotCount > MaxBallots {
		return &Error{Code: "invalid_ballot_count"}
	}
	if len(aggregate.Ciphertexts) < MinChoices || len(aggregate.Ciphertexts) > MaxChoices {
		return &Error{Code: "invalid_choice_count"}
	}
	for index, ciphertext := range aggregate.Ciphertexts {
		if _, err := decodePoint(ciphertext.A); err != nil {
			return &Error{Code: "invalid_aggregate", Err: fmt.Errorf("choice %d A: %w", index, err)}
		}
		if _, err := decodePoint(ciphertext.B); err != nil {
			return &Error{Code: "invalid_aggregate", Err: fmt.Errorf("choice %d B: %w", index, err)}
		}
	}
	return nil
}

func decryptionProofFields(
	ceremony Ceremony,
	trusteeIndex uint16,
	aggregateHash [32]byte,
	choiceIndex int,
	ciphertext Ciphertext,
	value Point,
) [][]byte {
	return [][]byte{
		aggregateHash[:],
		indexBytes(int(trusteeIndex)),
		indexBytes(choiceIndex),
		ceremony.ElectionKey[:],
		ceremony.TrusteePublicKeys[int(trusteeIndex)-1][:],
		ciphertext.A[:], ciphertext.B[:], value[:],
	}
}

func lagrangeAtZero(indices []*ristretto255.Scalar) []*ristretto255.Scalar {
	coefficients := make([]*ristretto255.Scalar, len(indices))
	for i, own := range indices {
		numerator := scalarFromIndex(1)
		denominator := scalarFromIndex(1)
		for j, other := range indices {
			if i == j {
				continue
			}
			numerator.Multiply(numerator, other)
			denominator.Multiply(denominator, ristretto255.NewScalar().Subtract(other, own))
		}
		coefficients[i] = ristretto255.NewScalar().Multiply(numerator, ristretto255.NewScalar().Invert(denominator))
	}
	return coefficients
}

func boundedDiscreteLog(message *ristretto255.Element, maximum int) (int, bool) {
	candidate := ristretto255.NewIdentityElement()
	generator := ristretto255.NewGeneratorElement()
	for value := 0; value <= maximum; value++ {
		if candidate.Equal(message) == 1 {
			return value, true
		}
		candidate.Add(candidate, generator)
	}
	return 0, false
}
