package election

import (
	"fmt"
	"io"

	"github.com/gtank/ristretto255"
)

// GenerateDealerContribution creates one Feldman VSS contribution.
func GenerateDealerContribution(
	dealerIndex, trusteeCount, quorum int,
	random io.Reader,
) (DealerContribution, error) {
	if trusteeCount < MinTrustees || trusteeCount > MaxTrustees {
		return DealerContribution{}, &Error{Code: "invalid_trustee_count"}
	}
	if quorum < MinTrustees || quorum > trusteeCount {
		return DealerContribution{}, &Error{Code: "invalid_quorum"}
	}
	if dealerIndex < 1 || dealerIndex > trusteeCount {
		return DealerContribution{}, &Error{Code: "invalid_trustee_index"}
	}

	coefficients := make([]*ristretto255.Scalar, quorum)
	commitments := make([]Point, quorum)
	for index := range coefficients {
		coefficient, err := randomScalar(random)
		if err != nil {
			return DealerContribution{}, err
		}
		coefficients[index] = coefficient
		commitments[index] = pointBytes(ristretto255.NewIdentityElement().ScalarBaseMult(coefficient))
	}

	shares := make([]Scalar, trusteeCount)
	for recipient := 1; recipient <= trusteeCount; recipient++ {
		shares[recipient-1] = scalarBytes(evaluatePolynomial(coefficients, scalarFromIndex(uint16(recipient))))
	}
	return DealerContribution{
		DealerIndex: uint16(dealerIndex),
		Commitments: commitments,
		shares:      shares,
	}, nil
}

// ShareFor returns only the share intended for one recipient.
func (contribution DealerContribution) ShareFor(recipientIndex int) (DealerShare, error) {
	if recipientIndex < 1 || recipientIndex > len(contribution.shares) {
		return DealerShare{}, &Error{Code: "invalid_trustee_index"}
	}
	return DealerShare{
		DealerIndex:    contribution.DealerIndex,
		RecipientIndex: uint16(recipientIndex),
		Value:          contribution.shares[recipientIndex-1],
	}, nil
}

// Public returns the contribution with all recipient secrets removed.
func (contribution DealerContribution) Public() PublicContribution {
	return PublicContribution{
		DealerIndex: contribution.DealerIndex,
		Commitments: append([]Point(nil), contribution.Commitments...),
	}
}

// VerifyDealerShare checks a recipient share against its coefficient commitments.
func VerifyDealerShare(contribution PublicContribution, trusteeCount int, share DealerShare) error {
	recipientIndex := int(share.RecipientIndex)
	if share.DealerIndex != contribution.DealerIndex || recipientIndex < 1 || recipientIndex > trusteeCount {
		return &Error{Code: "invalid_trustee_index"}
	}
	if len(contribution.Commitments) < MinTrustees || len(contribution.Commitments) > trusteeCount {
		return &Error{Code: "invalid_ceremony_contribution"}
	}
	shareScalar, err := decodeScalar(share.Value)
	if err != nil {
		return &Error{Code: "invalid_ceremony_share", Err: err}
	}
	commitments, err := decodeCommitments(contribution.Commitments)
	if err != nil {
		return err
	}
	left := ristretto255.NewIdentityElement().ScalarBaseMult(shareScalar)
	right := evaluateCommitments(commitments, scalarFromIndex(uint16(recipientIndex)))
	if left.Equal(right) != 1 {
		return &Error{Code: "invalid_ceremony_share"}
	}
	return nil
}

func finalizeCeremony(contributions []DealerContribution) (Ceremony, []TrusteeSecretShare, error) {
	public := make([]PublicContribution, len(contributions))
	for index, contribution := range contributions {
		public[index] = contribution.Public()
	}
	ceremony, err := FinalizePublicCeremony(public)
	if err != nil {
		return Ceremony{}, nil, err
	}
	secretShares := make([]TrusteeSecretShare, len(contributions))
	for recipient := 1; recipient <= len(contributions); recipient++ {
		shares := make([]DealerShare, len(contributions))
		for dealer, contribution := range contributions {
			shares[dealer], err = contribution.ShareFor(recipient)
			if err != nil {
				return Ceremony{}, nil, err
			}
		}
		secretShares[recipient-1], err = FinalizeTrusteeShare(public, shares, recipient)
		if err != nil {
			return Ceremony{}, nil, err
		}
	}
	return ceremony, secretShares, nil
}

// FinalizePublicCeremony derives the election key and trustee public keys.
func FinalizePublicCeremony(contributions []PublicContribution) (Ceremony, error) {
	trusteeCount := len(contributions)
	if trusteeCount < MinTrustees || trusteeCount > MaxTrustees {
		return Ceremony{}, &Error{Code: "invalid_trustee_count"}
	}
	quorum := len(contributions[0].Commitments)
	if quorum < MinTrustees || quorum > trusteeCount {
		return Ceremony{}, &Error{Code: "invalid_quorum"}
	}

	ordered := make([]PublicContribution, trusteeCount)
	for _, contribution := range contributions {
		index := int(contribution.DealerIndex)
		if index < 1 || index > trusteeCount || ordered[index-1].DealerIndex != 0 {
			return Ceremony{}, &Error{Code: "invalid_dealer_set"}
		}
		if len(contribution.Commitments) != quorum {
			return Ceremony{}, &Error{Code: "invalid_ceremony_contribution"}
		}
		ordered[index-1] = contribution
	}

	decodedCommitments := make([][]*ristretto255.Element, trusteeCount)
	for dealer, contribution := range ordered {
		var err error
		decodedCommitments[dealer], err = decodeCommitments(contribution.Commitments)
		if err != nil {
			return Ceremony{}, err
		}
	}

	electionKey := ristretto255.NewIdentityElement()
	for _, commitments := range decodedCommitments {
		electionKey.Add(electionKey, commitments[0])
	}
	if electionKey.Equal(ristretto255.NewIdentityElement()) == 1 {
		return Ceremony{}, &Error{Code: "invalid_election_key"}
	}

	publicKeys := make([]Point, trusteeCount)
	for recipient := 1; recipient <= trusteeCount; recipient++ {
		public := ristretto255.NewIdentityElement()
		x := scalarFromIndex(uint16(recipient))
		for dealer := range ordered {
			public.Add(public, evaluateCommitments(decodedCommitments[dealer], x))
		}
		if public.Equal(ristretto255.NewIdentityElement()) == 1 {
			return Ceremony{}, &Error{Code: "invalid_trustee_public_key"}
		}
		publicKeys[recipient-1] = pointBytes(public)
	}

	return Ceremony{
		TrusteeCount:      trusteeCount,
		Quorum:            quorum,
		ElectionKey:       pointBytes(electionKey),
		TrusteePublicKeys: publicKeys,
	}, nil
}

// FinalizeTrusteeShare verifies one recipient's dealer shares and sums them.
func FinalizeTrusteeShare(
	contributions []PublicContribution,
	shares []DealerShare,
	recipientIndex int,
) (TrusteeSecretShare, error) {
	ceremony, err := FinalizePublicCeremony(contributions)
	if err != nil {
		return TrusteeSecretShare{}, err
	}
	if recipientIndex < 1 || recipientIndex > ceremony.TrusteeCount || len(shares) != ceremony.TrusteeCount {
		return TrusteeSecretShare{}, &Error{Code: "invalid_trustee_index"}
	}
	byDealer := make(map[uint16]DealerShare, len(shares))
	for _, share := range shares {
		if int(share.RecipientIndex) != recipientIndex {
			return TrusteeSecretShare{}, &Error{Code: "wrong_share_recipient"}
		}
		if _, exists := byDealer[share.DealerIndex]; exists {
			return TrusteeSecretShare{}, &Error{Code: "duplicate_dealer_share"}
		}
		byDealer[share.DealerIndex] = share
	}
	secret := ristretto255.NewScalar()
	for _, contribution := range contributions {
		share, exists := byDealer[contribution.DealerIndex]
		if !exists {
			return TrusteeSecretShare{}, &Error{Code: "missing_dealer_share"}
		}
		if err := VerifyDealerShare(contribution, ceremony.TrusteeCount, share); err != nil {
			return TrusteeSecretShare{}, err
		}
		value, _ := decodeScalar(share.Value)
		secret.Add(secret, value)
	}
	publicKey, _ := decodePublicPoint(ceremony.TrusteePublicKeys[recipientIndex-1])
	if ristretto255.NewIdentityElement().ScalarBaseMult(secret).Equal(publicKey) != 1 {
		return TrusteeSecretShare{}, &Error{Code: "ceremony_invariant_failed"}
	}
	return TrusteeSecretShare{TrusteeIndex: uint16(recipientIndex), Value: scalarBytes(secret)}, nil
}

func decodeCommitments(encoded []Point) ([]*ristretto255.Element, error) {
	commitments := make([]*ristretto255.Element, len(encoded))
	for index, value := range encoded {
		point, err := decodePublicPoint(value)
		if err != nil {
			return nil, &Error{Code: "invalid_ceremony_commitment", Err: fmt.Errorf("index %d: %w", index, err)}
		}
		commitments[index] = point
	}
	return commitments, nil
}

func evaluatePolynomial(coefficients []*ristretto255.Scalar, x *ristretto255.Scalar) *ristretto255.Scalar {
	result := ristretto255.NewScalar()
	for index := len(coefficients) - 1; index >= 0; index-- {
		result.Multiply(result, x)
		result.Add(result, coefficients[index])
	}
	return result
}

func evaluateCommitments(commitments []*ristretto255.Element, x *ristretto255.Scalar) *ristretto255.Element {
	result := ristretto255.NewIdentityElement()
	power := scalarFromIndex(1)
	for _, commitment := range commitments {
		term := ristretto255.NewIdentityElement().ScalarMult(power, commitment)
		result.Add(result, term)
		power.Multiply(power, x)
	}
	return result
}
