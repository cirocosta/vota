package election

import (
	"encoding/binary"
	"fmt"
)

const (
	ciphertextSize      = PointSize * 2
	bitProofSize        = ScalarSize * 4
	equalityProofSize   = ScalarSize * 2
	ballotHeaderSize    = 2
	aggregateHeaderSize = 4
	shareHeaderSize     = 1 + 2 + 32 + 1
)

func (ciphertext Ciphertext) MarshalBinary() ([]byte, error) {
	if _, err := decodePoint(ciphertext.A); err != nil {
		return nil, &Error{Code: "invalid_ciphertext", Err: err}
	}
	if _, err := decodePoint(ciphertext.B); err != nil {
		return nil, &Error{Code: "invalid_ciphertext", Err: err}
	}
	encoded := make([]byte, ciphertextSize)
	copy(encoded[:PointSize], ciphertext.A[:])
	copy(encoded[PointSize:], ciphertext.B[:])
	return encoded, nil
}

func ParseCiphertext(encoded []byte) (Ciphertext, error) {
	if len(encoded) != ciphertextSize {
		return Ciphertext{}, &Error{Code: "invalid_ciphertext_encoding"}
	}
	var ciphertext Ciphertext
	copy(ciphertext.A[:], encoded[:PointSize])
	copy(ciphertext.B[:], encoded[PointSize:])
	if _, err := ciphertext.MarshalBinary(); err != nil {
		return Ciphertext{}, err
	}
	return ciphertext, nil
}

func (ballot EncryptedBallot) MarshalBinary() ([]byte, error) {
	choiceCount := len(ballot.Ciphertexts)
	if choiceCount < MinChoices || choiceCount > MaxChoices || len(ballot.Proof.Bits) != choiceCount {
		return nil, &Error{Code: "invalid_validity_proof_size"}
	}
	encoded := make([]byte, ballotHeaderSize+choiceCount*(ciphertextSize+bitProofSize)+equalityProofSize)
	encoded[0] = 1
	encoded[1] = byte(choiceCount)
	offset := ballotHeaderSize
	for _, ciphertext := range ballot.Ciphertexts {
		value, err := ciphertext.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(encoded[offset:offset+ciphertextSize], value)
		offset += ciphertextSize
	}
	for _, proof := range ballot.Proof.Bits {
		for branch := range 2 {
			if _, err := decodeScalar(proof.Challenges[branch]); err != nil {
				return nil, &Error{Code: "invalid_choice_proof", Err: err}
			}
			copy(encoded[offset:offset+ScalarSize], proof.Challenges[branch][:])
			offset += ScalarSize
		}
		for branch := range 2 {
			if _, err := decodeScalar(proof.Responses[branch]); err != nil {
				return nil, &Error{Code: "invalid_choice_proof", Err: err}
			}
			copy(encoded[offset:offset+ScalarSize], proof.Responses[branch][:])
			offset += ScalarSize
		}
	}
	for _, scalar := range []Scalar{ballot.Proof.Sum.Challenge, ballot.Proof.Sum.Response} {
		if _, err := decodeScalar(scalar); err != nil {
			return nil, &Error{Code: "invalid_choice_sum_proof", Err: err}
		}
		copy(encoded[offset:offset+ScalarSize], scalar[:])
		offset += ScalarSize
	}
	return encoded, nil
}

func ParseBallot(encoded []byte) (EncryptedBallot, error) {
	if len(encoded) < ballotHeaderSize || encoded[0] != 1 {
		return EncryptedBallot{}, &Error{Code: "invalid_ballot_encoding"}
	}
	choiceCount := int(encoded[1])
	expected := ballotHeaderSize + choiceCount*(ciphertextSize+bitProofSize) + equalityProofSize
	if choiceCount < MinChoices || choiceCount > MaxChoices || len(encoded) != expected {
		return EncryptedBallot{}, &Error{Code: "invalid_ballot_encoding"}
	}
	ballot := EncryptedBallot{
		Ciphertexts: make([]Ciphertext, choiceCount),
		Proof:       ValidityProof{Bits: make([]BitProof, choiceCount)},
	}
	offset := ballotHeaderSize
	for index := range choiceCount {
		ciphertext, err := ParseCiphertext(encoded[offset : offset+ciphertextSize])
		if err != nil {
			return EncryptedBallot{}, err
		}
		ballot.Ciphertexts[index] = ciphertext
		offset += ciphertextSize
	}
	for index := range choiceCount {
		for branch := range 2 {
			copy(ballot.Proof.Bits[index].Challenges[branch][:], encoded[offset:offset+ScalarSize])
			offset += ScalarSize
		}
		for branch := range 2 {
			copy(ballot.Proof.Bits[index].Responses[branch][:], encoded[offset:offset+ScalarSize])
			offset += ScalarSize
		}
	}
	copy(ballot.Proof.Sum.Challenge[:], encoded[offset:offset+ScalarSize])
	offset += ScalarSize
	copy(ballot.Proof.Sum.Response[:], encoded[offset:offset+ScalarSize])
	if _, err := ballot.MarshalBinary(); err != nil {
		return EncryptedBallot{}, err
	}
	return ballot, nil
}

func (contribution DealerContribution) MarshalPublicCommitment() ([]byte, error) {
	return contribution.Public().MarshalBinary()
}

func (contribution PublicContribution) MarshalBinary() ([]byte, error) {
	if contribution.DealerIndex < 1 || len(contribution.Commitments) < MinTrustees || len(contribution.Commitments) > MaxCeremonyQuorum {
		return nil, &Error{Code: "invalid_ceremony_contribution"}
	}
	encoded := make([]byte, 1+2+1+len(contribution.Commitments)*PointSize)
	encoded[0] = 1
	binary.BigEndian.PutUint16(encoded[1:3], contribution.DealerIndex)
	encoded[3] = byte(len(contribution.Commitments))
	offset := 4
	for _, commitment := range contribution.Commitments {
		if _, err := decodePublicPoint(commitment); err != nil {
			return nil, &Error{Code: "invalid_ceremony_commitment", Err: err}
		}
		copy(encoded[offset:offset+PointSize], commitment[:])
		offset += PointSize
	}
	return encoded, nil
}

func ParsePublicContribution(encoded []byte) (PublicContribution, error) {
	if len(encoded) < 4 || encoded[0] != 1 {
		return PublicContribution{}, &Error{Code: "invalid_ceremony_commitment"}
	}
	count := int(encoded[3])
	if count < MinTrustees || count > MaxCeremonyQuorum || len(encoded) != 4+count*PointSize {
		return PublicContribution{}, &Error{Code: "invalid_ceremony_commitment"}
	}
	contribution := PublicContribution{
		DealerIndex: binary.BigEndian.Uint16(encoded[1:3]),
		Commitments: make([]Point, count),
	}
	offset := 4
	for index := range count {
		copy(contribution.Commitments[index][:], encoded[offset:offset+PointSize])
		if _, err := decodePublicPoint(contribution.Commitments[index]); err != nil {
			return PublicContribution{}, &Error{Code: "invalid_ceremony_commitment", Err: err}
		}
		offset += PointSize
	}
	return contribution, nil
}

func (share DealerShare) MarshalBinary() ([]byte, error) {
	if share.DealerIndex < 1 || share.RecipientIndex < 1 {
		return nil, &Error{Code: "invalid_ceremony_share"}
	}
	if _, err := decodeScalar(share.Value); err != nil {
		return nil, &Error{Code: "invalid_ceremony_share", Err: err}
	}
	encoded := make([]byte, 1+2+2+ScalarSize)
	encoded[0] = 1
	binary.BigEndian.PutUint16(encoded[1:3], share.DealerIndex)
	binary.BigEndian.PutUint16(encoded[3:5], share.RecipientIndex)
	copy(encoded[5:], share.Value[:])
	return encoded, nil
}

func ParseDealerShare(encoded []byte) (DealerShare, error) {
	if len(encoded) != 1+2+2+ScalarSize || encoded[0] != 1 {
		return DealerShare{}, &Error{Code: "invalid_ceremony_share"}
	}
	share := DealerShare{
		DealerIndex:    binary.BigEndian.Uint16(encoded[1:3]),
		RecipientIndex: binary.BigEndian.Uint16(encoded[3:5]),
	}
	copy(share.Value[:], encoded[5:])
	if _, err := share.MarshalBinary(); err != nil {
		return DealerShare{}, err
	}
	return share, nil
}

func (aggregate Aggregate) MarshalBinary() ([]byte, error) {
	if err := validateAggregate(aggregate); err != nil {
		return nil, err
	}
	encoded := make([]byte, aggregateHeaderSize+len(aggregate.Ciphertexts)*ciphertextSize)
	encoded[0] = 1
	binary.BigEndian.PutUint16(encoded[1:3], uint16(aggregate.BallotCount))
	encoded[3] = byte(len(aggregate.Ciphertexts))
	offset := aggregateHeaderSize
	for _, ciphertext := range aggregate.Ciphertexts {
		value, err := ciphertext.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(encoded[offset:offset+ciphertextSize], value)
		offset += ciphertextSize
	}
	return encoded, nil
}

func ParseAggregate(encoded []byte) (Aggregate, error) {
	if len(encoded) < aggregateHeaderSize || encoded[0] != 1 {
		return Aggregate{}, &Error{Code: "invalid_aggregate_encoding"}
	}
	choiceCount := int(encoded[3])
	if len(encoded) != aggregateHeaderSize+choiceCount*ciphertextSize {
		return Aggregate{}, &Error{Code: "invalid_aggregate_encoding"}
	}
	aggregate := Aggregate{
		BallotCount: int(binary.BigEndian.Uint16(encoded[1:3])),
		Ciphertexts: make([]Ciphertext, choiceCount),
	}
	offset := aggregateHeaderSize
	for index := range choiceCount {
		ciphertext, err := ParseCiphertext(encoded[offset : offset+ciphertextSize])
		if err != nil {
			return Aggregate{}, err
		}
		aggregate.Ciphertexts[index] = ciphertext
		offset += ciphertextSize
	}
	if err := validateAggregate(aggregate); err != nil {
		return Aggregate{}, err
	}
	return aggregate, nil
}

func (share DecryptionShare) MarshalBinary() ([]byte, error) {
	if share.TrusteeIndex < 1 || len(share.Values) < MinChoices || len(share.Values) > MaxChoices || len(share.Proofs) != len(share.Values) {
		return nil, &Error{Code: "invalid_decryption_share_size"}
	}
	encoded := make([]byte, shareHeaderSize+len(share.Values)*(PointSize+equalityProofSize))
	encoded[0] = 1
	binary.BigEndian.PutUint16(encoded[1:3], share.TrusteeIndex)
	copy(encoded[3:35], share.AggregateHash[:])
	encoded[35] = byte(len(share.Values))
	offset := shareHeaderSize
	for index, value := range share.Values {
		if _, err := decodePoint(value); err != nil {
			return nil, &Error{Code: "invalid_decryption_share", Err: fmt.Errorf("choice %d: %w", index, err)}
		}
		copy(encoded[offset:offset+PointSize], value[:])
		offset += PointSize
		for _, scalar := range []Scalar{share.Proofs[index].Challenge, share.Proofs[index].Response} {
			if _, err := decodeScalar(scalar); err != nil {
				return nil, &Error{Code: "invalid_decryption_share_proof", Err: err}
			}
			copy(encoded[offset:offset+ScalarSize], scalar[:])
			offset += ScalarSize
		}
	}
	return encoded, nil
}

func ParseDecryptionShare(encoded []byte) (DecryptionShare, error) {
	if len(encoded) < shareHeaderSize || encoded[0] != 1 {
		return DecryptionShare{}, &Error{Code: "invalid_decryption_share_encoding"}
	}
	choiceCount := int(encoded[35])
	if len(encoded) != shareHeaderSize+choiceCount*(PointSize+equalityProofSize) {
		return DecryptionShare{}, &Error{Code: "invalid_decryption_share_encoding"}
	}
	share := DecryptionShare{
		TrusteeIndex: binary.BigEndian.Uint16(encoded[1:3]),
		Values:       make([]Point, choiceCount),
		Proofs:       make([]EqualityProof, choiceCount),
	}
	copy(share.AggregateHash[:], encoded[3:35])
	offset := shareHeaderSize
	for index := range choiceCount {
		copy(share.Values[index][:], encoded[offset:offset+PointSize])
		offset += PointSize
		copy(share.Proofs[index].Challenge[:], encoded[offset:offset+ScalarSize])
		offset += ScalarSize
		copy(share.Proofs[index].Response[:], encoded[offset:offset+ScalarSize])
		offset += ScalarSize
	}
	if _, err := share.MarshalBinary(); err != nil {
		return DecryptionShare{}, err
	}
	return share, nil
}

func (evidence TallyEvidence) MarshalBinary() ([]byte, error) {
	if evidence.BallotCount < 1 || evidence.BallotCount > MaxBallots || len(evidence.Totals) < MinChoices || len(evidence.Totals) > MaxChoices {
		return nil, &Error{Code: "invalid_tally_evidence"}
	}
	if len(evidence.TrusteeIndices) < MinTrustees || len(evidence.TrusteeIndices) > MaxTrustees {
		return nil, &Error{Code: "invalid_tally_evidence"}
	}
	sum := 0
	for _, total := range evidence.Totals {
		if total < 0 || total > evidence.BallotCount {
			return nil, &Error{Code: "invalid_tally_evidence"}
		}
		sum += total
	}
	if sum != evidence.BallotCount {
		return nil, &Error{Code: "tally_invariant_failed"}
	}
	for index, trusteeIndex := range evidence.TrusteeIndices {
		if trusteeIndex < 1 || int(trusteeIndex) > MaxTrustees || (index > 0 && trusteeIndex <= evidence.TrusteeIndices[index-1]) {
			return nil, &Error{Code: "invalid_tally_evidence"}
		}
	}
	encoded := make([]byte, 1+32+2+1+len(evidence.Totals)*2+1+len(evidence.TrusteeIndices)*2)
	encoded[0] = 1
	copy(encoded[1:33], evidence.AggregateHash[:])
	binary.BigEndian.PutUint16(encoded[33:35], uint16(evidence.BallotCount))
	encoded[35] = byte(len(evidence.Totals))
	offset := 36
	for _, total := range evidence.Totals {
		binary.BigEndian.PutUint16(encoded[offset:offset+2], uint16(total))
		offset += 2
	}
	encoded[offset] = byte(len(evidence.TrusteeIndices))
	offset++
	for _, index := range evidence.TrusteeIndices {
		binary.BigEndian.PutUint16(encoded[offset:offset+2], index)
		offset += 2
	}
	return encoded, nil
}

func ParseTallyEvidence(encoded []byte) (TallyEvidence, error) {
	if len(encoded) < 37 || encoded[0] != 1 {
		return TallyEvidence{}, &Error{Code: "invalid_tally_evidence"}
	}
	choiceCount := int(encoded[35])
	trusteeCountOffset := 36 + choiceCount*2
	if trusteeCountOffset >= len(encoded) {
		return TallyEvidence{}, &Error{Code: "invalid_tally_evidence"}
	}
	trusteeCount := int(encoded[trusteeCountOffset])
	if len(encoded) != trusteeCountOffset+1+trusteeCount*2 {
		return TallyEvidence{}, &Error{Code: "invalid_tally_evidence"}
	}
	evidence := TallyEvidence{
		BallotCount:    int(binary.BigEndian.Uint16(encoded[33:35])),
		Totals:         make([]int, choiceCount),
		TrusteeIndices: make([]uint16, trusteeCount),
	}
	copy(evidence.AggregateHash[:], encoded[1:33])
	offset := 36
	for index := range choiceCount {
		evidence.Totals[index] = int(binary.BigEndian.Uint16(encoded[offset : offset+2]))
		offset += 2
	}
	offset++
	for index := range trusteeCount {
		evidence.TrusteeIndices[index] = binary.BigEndian.Uint16(encoded[offset : offset+2])
		offset += 2
	}
	if _, err := evidence.MarshalBinary(); err != nil {
		return TallyEvidence{}, err
	}
	return evidence, nil
}
