package election

import (
	"fmt"
	"io"

	"github.com/cirocosta/vota/internal/protocol"
	"github.com/gtank/ristretto255"
)

// EncryptChoice encrypts a one-hot ballot and proves its validity.
func EncryptChoice(
	binding Binding,
	electionKey Point,
	choiceCount, selected int,
	random io.Reader,
) (EncryptedBallot, error) {
	if choiceCount < MinChoices || choiceCount > MaxChoices {
		return EncryptedBallot{}, &Error{Code: "invalid_choice_count"}
	}
	if selected < 0 || selected >= choiceCount {
		return EncryptedBallot{}, &Error{Code: "invalid_choice"}
	}
	publicKey, err := decodePublicPoint(electionKey)
	if err != nil {
		return EncryptedBallot{}, &Error{Code: "invalid_election_key", Err: err}
	}

	ballot := EncryptedBallot{
		Ciphertexts: make([]Ciphertext, choiceCount),
		Proof: ValidityProof{
			Bits: make([]BitProof, choiceCount),
		},
	}
	randomness := make([]*ristretto255.Scalar, choiceCount)
	for index := range choiceCount {
		value := 0
		if index == selected {
			value = 1
		}
		randomness[index], err = randomScalar(random)
		if err != nil {
			return EncryptedBallot{}, err
		}
		ciphertext := encryptBit(publicKey, randomness[index], value)
		proof, err := proveBit(binding, electionKey, ciphertext, index, value, randomness[index], random)
		if err != nil {
			return EncryptedBallot{}, err
		}
		ballot.Ciphertexts[index] = ciphertext
		ballot.Proof.Bits[index] = proof
	}

	sumCiphertext, err := sumCiphertexts(ballot.Ciphertexts)
	if err != nil {
		return EncryptedBallot{}, err
	}
	sumRandomness := ristretto255.NewScalar()
	for _, value := range randomness {
		sumRandomness.Add(sumRandomness, value)
	}
	sumA, _ := decodePoint(sumCiphertext.A)
	sumB, _ := decodePoint(sumCiphertext.B)
	message := subtractPoints(sumB, ristretto255.NewGeneratorElement())
	ballot.Proof.Sum, err = proveEquality(
		protocol.DomainChoiceSumProof,
		sumProofFields(binding, electionKey, sumCiphertext),
		ristretto255.NewGeneratorElement(), publicKey,
		sumA, message, sumRandomness, random,
	)
	if err != nil {
		return EncryptedBallot{}, err
	}
	return ballot, nil
}

// VerifyBallot checks all bit proofs and the exactly-one sum proof.
func VerifyBallot(binding Binding, electionKey Point, ballot EncryptedBallot) error {
	if len(ballot.Ciphertexts) < MinChoices || len(ballot.Ciphertexts) > MaxChoices {
		return &Error{Code: "invalid_choice_count"}
	}
	if len(ballot.Proof.Bits) != len(ballot.Ciphertexts) {
		return &Error{Code: "invalid_validity_proof_size"}
	}
	publicKey, err := decodePublicPoint(electionKey)
	if err != nil {
		return &Error{Code: "invalid_election_key", Err: err}
	}
	for index, ciphertext := range ballot.Ciphertexts {
		if err := verifyBit(binding, electionKey, ciphertext, index, ballot.Proof.Bits[index]); err != nil {
			return err
		}
	}
	sum, err := sumCiphertexts(ballot.Ciphertexts)
	if err != nil {
		return err
	}
	sumA, _ := decodePoint(sum.A)
	sumB, _ := decodePoint(sum.B)
	message := subtractPoints(sumB, ristretto255.NewGeneratorElement())
	if err := verifyEquality(
		protocol.DomainChoiceSumProof,
		sumProofFields(binding, electionKey, sum),
		ristretto255.NewGeneratorElement(), publicKey,
		sumA, message, ballot.Proof.Sum,
	); err != nil {
		return &Error{Code: "invalid_choice_sum_proof", Err: err}
	}
	return nil
}

func encryptBit(publicKey *ristretto255.Element, randomness *ristretto255.Scalar, value int) Ciphertext {
	a := ristretto255.NewIdentityElement().ScalarBaseMult(randomness)
	b := ristretto255.NewIdentityElement().ScalarMult(randomness, publicKey)
	if value == 1 {
		b.Add(b, ristretto255.NewGeneratorElement())
	}
	return Ciphertext{A: pointBytes(a), B: pointBytes(b)}
}

func proveBit(
	binding Binding,
	electionKey Point,
	ciphertext Ciphertext,
	choiceIndex, value int,
	witness *ristretto255.Scalar,
	random io.Reader,
) (BitProof, error) {
	a, err := decodePublicPoint(ciphertext.A)
	if err != nil {
		return BitProof{}, &Error{Code: "invalid_ciphertext", Err: err}
	}
	b, err := decodePoint(ciphertext.B)
	if err != nil {
		return BitProof{}, &Error{Code: "invalid_ciphertext", Err: err}
	}
	publicKey, _ := decodePublicPoint(electionKey)
	statements := [2]*ristretto255.Element{
		b,
		subtractPoints(b, ristretto255.NewGeneratorElement()),
	}
	real := value
	fake := 1 - value
	fakeChallenge, err := randomScalar(random)
	if err != nil {
		return BitProof{}, err
	}
	fakeResponse, err := randomScalar(random)
	if err != nil {
		return BitProof{}, err
	}
	nonce, err := randomScalar(random)
	if err != nil {
		return BitProof{}, err
	}

	var commitments [2][2]*ristretto255.Element
	commitments[real][0] = ristretto255.NewIdentityElement().ScalarBaseMult(nonce)
	commitments[real][1] = ristretto255.NewIdentityElement().ScalarMult(nonce, publicKey)
	commitments[fake][0] = subtractPoints(
		ristretto255.NewIdentityElement().ScalarBaseMult(fakeResponse),
		ristretto255.NewIdentityElement().ScalarMult(fakeChallenge, a),
	)
	commitments[fake][1] = subtractPoints(
		ristretto255.NewIdentityElement().ScalarMult(fakeResponse, publicKey),
		ristretto255.NewIdentityElement().ScalarMult(fakeChallenge, statements[fake]),
	)
	overall := bitChallenge(binding, electionKey, ciphertext, choiceIndex, commitments)
	realChallenge := ristretto255.NewScalar().Subtract(overall, fakeChallenge)
	realResponse := ristretto255.NewScalar().Add(
		nonce,
		ristretto255.NewScalar().Multiply(realChallenge, witness),
	)

	var proof BitProof
	proof.Challenges[real] = scalarBytes(realChallenge)
	proof.Challenges[fake] = scalarBytes(fakeChallenge)
	proof.Responses[real] = scalarBytes(realResponse)
	proof.Responses[fake] = scalarBytes(fakeResponse)
	return proof, nil
}

func verifyBit(binding Binding, electionKey Point, ciphertext Ciphertext, choiceIndex int, proof BitProof) error {
	a, err := decodePublicPoint(ciphertext.A)
	if err != nil {
		return &Error{Code: "invalid_ciphertext", Err: err}
	}
	b, err := decodePoint(ciphertext.B)
	if err != nil {
		return &Error{Code: "invalid_ciphertext", Err: err}
	}
	publicKey, _ := decodePublicPoint(electionKey)
	statements := [2]*ristretto255.Element{
		b,
		subtractPoints(b, ristretto255.NewGeneratorElement()),
	}
	var challenges [2]*ristretto255.Scalar
	var responses [2]*ristretto255.Scalar
	var commitments [2][2]*ristretto255.Element
	for branch := range 2 {
		challenges[branch], err = decodeScalar(proof.Challenges[branch])
		if err != nil {
			return &Error{Code: "invalid_choice_proof", Err: err}
		}
		responses[branch], err = decodeScalar(proof.Responses[branch])
		if err != nil {
			return &Error{Code: "invalid_choice_proof", Err: err}
		}
		commitments[branch][0] = subtractPoints(
			ristretto255.NewIdentityElement().ScalarBaseMult(responses[branch]),
			ristretto255.NewIdentityElement().ScalarMult(challenges[branch], a),
		)
		commitments[branch][1] = subtractPoints(
			ristretto255.NewIdentityElement().ScalarMult(responses[branch], publicKey),
			ristretto255.NewIdentityElement().ScalarMult(challenges[branch], statements[branch]),
		)
	}
	expected := bitChallenge(binding, electionKey, ciphertext, choiceIndex, commitments)
	actual := ristretto255.NewScalar().Add(challenges[0], challenges[1])
	if expected.Equal(actual) != 1 {
		return &Error{Code: "invalid_choice_proof", Err: fmt.Errorf("challenge mismatch")}
	}
	return nil
}

func bitChallenge(
	binding Binding,
	electionKey Point,
	ciphertext Ciphertext,
	choiceIndex int,
	commitments [2][2]*ristretto255.Element,
) *ristretto255.Scalar {
	fields := [][]byte{
		binding.PollID[:], binding.ManifestHash[:], indexBytes(choiceIndex),
		electionKey[:], ciphertext.A[:], ciphertext.B[:],
	}
	for branch := range 2 {
		for side := range 2 {
			fields = append(fields, commitments[branch][side].Bytes())
		}
	}
	return hashScalar(protocol.DomainChoiceProof, fields...)
}

func proveEquality(
	domain string,
	fields [][]byte,
	baseOne, baseTwo, statementOne, statementTwo *ristretto255.Element,
	witness *ristretto255.Scalar,
	random io.Reader,
) (EqualityProof, error) {
	nonce, err := randomScalar(random)
	if err != nil {
		return EqualityProof{}, err
	}
	commitmentOne := ristretto255.NewIdentityElement().ScalarMult(nonce, baseOne)
	commitmentTwo := ristretto255.NewIdentityElement().ScalarMult(nonce, baseTwo)
	challenge := equalityChallenge(domain, fields, baseOne, baseTwo, statementOne, statementTwo, commitmentOne, commitmentTwo)
	response := ristretto255.NewScalar().Add(nonce, ristretto255.NewScalar().Multiply(challenge, witness))
	return EqualityProof{Challenge: scalarBytes(challenge), Response: scalarBytes(response)}, nil
}

func verifyEquality(
	domain string,
	fields [][]byte,
	baseOne, baseTwo, statementOne, statementTwo *ristretto255.Element,
	proof EqualityProof,
) error {
	challenge, err := decodeScalar(proof.Challenge)
	if err != nil {
		return err
	}
	response, err := decodeScalar(proof.Response)
	if err != nil {
		return err
	}
	commitmentOne := subtractPoints(
		ristretto255.NewIdentityElement().ScalarMult(response, baseOne),
		ristretto255.NewIdentityElement().ScalarMult(challenge, statementOne),
	)
	commitmentTwo := subtractPoints(
		ristretto255.NewIdentityElement().ScalarMult(response, baseTwo),
		ristretto255.NewIdentityElement().ScalarMult(challenge, statementTwo),
	)
	expected := equalityChallenge(domain, fields, baseOne, baseTwo, statementOne, statementTwo, commitmentOne, commitmentTwo)
	if expected.Equal(challenge) != 1 {
		return fmt.Errorf("challenge mismatch")
	}
	return nil
}

func equalityChallenge(
	domain string,
	fields [][]byte,
	baseOne, baseTwo, statementOne, statementTwo, commitmentOne, commitmentTwo *ristretto255.Element,
) *ristretto255.Scalar {
	transcript := append([][]byte(nil), fields...)
	transcript = append(transcript,
		baseOne.Bytes(), baseTwo.Bytes(), statementOne.Bytes(), statementTwo.Bytes(),
		commitmentOne.Bytes(), commitmentTwo.Bytes(),
	)
	return hashScalar(domain, transcript...)
}

func sumProofFields(binding Binding, electionKey Point, sum Ciphertext) [][]byte {
	return [][]byte{binding.PollID[:], binding.ManifestHash[:], electionKey[:], sum.A[:], sum.B[:]}
}

func sumCiphertexts(ciphertexts []Ciphertext) (Ciphertext, error) {
	if len(ciphertexts) == 0 {
		return Ciphertext{}, &Error{Code: "invalid_ciphertext_count"}
	}
	a := ristretto255.NewIdentityElement()
	b := ristretto255.NewIdentityElement()
	for index, ciphertext := range ciphertexts {
		pointA, err := decodePoint(ciphertext.A)
		if err != nil {
			return Ciphertext{}, &Error{Code: "invalid_ciphertext", Err: fmt.Errorf("index %d A: %w", index, err)}
		}
		if pointA.Equal(ristretto255.NewIdentityElement()) == 1 {
			return Ciphertext{}, &Error{Code: "invalid_ciphertext", Err: fmt.Errorf("index %d A: identity", index)}
		}
		pointB, err := decodePoint(ciphertext.B)
		if err != nil {
			return Ciphertext{}, &Error{Code: "invalid_ciphertext", Err: fmt.Errorf("index %d B: %w", index, err)}
		}
		a.Add(a, pointA)
		b.Add(b, pointB)
	}
	return Ciphertext{A: pointBytes(a), B: pointBytes(b)}, nil
}
