package manifest

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/cirocosta/vota/internal/crypto/lrs"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/gtank/ristretto255"
)

const enrollmentProofPrefix = "vota-enrollment-proof-v1"

// CreateEnrollment proves possession of one poll-specific eligibility key.
func CreateEnrollment(draftID string, privateKey lrs.PrivateKey, random io.Reader) (protocol.Enrollment, error) {
	draftHash, err := decodePrefixed("sha256", draftID, 32)
	if err != nil {
		return protocol.Enrollment{}, &Error{Code: "invalid_draft_id", Err: err}
	}
	secret, err := ristretto255.NewScalar().SetCanonicalBytes(privateKey[:])
	if err != nil || secret.Equal(ristretto255.NewScalar()) == 1 {
		return protocol.Enrollment{}, &Error{Code: "invalid_eligibility_private_key", Err: err}
	}
	publicKey, err := lrs.Public(privateKey)
	if err != nil {
		return protocol.Enrollment{}, &Error{Code: "invalid_eligibility_private_key", Err: err}
	}
	nonce, err := enrollmentRandomScalar(random)
	if err != nil {
		return protocol.Enrollment{}, err
	}
	commitment := ristretto255.NewIdentityElement().ScalarBaseMult(nonce)
	challenge := enrollmentChallenge(draftHash, publicKey[:], commitment.Bytes())
	response := ristretto255.NewScalar().Add(nonce, ristretto255.NewScalar().Multiply(challenge, secret))
	proof := make([]byte, 64)
	copy(proof[:32], commitment.Bytes())
	copy(proof[32:], response.Bytes())
	return protocol.Enrollment{
		SchemaVersion:  protocol.SchemaVersion,
		Protocol:       protocol.ProtocolVersion,
		PollDraftID:    draftID,
		EligibilityKey: "ristretto255:" + hex.EncodeToString(publicKey[:]),
		Proof:          enrollmentProofPrefix + ":" + hex.EncodeToString(proof),
	}, nil
}

// VerifyEnrollment checks a draft-bound Schnorr proof of key possession.
func VerifyEnrollment(enrollment protocol.Enrollment) error {
	if enrollment.SchemaVersion != protocol.SchemaVersion {
		return &Error{Code: "unsupported_schema_version"}
	}
	if enrollment.Protocol != protocol.ProtocolVersion {
		return &Error{Code: "unsupported_protocol"}
	}
	draftHash, err := decodePrefixed("sha256", enrollment.PollDraftID, 32)
	if err != nil {
		return &Error{Code: "invalid_draft_id", Err: err}
	}
	publicBytes, err := decodePrefixed("ristretto255", enrollment.EligibilityKey, 32)
	if err != nil {
		return &Error{Code: "invalid_eligibility_key", Err: err}
	}
	publicKey, err := ristretto255.NewIdentityElement().SetCanonicalBytes(publicBytes)
	if err != nil || publicKey.Equal(ristretto255.NewIdentityElement()) == 1 {
		return &Error{Code: "invalid_eligibility_key", Err: err}
	}
	proof, err := decodePrefixed(enrollmentProofPrefix, enrollment.Proof, 64)
	if err != nil {
		return &Error{Code: "invalid_enrollment_proof", Err: err}
	}
	commitment, err := ristretto255.NewIdentityElement().SetCanonicalBytes(proof[:32])
	if err != nil {
		return &Error{Code: "invalid_enrollment_proof", Err: err}
	}
	response, err := ristretto255.NewScalar().SetCanonicalBytes(proof[32:])
	if err != nil {
		return &Error{Code: "invalid_enrollment_proof", Err: err}
	}
	challenge := enrollmentChallenge(draftHash, publicBytes, proof[:32])
	left := ristretto255.NewIdentityElement().ScalarBaseMult(response)
	right := ristretto255.NewIdentityElement().Add(
		commitment,
		ristretto255.NewIdentityElement().ScalarMult(challenge, publicKey),
	)
	if left.Equal(right) != 1 {
		return &Error{Code: "invalid_enrollment_proof"}
	}
	return nil
}

func enrollmentRandomScalar(random io.Reader) (*ristretto255.Scalar, error) {
	if random == nil {
		random = rand.Reader
	}
	for range 128 {
		uniform := make([]byte, 64)
		if _, err := io.ReadFull(random, uniform); err != nil {
			return nil, &Error{Code: "random_failed", Err: err}
		}
		scalar, err := ristretto255.NewScalar().SetUniformBytes(uniform)
		if err != nil {
			return nil, &Error{Code: "random_failed", Err: err}
		}
		if scalar.Equal(ristretto255.NewScalar()) != 1 {
			return scalar, nil
		}
	}
	return nil, &Error{Code: "random_failed", Err: fmt.Errorf("generated zero scalar repeatedly")}
}

func enrollmentChallenge(draftID, publicKey, commitment []byte) *ristretto255.Scalar {
	hash := sha512.New()
	_, _ = hash.Write([]byte(protocol.DomainEnrollmentProof))
	_, _ = hash.Write([]byte{0})
	for _, field := range [][]byte{draftID, publicKey, commitment} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(field)
	}
	challenge, err := ristretto255.NewScalar().SetUniformBytes(hash.Sum(nil))
	if err != nil {
		panic(fmt.Sprintf("set enrollment challenge: %v", err))
	}
	return challenge
}
