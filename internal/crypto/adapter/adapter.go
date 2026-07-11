// Package adapter hides eligibility-scheme details from application services.
package adapter

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"github.com/cirocosta/vota/internal/crypto/lrs"
	"github.com/cirocosta/vota/internal/protocol"
)

type Artifact struct {
	Scheme    string
	Nullifier [lrs.PublicKeySize]byte
	Proof     []byte
}

type Prover interface {
	Prove(message [lrs.MessageSize]byte, random io.Reader) (Artifact, error)
}

type Verifier interface {
	Verify(message [lrs.MessageSize]byte, artifact Artifact) error
}

type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return e.Code
	}
	return fmt.Sprintf("%s: %v", e.Code, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

func ErrorCode(err error) string {
	var target *Error
	if errors.As(err, &target) {
		return target.Code
	}
	return "internal_error"
}

type ringProver struct {
	pollID      [lrs.PollIDSize]byte
	ring        []lrs.PublicKey
	privateKey  lrs.PrivateKey
	signerIndex int
}

type ringVerifier struct {
	pollID [lrs.PollIDSize]byte
	ring   []lrs.PublicKey
}

// NewRingV1Prover creates a poll-bound prover without exposing its credential.
func NewRingV1Prover(
	pollID [lrs.PollIDSize]byte,
	encodedRing [][]byte,
	privateKey []byte,
	signerIndex int,
) (Prover, error) {
	ring, err := parseRing(encodedRing)
	if err != nil {
		return nil, err
	}
	if len(privateKey) != lrs.ScalarSize {
		return nil, &Error{Code: "invalid_eligibility_credential"}
	}
	var secret lrs.PrivateKey
	copy(secret[:], privateKey)
	public, err := lrs.Public(secret)
	if err != nil {
		return nil, &Error{Code: "invalid_eligibility_credential", Err: err}
	}
	if signerIndex < 0 || signerIndex >= len(ring) || subtle.ConstantTimeCompare(public[:], ring[signerIndex][:]) != 1 {
		return nil, &Error{Code: "credential_not_eligible"}
	}
	return &ringProver{pollID: pollID, ring: ring, privateKey: secret, signerIndex: signerIndex}, nil
}

// NewVerifier selects an eligibility verifier by its public scheme identifier.
func NewVerifier(scheme string, pollID [lrs.PollIDSize]byte, encodedMembers [][]byte) (Verifier, error) {
	if scheme != protocol.EligibilityScheme {
		return nil, &Error{Code: "unsupported_eligibility_scheme"}
	}
	ring, err := parseRing(encodedMembers)
	if err != nil {
		return nil, err
	}
	return &ringVerifier{pollID: pollID, ring: ring}, nil
}

func (prover *ringProver) Prove(message [lrs.MessageSize]byte, random io.Reader) (Artifact, error) {
	signature, err := lrs.Sign(prover.pollID, message, prover.ring, prover.privateKey, prover.signerIndex, random)
	if err != nil {
		return Artifact{}, &Error{Code: "eligibility_proof_failed", Err: err}
	}
	proof, err := signature.MarshalBinary()
	if err != nil {
		return Artifact{}, &Error{Code: "eligibility_proof_failed", Err: err}
	}
	return Artifact{
		Scheme:    protocol.EligibilityScheme,
		Nullifier: signature.KeyImage,
		Proof:     proof,
	}, nil
}

func (verifier *ringVerifier) Verify(message [lrs.MessageSize]byte, artifact Artifact) error {
	if artifact.Scheme != protocol.EligibilityScheme {
		return &Error{Code: "unsupported_eligibility_scheme"}
	}
	signature, err := lrs.ParseSignature(artifact.Proof)
	if err != nil {
		return &Error{Code: "invalid_eligibility_proof", Err: err}
	}
	if subtle.ConstantTimeCompare(artifact.Nullifier[:], signature.KeyImage[:]) != 1 {
		return &Error{Code: "nullifier_mismatch"}
	}
	if err := lrs.Verify(verifier.pollID, message, verifier.ring, signature); err != nil {
		return &Error{Code: "invalid_eligibility_proof", Err: err}
	}
	return nil
}

func parseRing(encoded [][]byte) ([]lrs.PublicKey, error) {
	if len(encoded) < lrs.MinRingSize || len(encoded) > lrs.MaxRingSize {
		return nil, &Error{Code: "invalid_eligibility_set"}
	}
	ring := make([]lrs.PublicKey, len(encoded))
	for index, member := range encoded {
		if len(member) != lrs.PublicKeySize {
			return nil, &Error{Code: "invalid_eligibility_set", Err: fmt.Errorf("member %d", index)}
		}
		copy(ring[index][:], member)
	}
	return ring, nil
}
