// Package app orchestrates Vota protocol operations independently of transports.
package app

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/cirocosta/vota/internal/crypto/adapter"
	"github.com/cirocosta/vota/internal/crypto/election"
	"github.com/cirocosta/vota/internal/crypto/lrs"
	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
)

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

// ManifestHash commits to the complete signed canonical manifest.
func ManifestHash(value protocol.Manifest) (string, error) {
	if err := manifest.Verify(value); err != nil {
		return "", &Error{Code: "invalid_manifest", Err: err}
	}
	hash, err := protocol.HashCanonical(protocol.DomainManifestHash, value)
	if err != nil {
		return "", &Error{Code: "manifest_hash_failed", Err: err}
	}
	return hash, nil
}

// CastBallot encrypts a choice and proves eligibility against one manifest.
func CastBallot(
	value protocol.Manifest,
	privateKey lrs.PrivateKey,
	signerIndex int,
	selectedChoice int,
	random io.Reader,
) (protocol.BallotEnvelope, error) {
	if err := manifest.Verify(value); err != nil {
		return protocol.BallotEnvelope{}, &Error{Code: "invalid_manifest", Err: err}
	}
	manifestHash, err := ManifestHash(value)
	if err != nil {
		return protocol.BallotEnvelope{}, err
	}
	binding, electionKey, ring, err := artifactContext(value, manifestHash)
	if err != nil {
		return protocol.BallotEnvelope{}, err
	}
	encrypted, err := election.EncryptChoice(binding, electionKey, len(value.Choices), selectedChoice, random)
	if err != nil {
		return protocol.BallotEnvelope{}, &Error{Code: "ballot_encryption_failed", Err: err}
	}
	ciphertexts := make([]string, len(encrypted.Ciphertexts))
	for index, ciphertext := range encrypted.Ciphertexts {
		encoded, err := ciphertext.MarshalBinary()
		if err != nil {
			return protocol.BallotEnvelope{}, &Error{Code: "ballot_encode_failed", Err: err}
		}
		ciphertexts[index] = "vota-elgamal-v1:" + hex.EncodeToString(encoded)
	}
	proof, err := encrypted.Proof.MarshalBinary()
	if err != nil {
		return protocol.BallotEnvelope{}, &Error{Code: "ballot_encode_failed", Err: err}
	}
	ballot := protocol.BallotEnvelope{
		SchemaVersion:     protocol.SchemaVersion,
		Protocol:          protocol.ProtocolVersion,
		PollID:            value.PollID,
		ManifestHash:      manifestHash,
		EligibilityScheme: value.EligibilityScheme,
		Ciphertexts:       ciphertexts,
		ValidityProof:     "vota-choice-proof-v1:" + hex.EncodeToString(proof),
	}
	ballot.BallotHash, err = HashBallot(ballot)
	if err != nil {
		return protocol.BallotEnvelope{}, err
	}
	ballotHash, _ := decodeHash(ballot.BallotHash)
	var message [32]byte
	copy(message[:], ballotHash)
	prover, err := adapter.NewRingV1Prover(binding.PollID, ring, privateKey[:], signerIndex)
	if err != nil {
		return protocol.BallotEnvelope{}, &Error{Code: adapter.ErrorCode(err), Err: err}
	}
	artifact, err := prover.Prove(message, random)
	if err != nil {
		return protocol.BallotEnvelope{}, &Error{Code: adapter.ErrorCode(err), Err: err}
	}
	ballot.Nullifier = "ristretto255:" + hex.EncodeToString(artifact.Nullifier[:])
	ballot.EligibilityProof = "vota-lsag-v1:" + hex.EncodeToString(artifact.Proof)
	return ballot, nil
}

// VerifyBallot validates all public ballot commitments and proofs.
func VerifyBallot(value protocol.Manifest, ballot protocol.BallotEnvelope) error {
	if err := manifest.Verify(value); err != nil {
		return &Error{Code: "invalid_manifest", Err: err}
	}
	if err := protocol.ValidateBallotShape(value, ballot); err != nil {
		return &Error{Code: protocol.ErrorCode(err), Err: err}
	}
	manifestHash, err := ManifestHash(value)
	if err != nil {
		return err
	}
	if ballot.ManifestHash != manifestHash {
		return &Error{Code: "wrong_manifest"}
	}
	expectedHash, err := HashBallot(ballot)
	if err != nil {
		return err
	}
	if ballot.BallotHash != expectedHash {
		return &Error{Code: "ballot_hash_mismatch"}
	}
	binding, electionKey, ring, err := artifactContext(value, manifestHash)
	if err != nil {
		return err
	}
	encrypted := election.EncryptedBallot{Ciphertexts: make([]election.Ciphertext, len(ballot.Ciphertexts))}
	for index, encoded := range ballot.Ciphertexts {
		payload, err := decodeOpaque("vota-elgamal-v1", encoded)
		if err != nil {
			return &Error{Code: "invalid_ciphertext", Err: err}
		}
		encrypted.Ciphertexts[index], err = election.ParseCiphertext(payload)
		if err != nil {
			return &Error{Code: "invalid_ciphertext", Err: err}
		}
	}
	proofBytes, err := decodeOpaque("vota-choice-proof-v1", ballot.ValidityProof)
	if err != nil {
		return &Error{Code: "invalid_validity_proof", Err: err}
	}
	encrypted.Proof, err = election.ParseValidityProof(proofBytes, len(ballot.Ciphertexts))
	if err != nil {
		return &Error{Code: "invalid_validity_proof", Err: err}
	}
	if err := election.VerifyBallot(binding, electionKey, encrypted); err != nil {
		return &Error{Code: "invalid_validity_proof", Err: err}
	}
	nullifier, err := decodeFixed("ristretto255", ballot.Nullifier, 32)
	if err != nil {
		return &Error{Code: "invalid_nullifier", Err: err}
	}
	proof, err := decodeOpaque("vota-lsag-v1", ballot.EligibilityProof)
	if err != nil {
		return &Error{Code: "invalid_eligibility_proof", Err: err}
	}
	var artifact adapter.Artifact
	artifact.Scheme = ballot.EligibilityScheme
	copy(artifact.Nullifier[:], nullifier)
	artifact.Proof = proof
	verifier, err := adapter.NewVerifier(ballot.EligibilityScheme, binding.PollID, ring)
	if err != nil {
		return &Error{Code: adapter.ErrorCode(err), Err: err}
	}
	ballotHash, _ := decodeHash(ballot.BallotHash)
	var message [32]byte
	copy(message[:], ballotHash)
	if err := verifier.Verify(message, artifact); err != nil {
		return &Error{Code: adapter.ErrorCode(err), Err: err}
	}
	return nil
}

// HashBallot returns the hash signed by the eligibility proof.
func HashBallot(ballot protocol.BallotEnvelope) (string, error) {
	unsigned := ballot
	unsigned.Nullifier = ""
	unsigned.EligibilityProof = ""
	unsigned.BallotHash = ""
	hash, err := protocol.HashCanonical(protocol.DomainBallotHash, unsigned)
	if err != nil {
		return "", &Error{Code: "ballot_hash_failed", Err: err}
	}
	return hash, nil
}

func MarshalBallot(ballot protocol.BallotEnvelope) ([]byte, error) {
	encoded, err := protocol.MarshalCanonical(ballot)
	if err != nil {
		return nil, &Error{Code: "ballot_encode_failed", Err: err}
	}
	return encoded, nil
}

func ParseBallot(encoded []byte) (protocol.BallotEnvelope, error) {
	var ballot protocol.BallotEnvelope
	if err := protocol.DecodeStrict(encoded, &ballot); err != nil {
		return protocol.BallotEnvelope{}, &Error{Code: "invalid_ballot", Err: err}
	}
	return ballot, nil
}

func artifactContext(value protocol.Manifest, manifestHash string) (election.Binding, election.Point, [][]byte, error) {
	pollID, err := decodeHash(value.PollID)
	if err != nil {
		return election.Binding{}, election.Point{}, nil, &Error{Code: "invalid_poll_id", Err: err}
	}
	manifestHashBytes, err := decodeHash(manifestHash)
	if err != nil {
		return election.Binding{}, election.Point{}, nil, &Error{Code: "invalid_manifest_hash", Err: err}
	}
	var binding election.Binding
	copy(binding.PollID[:], pollID)
	copy(binding.ManifestHash[:], manifestHashBytes)
	electionKeyBytes, err := decodeFixed("ristretto255", value.Trustees.ElectionPublicKey, election.PointSize)
	if err != nil {
		return election.Binding{}, election.Point{}, nil, &Error{Code: "invalid_election_key", Err: err}
	}
	var electionKey election.Point
	copy(electionKey[:], electionKeyBytes)
	ring := make([][]byte, len(value.EligibleKeys))
	for index, encoded := range value.EligibleKeys {
		ring[index], err = decodeFixed("ristretto255", encoded, lrs.PublicKeySize)
		if err != nil {
			return election.Binding{}, election.Point{}, nil, &Error{Code: "invalid_eligibility_set", Err: err}
		}
	}
	return binding, electionKey, ring, nil
}

func decodeHash(value string) ([]byte, error) {
	decoded, err := decodeFixed("sha256", value, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid sha256 value")
	}
	return decoded, nil
}

func decodeFixed(prefix, value string, size int) ([]byte, error) {
	return protocol.DecodeFixedHex(prefix, value, size)
}

func decodeOpaque(prefix, value string) ([]byte, error) {
	return protocol.DecodeOpaqueHex(prefix, value)
}
