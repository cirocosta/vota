// Package lrs implements Vota's experimental poll-local LSAG proof.
package lrs

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/cirocosta/vota/internal/protocol"
	"github.com/gtank/ristretto255"
)

const (
	ScalarSize    = 32
	PublicKeySize = 32
	MessageSize   = 32
	PollIDSize    = 32
	MinRingSize   = 2
	MaxRingSize   = 256
	signatureHead = 1 + PublicKeySize + ScalarSize + 2
)

type PrivateKey [ScalarSize]byte
type PublicKey [PublicKeySize]byte

type Signature struct {
	KeyImage  PublicKey
	C0        [ScalarSize]byte
	Responses [][ScalarSize]byte
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
	for err != nil {
		if typed, ok := err.(*Error); ok {
			return typed.Code
		}
		type unwrapper interface{ Unwrap() error }
		wrapped, ok := err.(unwrapper)
		if !ok {
			break
		}
		err = wrapped.Unwrap()
	}
	return "internal_error"
}

// GenerateKey creates a canonical nonzero Ristretto255 scalar and public key.
func GenerateKey(random io.Reader) (PrivateKey, PublicKey, error) {
	if random == nil {
		random = rand.Reader
	}
	secret, err := randomNonzeroScalar(random)
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}
	privateKey := scalarBytes(secret)
	publicKey := elementBytes(ristretto255.NewIdentityElement().ScalarBaseMult(secret))
	return PrivateKey(privateKey), PublicKey(publicKey), nil
}

// Public derives the public key for a private scalar.
func Public(privateKey PrivateKey) (PublicKey, error) {
	secret, err := decodeNonzeroScalar(privateKey[:])
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey(elementBytes(ristretto255.NewIdentityElement().ScalarBaseMult(secret))), nil
}

// Sign creates a poll-local linkable proof over the complete canonical ring.
func Sign(
	pollID [PollIDSize]byte,
	message [MessageSize]byte,
	ring []PublicKey,
	privateKey PrivateKey,
	signerIndex int,
	random io.Reader,
) (Signature, error) {
	points, err := validateRing(ring)
	if err != nil {
		return Signature{}, err
	}
	if signerIndex < 0 || signerIndex >= len(ring) {
		return Signature{}, &Error{Code: "invalid_signer_index"}
	}
	secret, err := decodeNonzeroScalar(privateKey[:])
	if err != nil {
		return Signature{}, err
	}
	public := ristretto255.NewIdentityElement().ScalarBaseMult(secret)
	if public.Equal(points[signerIndex]) != 1 {
		return Signature{}, &Error{Code: "private_key_not_in_ring"}
	}
	if random == nil {
		random = rand.Reader
	}

	ringHash := hashRing(pollID, ring)
	hashPoints := make([]*ristretto255.Element, len(ring))
	for index, key := range ring {
		hashPoints[index] = hashToGroup(key)
	}
	keyImagePoint := ristretto255.NewIdentityElement().ScalarMult(secret, hashPoints[signerIndex])
	keyImage := PublicKey(elementBytes(keyImagePoint))

	responses := make([][ScalarSize]byte, len(ring))
	responseScalars := make([]*ristretto255.Scalar, len(ring))
	for index := range ring {
		if index == signerIndex {
			continue
		}
		responseScalars[index], err = randomNonzeroScalar(random)
		if err != nil {
			return Signature{}, err
		}
		responses[index] = scalarBytes(responseScalars[index])
	}
	alpha, err := randomNonzeroScalar(random)
	if err != nil {
		return Signature{}, err
	}

	challenges := make([]*ristretto255.Scalar, len(ring))
	left := ristretto255.NewIdentityElement().ScalarBaseMult(alpha)
	right := ristretto255.NewIdentityElement().ScalarMult(alpha, hashPoints[signerIndex])
	next := (signerIndex + 1) % len(ring)
	challenges[next] = hashChallenge(pollID, message, ringHash, keyImage, signerIndex, left, right)

	for index := next; index != signerIndex; index = (index + 1) % len(ring) {
		left = ristretto255.NewIdentityElement().Add(
			ristretto255.NewIdentityElement().ScalarBaseMult(responseScalars[index]),
			ristretto255.NewIdentityElement().ScalarMult(challenges[index], points[index]),
		)
		right = ristretto255.NewIdentityElement().Add(
			ristretto255.NewIdentityElement().ScalarMult(responseScalars[index], hashPoints[index]),
			ristretto255.NewIdentityElement().ScalarMult(challenges[index], keyImagePoint),
		)
		following := (index + 1) % len(ring)
		challenges[following] = hashChallenge(pollID, message, ringHash, keyImage, index, left, right)
	}

	product := ristretto255.NewScalar().Multiply(challenges[signerIndex], secret)
	signerResponse := ristretto255.NewScalar().Subtract(alpha, product)
	responses[signerIndex] = scalarBytes(signerResponse)

	return Signature{
		KeyImage:  keyImage,
		C0:        scalarBytes(challenges[0]),
		Responses: responses,
	}, nil
}

// Verify checks a signature against the exact canonical ring and poll.
func Verify(
	pollID [PollIDSize]byte,
	message [MessageSize]byte,
	ring []PublicKey,
	signature Signature,
) error {
	points, err := validateRing(ring)
	if err != nil {
		return err
	}
	if len(signature.Responses) != len(ring) {
		return &Error{Code: "invalid_signature_size"}
	}
	keyImage, err := decodeNonidentityElement(signature.KeyImage[:])
	if err != nil {
		return &Error{Code: "invalid_key_image", Err: err}
	}
	challenge, err := decodeScalar(signature.C0[:])
	if err != nil {
		return &Error{Code: "invalid_challenge", Err: err}
	}
	initialChallenge := challenge
	ringHash := hashRing(pollID, ring)

	for index, key := range ring {
		response, err := decodeScalar(signature.Responses[index][:])
		if err != nil {
			return &Error{Code: "invalid_response", Err: err}
		}
		hashPoint := hashToGroup(key)
		left := ristretto255.NewIdentityElement().Add(
			ristretto255.NewIdentityElement().ScalarBaseMult(response),
			ristretto255.NewIdentityElement().ScalarMult(challenge, points[index]),
		)
		right := ristretto255.NewIdentityElement().Add(
			ristretto255.NewIdentityElement().ScalarMult(response, hashPoint),
			ristretto255.NewIdentityElement().ScalarMult(challenge, keyImage),
		)
		challenge = hashChallenge(pollID, message, ringHash, signature.KeyImage, index, left, right)
	}

	if challenge.Equal(initialChallenge) != 1 {
		return &Error{Code: "invalid_signature"}
	}
	return nil
}

// Link reports whether two signatures were made by the same poll key.
func Link(first, second Signature) bool {
	return subtle.ConstantTimeCompare(first.KeyImage[:], second.KeyImage[:]) == 1
}

// MarshalBinary encodes a signature without its externally committed ring.
func (signature Signature) MarshalBinary() ([]byte, error) {
	if len(signature.Responses) < MinRingSize || len(signature.Responses) > MaxRingSize {
		return nil, &Error{Code: "invalid_signature_size"}
	}
	encoded := make([]byte, signatureHead+len(signature.Responses)*ScalarSize)
	encoded[0] = 1
	copy(encoded[1:1+PublicKeySize], signature.KeyImage[:])
	copy(encoded[1+PublicKeySize:1+PublicKeySize+ScalarSize], signature.C0[:])
	binary.BigEndian.PutUint16(encoded[1+PublicKeySize+ScalarSize:signatureHead], uint16(len(signature.Responses)))
	offset := signatureHead
	for _, response := range signature.Responses {
		copy(encoded[offset:offset+ScalarSize], response[:])
		offset += ScalarSize
	}
	return encoded, nil
}

// ParseSignature decodes and validates canonical signature encodings.
func ParseSignature(encoded []byte) (Signature, error) {
	if len(encoded) < signatureHead || encoded[0] != 1 {
		return Signature{}, &Error{Code: "invalid_signature_encoding"}
	}
	ringSize := int(binary.BigEndian.Uint16(encoded[1+PublicKeySize+ScalarSize : signatureHead]))
	if ringSize < MinRingSize || ringSize > MaxRingSize || len(encoded) != signatureHead+ringSize*ScalarSize {
		return Signature{}, &Error{Code: "invalid_signature_size"}
	}
	var signature Signature
	copy(signature.KeyImage[:], encoded[1:1+PublicKeySize])
	copy(signature.C0[:], encoded[1+PublicKeySize:1+PublicKeySize+ScalarSize])
	signature.Responses = make([][ScalarSize]byte, ringSize)
	offset := signatureHead
	for index := range signature.Responses {
		copy(signature.Responses[index][:], encoded[offset:offset+ScalarSize])
		offset += ScalarSize
	}
	if _, err := decodeNonidentityElement(signature.KeyImage[:]); err != nil {
		return Signature{}, &Error{Code: "invalid_key_image", Err: err}
	}
	if _, err := decodeScalar(signature.C0[:]); err != nil {
		return Signature{}, &Error{Code: "invalid_challenge", Err: err}
	}
	for _, response := range signature.Responses {
		if _, err := decodeScalar(response[:]); err != nil {
			return Signature{}, &Error{Code: "invalid_response", Err: err}
		}
	}
	return signature, nil
}

func validateRing(ring []PublicKey) ([]*ristretto255.Element, error) {
	if len(ring) < MinRingSize || len(ring) > MaxRingSize {
		return nil, &Error{Code: "invalid_ring_size"}
	}
	points := make([]*ristretto255.Element, len(ring))
	seen := make(map[PublicKey]struct{}, len(ring))
	for index, key := range ring {
		if _, exists := seen[key]; exists {
			return nil, &Error{Code: "duplicate_ring_key"}
		}
		seen[key] = struct{}{}
		point, err := decodeNonidentityElement(key[:])
		if err != nil {
			return nil, &Error{Code: "invalid_ring_key", Err: fmt.Errorf("index %d: %w", index, err)}
		}
		points[index] = point
	}
	return points, nil
}

func hashRing(pollID [PollIDSize]byte, ring []PublicKey) [64]byte {
	hash := sha512.New()
	_, _ = hash.Write([]byte(protocol.DomainRingHash))
	_, _ = hash.Write([]byte{0})
	writeTranscriptField(hash, pollID[:])
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(ring)))
	writeTranscriptField(hash, count[:])
	for _, key := range ring {
		writeTranscriptField(hash, key[:])
	}
	var output [64]byte
	copy(output[:], hash.Sum(nil))
	return output
}

func hashToGroup(key PublicKey) *ristretto255.Element {
	digest := transcriptHash(protocol.DomainRingHashToGroup, key[:])
	element, err := ristretto255.NewIdentityElement().SetUniformBytes(digest[:])
	if err != nil {
		panic(fmt.Sprintf("set 64-byte uniform element: %v", err))
	}
	return element
}

func hashChallenge(
	pollID [PollIDSize]byte,
	message [MessageSize]byte,
	ringHash [64]byte,
	keyImage PublicKey,
	index int,
	left, right *ristretto255.Element,
) *ristretto255.Scalar {
	var indexBytes [8]byte
	binary.BigEndian.PutUint64(indexBytes[:], uint64(index))
	leftBytes := left.Bytes()
	rightBytes := right.Bytes()
	digest := transcriptHash(
		protocol.DomainRingChallenge,
		pollID[:],
		ringHash[:],
		message[:],
		keyImage[:],
		indexBytes[:],
		leftBytes,
		rightBytes,
	)
	scalar, err := ristretto255.NewScalar().SetUniformBytes(digest[:])
	if err != nil {
		panic(fmt.Sprintf("set 64-byte uniform scalar: %v", err))
	}
	return scalar
}

func transcriptHash(domain string, fields ...[]byte) [64]byte {
	hash := sha512.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0})
	for _, field := range fields {
		writeTranscriptField(hash, field)
	}
	var output [64]byte
	copy(output[:], hash.Sum(nil))
	return output
}

func writeTranscriptField(writer io.Writer, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

func randomNonzeroScalar(random io.Reader) (*ristretto255.Scalar, error) {
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

func decodeScalar(encoded []byte) (*ristretto255.Scalar, error) {
	if len(encoded) != ScalarSize {
		return nil, fmt.Errorf("expected %d scalar bytes", ScalarSize)
	}
	scalar := ristretto255.NewScalar()
	if _, err := scalar.SetCanonicalBytes(encoded); err != nil {
		return nil, fmt.Errorf("decode scalar: %w", err)
	}
	return scalar, nil
}

func decodeNonzeroScalar(encoded []byte) (*ristretto255.Scalar, error) {
	scalar, err := decodeScalar(encoded)
	if err != nil {
		return nil, &Error{Code: "invalid_private_key", Err: err}
	}
	if scalar.Equal(ristretto255.NewScalar()) == 1 {
		return nil, &Error{Code: "invalid_private_key", Err: fmt.Errorf("zero scalar")}
	}
	return scalar, nil
}

func decodeNonidentityElement(encoded []byte) (*ristretto255.Element, error) {
	if len(encoded) != PublicKeySize {
		return nil, fmt.Errorf("expected %d element bytes", PublicKeySize)
	}
	element := ristretto255.NewIdentityElement()
	if _, err := element.SetCanonicalBytes(encoded); err != nil {
		return nil, fmt.Errorf("decode element: %w", err)
	}
	if element.Equal(ristretto255.NewIdentityElement()) == 1 {
		return nil, fmt.Errorf("identity element")
	}
	return element, nil
}

func scalarBytes(scalar *ristretto255.Scalar) [ScalarSize]byte {
	var output [ScalarSize]byte
	copy(output[:], scalar.Bytes())
	return output
}

func elementBytes(element *ristretto255.Element) [PublicKeySize]byte {
	var output [PublicKeySize]byte
	copy(output[:], element.Bytes())
	return output
}
