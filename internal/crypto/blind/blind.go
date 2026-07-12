// Package blind implements the randomized RSABSSA variant from RFC 9474.
package blind

import (
	"bytes"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
)

const (
	SerialSize        = 32
	MessagePrefixSize = 32
	SaltSize          = 48
	MinRSAKeyBits     = 2048
	credentialDomain  = "vota:credential:v1"
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

// State contains the client-only material needed to finalize an issuance.
// Persist it until a receipt has been written durably.
type State struct {
	PollID         string `json:"poll_id"`
	IssuerKeyID    string `json:"issuer_key_id"`
	Serial         []byte `json:"serial"`
	MessagePrefix  []byte `json:"message_prefix"`
	Inverse        []byte `json:"inverse"`
	EncodedMessage []byte `json:"encoded_message"`
}

// Request is a blind credential request and its local recovery state.
type Request struct {
	BlindedMessage []byte `json:"blinded_message"`
	State          State  `json:"state"`
}

// Credential is a poll-bound bearer credential. Signature contains the
// randomized message prefix followed by a fixed-width RSA-PSS signature.
type Credential struct {
	IssuerKeyID string `json:"issuer_key_id"`
	Serial      []byte `json:"serial"`
	Signature   []byte `json:"signature"`
}

// Prepare creates a randomized and blinded request using a caller-provided
// credential serial. Randomness supplies the RFC 9474 message prefix, PSS salt,
// and RSA blinding factor.
func Prepare(publicKey *rsa.PublicKey, pollID, issuerKeyID string, serial []byte, random io.Reader) (Request, error) {
	if err := validatePublicKey(publicKey); err != nil {
		return Request{}, err
	}
	if issuerKeyID != KeyID(publicKey) {
		return Request{}, &Error{Code: "wrong_issuer_key"}
	}
	message, err := credentialMessage(pollID, issuerKeyID, serial)
	if err != nil {
		return Request{}, err
	}
	if random == nil {
		random = cryptorand.Reader
	}
	prefix := make([]byte, MessagePrefixSize)
	if _, err := io.ReadFull(random, prefix); err != nil {
		return Request{}, &Error{Code: "random_failed", Err: err}
	}
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(random, salt); err != nil {
		return Request{}, &Error{Code: "random_failed", Err: err}
	}
	prepared := append(append([]byte(nil), prefix...), message...)
	encoded, err := encodePSS(prepared, publicKey.N.BitLen()-1, salt)
	if err != nil {
		return Request{}, err
	}
	blinded, inverse, err := blindEncoded(publicKey, encoded, random)
	if err != nil {
		return Request{}, err
	}
	return Request{
		BlindedMessage: blinded,
		State: State{
			PollID:         pollID,
			IssuerKeyID:    issuerKeyID,
			Serial:         append([]byte(nil), serial...),
			MessagePrefix:  prefix,
			Inverse:        inverse,
			EncodedMessage: encoded,
		},
	}, nil
}

// BlindSign performs the server operation. The extra RSA blinding step keeps
// the private exponentiation independent of attacker-controlled input.
func BlindSign(privateKey *rsa.PrivateKey, blindedMessage []byte, random io.Reader) ([]byte, error) {
	if privateKey == nil || privateKey.N == nil || privateKey.N.BitLen() < MinRSAKeyBits || privateKey.E < 3 || privateKey.D == nil {
		return nil, &Error{Code: "invalid_issuer_private_key"}
	}
	if err := privateKey.Validate(); err != nil {
		return nil, &Error{Code: "invalid_issuer_private_key", Err: err}
	}
	size := privateKey.Size()
	if len(blindedMessage) != size {
		return nil, &Error{Code: "invalid_blinded_message"}
	}
	ciphertext := new(big.Int).SetBytes(blindedMessage)
	if ciphertext.Sign() <= 0 || ciphertext.Cmp(privateKey.N) >= 0 {
		return nil, &Error{Code: "invalid_blinded_message"}
	}
	if random == nil {
		random = cryptorand.Reader
	}
	factor, inverse, err := randomInvertible(privateKey.N, random)
	if err != nil {
		return nil, err
	}
	e := big.NewInt(int64(privateKey.E))
	blinder := new(big.Int).Exp(factor, e, privateKey.N)
	blinded := new(big.Int).Mul(ciphertext, blinder)
	blinded.Mod(blinded, privateKey.N)
	signed := new(big.Int).Exp(blinded, privateKey.D, privateKey.N)
	signed.Mul(signed, inverse)
	signed.Mod(signed, privateKey.N)
	check := new(big.Int).Exp(signed, e, privateKey.N)
	if check.Cmp(ciphertext) != 0 {
		return nil, &Error{Code: "blind_sign_failed"}
	}
	return leftPad(signed.Bytes(), size), nil
}

// Finalize unblinds and verifies a server response before returning a bearer
// credential.
func Finalize(publicKey *rsa.PublicKey, state State, blindSignature []byte) (Credential, error) {
	if err := validatePublicKey(publicKey); err != nil {
		return Credential{}, err
	}
	if state.IssuerKeyID != KeyID(publicKey) {
		return Credential{}, &Error{Code: "wrong_issuer_key"}
	}
	message, err := credentialMessage(state.PollID, state.IssuerKeyID, state.Serial)
	if err != nil {
		return Credential{}, err
	}
	size := publicKey.Size()
	if len(state.MessagePrefix) != MessagePrefixSize || len(state.Inverse) != size || len(state.EncodedMessage) != size || len(blindSignature) != size {
		return Credential{}, &Error{Code: "invalid_blind_state"}
	}
	inverse := new(big.Int).SetBytes(state.Inverse)
	if inverse.Sign() <= 0 || inverse.Cmp(publicKey.N) >= 0 {
		return Credential{}, &Error{Code: "invalid_blind_state"}
	}
	signed := new(big.Int).SetBytes(blindSignature)
	signed.Mul(signed, inverse)
	signed.Mod(signed, publicKey.N)
	signature := leftPad(signed.Bytes(), size)
	e := big.NewInt(int64(publicKey.E))
	encoded := new(big.Int).Exp(signed, e, publicKey.N)
	if subtle.ConstantTimeCompare(leftPad(encoded.Bytes(), size), state.EncodedMessage) != 1 {
		return Credential{}, &Error{Code: "invalid_blind_signature"}
	}
	prepared := append(append([]byte(nil), state.MessagePrefix...), message...)
	digest := sha512.Sum384(prepared)
	if err := rsa.VerifyPSS(publicKey, crypto.SHA384, digest[:], signature, &rsa.PSSOptions{SaltLength: SaltSize, Hash: crypto.SHA384}); err != nil {
		return Credential{}, &Error{Code: "invalid_blind_signature", Err: err}
	}
	combined := append(append([]byte(nil), state.MessagePrefix...), signature...)
	return Credential{IssuerKeyID: state.IssuerKeyID, Serial: append([]byte(nil), state.Serial...), Signature: combined}, nil
}

// Verify checks a finalized credential against one poll and issuer.
func Verify(publicKey *rsa.PublicKey, pollID string, credential Credential) error {
	if err := validatePublicKey(publicKey); err != nil {
		return err
	}
	if credential.IssuerKeyID != KeyID(publicKey) {
		return &Error{Code: "wrong_issuer_key"}
	}
	message, err := credentialMessage(pollID, credential.IssuerKeyID, credential.Serial)
	if err != nil {
		return err
	}
	size := publicKey.Size()
	if len(credential.Signature) != MessagePrefixSize+size {
		return &Error{Code: "invalid_credential"}
	}
	prefix := credential.Signature[:MessagePrefixSize]
	signature := credential.Signature[MessagePrefixSize:]
	prepared := append(append([]byte(nil), prefix...), message...)
	digest := sha512.Sum384(prepared)
	if err := rsa.VerifyPSS(publicKey, crypto.SHA384, digest[:], signature, &rsa.PSSOptions{SaltLength: SaltSize, Hash: crypto.SHA384}); err != nil {
		return &Error{Code: "invalid_credential", Err: err}
	}
	return nil
}

func credentialMessage(pollID, issuerKeyID string, serial []byte) ([]byte, error) {
	if pollID == "" || len(pollID) > 512 {
		return nil, &Error{Code: "invalid_poll_id"}
	}
	if issuerKeyID == "" || len(issuerKeyID) > 128 {
		return nil, &Error{Code: "invalid_issuer_key_id"}
	}
	if len(serial) != SerialSize {
		return nil, &Error{Code: "invalid_credential_serial"}
	}
	var output bytes.Buffer
	output.WriteString(credentialDomain)
	output.WriteByte(0)
	_ = binary.Write(&output, binary.BigEndian, uint32(len(pollID)))
	output.WriteString(pollID)
	_ = binary.Write(&output, binary.BigEndian, uint32(len(issuerKeyID)))
	output.WriteString(issuerKeyID)
	output.Write(serial)
	return output.Bytes(), nil
}

func validatePublicKey(publicKey *rsa.PublicKey) error {
	if publicKey == nil || publicKey.N == nil || publicKey.N.BitLen() < MinRSAKeyBits || publicKey.E < 3 || publicKey.E%2 == 0 {
		return &Error{Code: "invalid_issuer_public_key"}
	}
	return nil
}

func blindEncoded(publicKey *rsa.PublicKey, encoded []byte, random io.Reader) ([]byte, []byte, error) {
	size := publicKey.Size()
	if len(encoded) != size {
		return nil, nil, &Error{Code: "invalid_encoded_message"}
	}
	message := new(big.Int).SetBytes(encoded)
	if message.Cmp(publicKey.N) >= 0 {
		return nil, nil, &Error{Code: "invalid_encoded_message"}
	}
	factor, inverse, err := randomInvertible(publicKey.N, random)
	if err != nil {
		return nil, nil, err
	}
	blinded, err := blindEncodedWithFactor(publicKey, encoded, factor)
	if err != nil {
		return nil, nil, err
	}
	return blinded, leftPad(inverse.Bytes(), size), nil
}

func blindEncodedWithFactor(publicKey *rsa.PublicKey, encoded []byte, factor *big.Int) ([]byte, error) {
	if err := validatePublicKey(publicKey); err != nil {
		return nil, err
	}
	size := publicKey.Size()
	if len(encoded) != size || factor == nil || factor.Sign() <= 0 || factor.Cmp(publicKey.N) >= 0 || new(big.Int).ModInverse(factor, publicKey.N) == nil {
		return nil, &Error{Code: "invalid_blind_factor"}
	}
	message := new(big.Int).SetBytes(encoded)
	if message.Cmp(publicKey.N) >= 0 {
		return nil, &Error{Code: "invalid_encoded_message"}
	}
	e := big.NewInt(int64(publicKey.E))
	blinder := new(big.Int).Exp(factor, e, publicKey.N)
	blinded := new(big.Int).Mul(message, blinder)
	blinded.Mod(blinded, publicKey.N)
	return leftPad(blinded.Bytes(), size), nil
}

func randomInvertible(modulus *big.Int, random io.Reader) (*big.Int, *big.Int, error) {
	for attempts := 0; attempts < 128; attempts++ {
		value, err := cryptorand.Int(random, modulus)
		if err != nil {
			return nil, nil, &Error{Code: "random_failed", Err: err}
		}
		if value.Sign() == 0 {
			continue
		}
		inverse := new(big.Int).ModInverse(value, modulus)
		if inverse != nil {
			return value, inverse, nil
		}
	}
	return nil, nil, &Error{Code: "random_failed"}
}

func leftPad(value []byte, size int) []byte {
	if len(value) >= size {
		return append([]byte(nil), value[len(value)-size:]...)
	}
	output := make([]byte, size)
	copy(output[size-len(value):], value)
	return output
}
