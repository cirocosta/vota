// Package sshsig creates and verifies OpenSSH SSHSIG signatures with keys held
// by ssh-agent.
package sshsig

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	magic            = "SSHSIG"
	version          = uint32(1)
	hashAlgorithm    = "sha512"
	pemType          = "SSH SIGNATURE"
	maxNamespaceSize = 128
	maxSignatureSize = 16 << 10
)

// Error reports a stable SSHSIG adapter error code.
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

// ErrorCode returns a stable public code for an adapter error.
func ErrorCode(err error) string {
	var target *Error
	if errors.As(err, &target) {
		return target.Code
	}
	return "internal_error"
}

type envelope struct {
	Version       uint32
	PublicKey     []byte
	Namespace     string
	Reserved      []byte
	HashAlgorithm string
	Signature     []byte
}

type signedPayload struct {
	Namespace     string
	Reserved      []byte
	HashAlgorithm string
	MessageHash   []byte
}

// ParsePublicKey parses one authorized_keys-formatted Ed25519 public key. A
// trailing comment is accepted but is not part of the canonical key.
func ParsePublicKey(encoded []byte) (ssh.PublicKey, error) {
	publicKey, _, options, rest, err := ssh.ParseAuthorizedKey(encoded)
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, &Error{Code: "invalid_ssh_public_key", Err: err}
	}
	if publicKey.Type() != ssh.KeyAlgoED25519 {
		return nil, &Error{Code: "unsupported_ssh_key_type"}
	}
	return publicKey, nil
}

// CanonicalPublicKey returns the normalized authorized_keys representation
// without a comment.
func CanonicalPublicKey(publicKey ssh.PublicKey) ([]byte, error) {
	if publicKey == nil || publicKey.Type() != ssh.KeyAlgoED25519 {
		return nil, &Error{Code: "unsupported_ssh_key_type"}
	}
	return bytes.TrimSpace(ssh.MarshalAuthorizedKey(publicKey)), nil
}

// Fingerprint returns the OpenSSH SHA-256 fingerprint for an Ed25519 key.
func Fingerprint(publicKey ssh.PublicKey) (string, error) {
	if publicKey == nil || publicKey.Type() != ssh.KeyAlgoED25519 {
		return "", &Error{Code: "unsupported_ssh_key_type"}
	}
	return ssh.FingerprintSHA256(publicKey), nil
}

// Sign asks the agent named by SSH_AUTH_SOCK to create an armored SSHSIG
// signature. The private key is never read by this package.
func Sign(ctx context.Context, encodedPublicKey []byte, namespace string, message []byte) ([]byte, error) {
	publicKey, err := ParsePublicKey(encodedPublicKey)
	if err != nil {
		return nil, err
	}
	if err := validateNamespace(namespace); err != nil {
		return nil, err
	}
	socketPath := os.Getenv("SSH_AUTH_SOCK")
	if socketPath == "" {
		return nil, &Error{Code: "ssh_agent_unavailable"}
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, &Error{Code: "ssh_agent_unavailable", Err: err}
	}
	defer connection.Close()
	return signWithAgent(agent.NewClient(connection), publicKey, namespace, message)
}

func signWithAgent(client agent.Agent, publicKey ssh.PublicKey, namespace string, message []byte) ([]byte, error) {
	if client == nil {
		return nil, &Error{Code: "ssh_agent_unavailable"}
	}
	if publicKey == nil || publicKey.Type() != ssh.KeyAlgoED25519 {
		return nil, &Error{Code: "unsupported_ssh_key_type"}
	}
	if err := validateNamespace(namespace); err != nil {
		return nil, err
	}
	keys, err := client.List()
	if err != nil {
		return nil, &Error{Code: "ssh_agent_list_failed", Err: err}
	}
	var selected ssh.PublicKey
	for _, candidate := range keys {
		if candidate.Type() == publicKey.Type() && subtle.ConstantTimeCompare(candidate.Marshal(), publicKey.Marshal()) == 1 {
			selected = candidate
			break
		}
	}
	if selected == nil {
		return nil, &Error{Code: "ssh_key_not_in_agent"}
	}
	payload := payloadFor(namespace, message)
	signature, err := client.Sign(selected, payload)
	if err != nil {
		return nil, &Error{Code: "ssh_agent_sign_failed", Err: err}
	}
	if signature == nil || signature.Format != ssh.KeyAlgoED25519 || len(signature.Blob) == 0 {
		return nil, &Error{Code: "invalid_ssh_signature"}
	}
	blob := envelope{
		Version:       version,
		PublicKey:     append([]byte(nil), publicKey.Marshal()...),
		Namespace:     namespace,
		Reserved:      []byte{},
		HashAlgorithm: hashAlgorithm,
		Signature:     ssh.Marshal(signature),
	}
	binarySignature := append([]byte(magic), ssh.Marshal(blob)...)
	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: binarySignature}), nil
}

// Verify checks an armored SSHSIG against the expected key, namespace, and
// message. It accepts only version 1 Ed25519 signatures using SHA-512.
func Verify(expectedKey ssh.PublicKey, namespace string, message, encodedSignature []byte) error {
	if expectedKey == nil || expectedKey.Type() != ssh.KeyAlgoED25519 {
		return &Error{Code: "unsupported_ssh_key_type"}
	}
	if err := validateNamespace(namespace); err != nil {
		return err
	}
	if len(encodedSignature) == 0 || len(encodedSignature) > maxSignatureSize {
		return &Error{Code: "invalid_ssh_signature_encoding"}
	}
	block, rest := pem.Decode(encodedSignature)
	if block == nil || block.Type != pemType || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(block.Bytes, []byte(magic)) {
		return &Error{Code: "invalid_ssh_signature_encoding"}
	}
	var value envelope
	if err := ssh.Unmarshal(block.Bytes[len(magic):], &value); err != nil {
		return &Error{Code: "invalid_ssh_signature_encoding", Err: err}
	}
	if value.Version != version {
		return &Error{Code: "unsupported_ssh_signature_version"}
	}
	if value.Namespace != namespace {
		return &Error{Code: "wrong_ssh_signature_namespace"}
	}
	if len(value.Reserved) != 0 {
		return &Error{Code: "unsupported_ssh_signature_reserved"}
	}
	if value.HashAlgorithm != hashAlgorithm {
		return &Error{Code: "unsupported_ssh_hash_algorithm"}
	}
	embeddedKey, err := ssh.ParsePublicKey(value.PublicKey)
	if err != nil || embeddedKey.Type() != ssh.KeyAlgoED25519 {
		return &Error{Code: "invalid_ssh_signature_key", Err: err}
	}
	if subtle.ConstantTimeCompare(embeddedKey.Marshal(), expectedKey.Marshal()) != 1 {
		return &Error{Code: "wrong_ssh_signature_key"}
	}
	var signature ssh.Signature
	if err := ssh.Unmarshal(value.Signature, &signature); err != nil || len(signature.Rest) != 0 || signature.Format != ssh.KeyAlgoED25519 || len(signature.Blob) == 0 {
		return &Error{Code: "invalid_ssh_signature_encoding", Err: err}
	}
	if err := embeddedKey.Verify(payloadFor(value.Namespace, message), &signature); err != nil {
		return &Error{Code: "invalid_ssh_signature", Err: err}
	}
	return nil
}

func payloadFor(namespace string, message []byte) []byte {
	digest := sha512.Sum512(message)
	value := signedPayload{
		Namespace:     namespace,
		Reserved:      []byte{},
		HashAlgorithm: hashAlgorithm,
		MessageHash:   digest[:],
	}
	return append([]byte(magic), ssh.Marshal(value)...)
}

func validateNamespace(namespace string) error {
	if namespace == "" || len(namespace) > maxNamespaceSize || !utf8.ValidString(namespace) || strings.TrimSpace(namespace) != namespace {
		return &Error{Code: "invalid_ssh_signature_namespace"}
	}
	for _, value := range namespace {
		if value < 0x21 || value > 0x7e {
			return &Error{Code: "invalid_ssh_signature_namespace"}
		}
	}
	return nil
}
