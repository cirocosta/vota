// Package keystore protects Vota role keys at rest.
package keystore

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cirocosta/vota/internal/protocol"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	FormatVersion = "vota-keystore-v1"
	maxFileBytes  = 1 << 20
)

type Role string

const (
	RoleAdmin   Role = "admin"
	RoleVoter   Role = "voter"
	RoleTrustee Role = "trustee"
)

type KDFParams struct {
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
	KeyLength uint32 `json:"key_length"`
}

var DefaultKDFParams = KDFParams{
	Time:      3,
	MemoryKiB: 64 * 1024,
	Threads:   2,
	KeyLength: chacha20poly1305.KeySize,
}

type Envelope struct {
	FormatVersion      string    `json:"format_version"`
	Role               Role      `json:"role"`
	KeyID              string    `json:"key_id"`
	CreatedAt          string    `json:"created_at"`
	KDF                KDFParams `json:"kdf"`
	Salt               string    `json:"salt"`
	Nonce              string    `json:"nonce"`
	Ciphertext         string    `json:"ciphertext"`
	CiphertextChecksum string    `json:"ciphertext_checksum"`
}

type Options struct {
	KDF  KDFParams
	Rand io.Reader
	Now  func() time.Time
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

func (e *Error) Unwrap() error {
	return e.Err
}

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

// Seal encrypts one opaque role secret into a canonical keystore envelope.
func Seal(role Role, keyID string, secret, passphrase []byte, options Options) ([]byte, error) {
	if err := validateRole(role); err != nil {
		return nil, err
	}
	if err := validateKeyID(keyID); err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, &Error{Code: "empty_key_material"}
	}
	if len(passphrase) == 0 {
		return nil, &Error{Code: "empty_passphrase"}
	}
	options = withDefaults(options)
	if err := validateKDF(options.KDF); err != nil {
		return nil, err
	}

	salt := make([]byte, 16)
	if _, err := io.ReadFull(options.Rand, salt); err != nil {
		return nil, &Error{Code: "random_failed", Err: err}
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(options.Rand, nonce); err != nil {
		return nil, &Error{Code: "random_failed", Err: err}
	}

	envelope := Envelope{
		FormatVersion: FormatVersion,
		Role:          role,
		KeyID:         keyID,
		CreatedAt:     options.Now().UTC().Format(time.RFC3339),
		KDF:           options.KDF,
		Salt:          hex.EncodeToString(salt),
		Nonce:         hex.EncodeToString(nonce),
	}
	aad, err := associatedData(envelope)
	if err != nil {
		return nil, err
	}
	key := deriveKey(passphrase, salt, options.KDF)
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, &Error{Code: "cipher_init_failed", Err: err}
	}
	ciphertext := aead.Seal(nil, nonce, secret, aad)
	checksum := sha256.Sum256(ciphertext)
	envelope.Ciphertext = hex.EncodeToString(ciphertext)
	envelope.CiphertextChecksum = "sha256:" + hex.EncodeToString(checksum[:])

	encoded, err := protocol.MarshalCanonical(envelope)
	if err != nil {
		return nil, &Error{Code: "keystore_encode_failed", Err: err}
	}
	return encoded, nil
}

// Open decrypts a canonical keystore after validating its expected role.
func Open(encoded []byte, expectedRole Role, passphrase []byte) ([]byte, Envelope, error) {
	var envelope Envelope
	if err := protocol.DecodeStrict(encoded, &envelope); err != nil {
		return nil, Envelope{}, &Error{Code: "invalid_keystore", Err: err}
	}
	if envelope.FormatVersion != FormatVersion {
		return nil, Envelope{}, &Error{Code: "unsupported_keystore_version"}
	}
	if err := validateRole(envelope.Role); err != nil {
		return nil, Envelope{}, err
	}
	if envelope.Role != expectedRole {
		return nil, Envelope{}, &Error{Code: "wrong_key_role"}
	}
	if err := validateKeyID(envelope.KeyID); err != nil {
		return nil, Envelope{}, err
	}
	if _, err := protocol.ParseCanonicalTime(envelope.CreatedAt); err != nil {
		return nil, Envelope{}, &Error{Code: "invalid_keystore", Err: fmt.Errorf("created_at: %w", err)}
	}
	if err := validateKDF(envelope.KDF); err != nil {
		return nil, Envelope{}, err
	}
	salt, err := decodeHex("salt", envelope.Salt, 16)
	if err != nil {
		return nil, Envelope{}, err
	}
	nonce, err := decodeHex("nonce", envelope.Nonce, chacha20poly1305.NonceSizeX)
	if err != nil {
		return nil, Envelope{}, err
	}
	ciphertext, err := decodeHex("ciphertext", envelope.Ciphertext, -1)
	if err != nil || len(ciphertext) < chacha20poly1305.Overhead {
		return nil, Envelope{}, &Error{Code: "invalid_keystore"}
	}
	checksum := sha256.Sum256(ciphertext)
	checksumBytes, err := protocol.DecodeFixedHex("sha256", envelope.CiphertextChecksum, sha256.Size)
	if err != nil {
		return nil, Envelope{}, &Error{Code: "invalid_keystore", Err: fmt.Errorf("ciphertext_checksum: %w", err)}
	}
	if !bytes.Equal(checksumBytes, checksum[:]) {
		return nil, Envelope{}, &Error{Code: "key_unlock_failed"}
	}
	aad, err := associatedData(envelope)
	if err != nil {
		return nil, Envelope{}, err
	}
	key := deriveKey(passphrase, salt, envelope.KDF)
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, Envelope{}, &Error{Code: "key_unlock_failed"}
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, Envelope{}, &Error{Code: "key_unlock_failed"}
	}
	return plaintext, envelope, nil
}

// Save writes a keystore atomically with owner-only permissions.
func Save(path string, encoded []byte) error {
	if len(encoded) == 0 || len(encoded) > maxFileBytes {
		return &Error{Code: "invalid_keystore_size"}
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".vota-key-*")
	if err != nil {
		return &Error{Code: "key_write_failed", Err: err}
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return &Error{Code: "key_write_failed", Err: err}
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return &Error{Code: "key_write_failed", Err: err}
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return &Error{Code: "key_write_failed", Err: err}
	}
	if err := temporary.Close(); err != nil {
		return &Error{Code: "key_write_failed", Err: err}
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return &Error{Code: "key_write_failed", Err: err}
	}
	return nil
}

// Load checks file permissions and decrypts a keystore.
func Load(path string, expectedRole Role, passphrase []byte) ([]byte, Envelope, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, Envelope{}, &Error{Code: "key_read_failed", Err: err}
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, Envelope{}, &Error{Code: "insecure_key_permissions"}
	}
	if info.Size() <= 0 || info.Size() > maxFileBytes {
		return nil, Envelope{}, &Error{Code: "invalid_keystore_size"}
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, Envelope{}, &Error{Code: "key_read_failed", Err: err}
	}
	return Open(encoded, expectedRole, passphrase)
}

func withDefaults(options Options) Options {
	if options.KDF == (KDFParams{}) {
		options.KDF = DefaultKDFParams
	}
	if options.Rand == nil {
		options.Rand = rand.Reader
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return options
}

func validateRole(role Role) error {
	switch role {
	case RoleAdmin, RoleVoter, RoleTrustee:
		return nil
	default:
		return &Error{Code: "invalid_key_role"}
	}
}

func validateKeyID(keyID string) error {
	if len(keyID) < 3 || len(keyID) > 128 || strings.TrimSpace(keyID) != keyID {
		return &Error{Code: "invalid_key_id"}
	}
	return nil
}

func validateKDF(params KDFParams) error {
	if params.Time < 1 || params.Time > 10 ||
		params.MemoryKiB < 8*1024 || params.MemoryKiB > 1024*1024 ||
		params.Threads < 1 || params.Threads > 16 ||
		params.KeyLength != chacha20poly1305.KeySize {
		return &Error{Code: "invalid_kdf_parameters"}
	}
	return nil
}

func deriveKey(passphrase, salt []byte, params KDFParams) []byte {
	return argon2.IDKey(passphrase, salt, params.Time, params.MemoryKiB, params.Threads, params.KeyLength)
}

func associatedData(envelope Envelope) ([]byte, error) {
	header := struct {
		FormatVersion string    `json:"format_version"`
		Role          Role      `json:"role"`
		KeyID         string    `json:"key_id"`
		CreatedAt     string    `json:"created_at"`
		KDF           KDFParams `json:"kdf"`
		Salt          string    `json:"salt"`
		Nonce         string    `json:"nonce"`
	}{
		FormatVersion: envelope.FormatVersion,
		Role:          envelope.Role,
		KeyID:         envelope.KeyID,
		CreatedAt:     envelope.CreatedAt,
		KDF:           envelope.KDF,
		Salt:          envelope.Salt,
		Nonce:         envelope.Nonce,
	}
	encoded, err := protocol.MarshalCanonical(header)
	if err != nil {
		return nil, &Error{Code: "keystore_encode_failed", Err: err}
	}
	return encoded, nil
}

func decodeHex(field, value string, expectedBytes int) ([]byte, error) {
	decoded, err := protocol.DecodeRawHex(value, expectedBytes)
	if err != nil {
		return nil, &Error{Code: "invalid_keystore", Err: fmt.Errorf("%s: %w", field, err)}
	}
	return decoded, nil
}
