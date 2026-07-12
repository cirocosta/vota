package blind

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const privateKeyPEMType = "RSA PRIVATE KEY"

// LoadOrCreatePrivateKey loads an owner-only PKCS#1 key or atomically creates
// a new 2048-bit issuer key.
func LoadOrCreatePrivateKey(path string) (*rsa.PrivateKey, bool, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		info, statErr := os.Stat(path)
		if statErr != nil {
			return nil, false, &Error{Code: "issuer_key_read_failed", Err: statErr}
		}
		if info.Mode().Perm() != 0o600 {
			return nil, false, &Error{Code: "unsafe_issuer_key_permissions"}
		}
		key, parseErr := ParsePrivateKey(data)
		return key, false, parseErr
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, &Error{Code: "issuer_key_read_failed", Err: err}
	}
	key, err := rsa.GenerateKey(rand.Reader, MinRSAKeyBits)
	if err != nil {
		return nil, false, &Error{Code: "issuer_key_generation_failed", Err: err}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, &Error{Code: "issuer_key_write_failed", Err: err}
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: x509.MarshalPKCS1PrivateKey(key)})
	temporary, err := os.CreateTemp(filepath.Dir(path), ".issuer-key-*")
	if err != nil {
		return nil, false, &Error{Code: "issuer_key_write_failed", Err: err}
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return nil, false, &Error{Code: "issuer_key_write_failed", Err: err}
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return nil, false, &Error{Code: "issuer_key_write_failed", Err: err}
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return nil, false, &Error{Code: "issuer_key_write_failed", Err: err}
	}
	if err := temporary.Close(); err != nil {
		return nil, false, &Error{Code: "issuer_key_write_failed", Err: err}
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return LoadOrCreatePrivateKey(path)
		}
		return nil, false, &Error{Code: "issuer_key_write_failed", Err: err}
	}
	return key, true, nil
}

func ParsePrivateKey(encoded []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != privateKeyPEMType || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, &Error{Code: "invalid_issuer_private_key"}
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil || key.N.BitLen() < MinRSAKeyBits || key.E != 65537 {
		return nil, &Error{Code: "invalid_issuer_private_key", Err: err}
	}
	if err := key.Validate(); err != nil {
		return nil, &Error{Code: "invalid_issuer_private_key", Err: err}
	}
	return key, nil
}

func EncodePublicKey(publicKey *rsa.PublicKey) (string, error) {
	if err := validatePublicKey(publicKey); err != nil {
		return "", err
	}
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", &Error{Code: "issuer_public_key_encode_failed", Err: err}
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func ParsePublicKey(encoded string) (*rsa.PublicKey, error) {
	der, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, &Error{Code: "invalid_issuer_public_key", Err: err}
	}
	value, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, &Error{Code: "invalid_issuer_public_key", Err: err}
	}
	publicKey, ok := value.(*rsa.PublicKey)
	if !ok {
		return nil, &Error{Code: "invalid_issuer_public_key", Err: fmt.Errorf("not RSA")}
	}
	if err := validatePublicKey(publicKey); err != nil {
		return nil, err
	}
	canonical, _ := EncodePublicKey(publicKey)
	if canonical != encoded {
		return nil, &Error{Code: "invalid_issuer_public_key"}
	}
	return publicKey, nil
}

func KeyID(publicKey *rsa.PublicKey) string {
	if publicKey == nil {
		return ""
	}
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}
