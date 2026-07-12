package keystore

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cirocosta/vota/internal/protocol"
)

var testKDF = KDFParams{
	Time:      1,
	MemoryKiB: 8 * 1024,
	Threads:   1,
	KeyLength: 32,
}

func TestSealOpenRoles(t *testing.T) {
	t.Parallel()

	roles := []Role{RoleAdmin, RoleVoter, RoleTrustee}
	for _, role := range roles {
		t.Run(string(role), func(t *testing.T) {
			secret := []byte("secret material for " + role)
			encoded, err := Seal(role, string(role)+"-key", secret, []byte("correct horse"), testOptions())
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			got, envelope, err := Open(encoded, role, []byte("correct horse"))
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if !bytes.Equal(got, secret) {
				t.Errorf("plaintext = %q, want %q", got, secret)
			}
			if envelope.Role != role {
				t.Errorf("role = %q, want %q", envelope.Role, role)
			}
		})
	}
}

func TestSealUsesUniqueSaltAndNonce(t *testing.T) {
	t.Parallel()

	first, err := Seal(RoleVoter, "voter-key", []byte("secret"), []byte("passphrase"), testOptionsWithByte(0x5a))
	if err != nil {
		t.Fatalf("seal first: %v", err)
	}
	second, err := Seal(RoleVoter, "voter-key", []byte("secret"), []byte("passphrase"), testOptionsWithByte(0x5b))
	if err != nil {
		t.Fatalf("seal second: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two keystores are byte-identical")
	}
	var firstEnvelope, secondEnvelope Envelope
	if err := json.Unmarshal(first, &firstEnvelope); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	if err := json.Unmarshal(second, &secondEnvelope); err != nil {
		t.Fatalf("decode second: %v", err)
	}
	if firstEnvelope.Salt == secondEnvelope.Salt || firstEnvelope.Nonce == secondEnvelope.Nonce {
		t.Fatalf("salt or nonce reused: first %#v second %#v", firstEnvelope, secondEnvelope)
	}
}

func TestOpenFailureCodesDoNotExposeSecrets(t *testing.T) {
	t.Parallel()

	secret := []byte("private-key-bytes-never-print")
	passphrase := []byte("correct-passphrase-never-print")
	encoded, err := Seal(RoleAdmin, "admin-key", secret, passphrase, testOptions())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	tests := []struct {
		name string
		role Role
		pass []byte
		code string
	}{
		{"wrong role", RoleTrustee, passphrase, "wrong_key_role"},
		{"wrong passphrase", RoleAdmin, []byte("wrong"), "key_unlock_failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := Open(encoded, test.role, test.pass)
			if ErrorCode(err) != test.code {
				t.Errorf("error = %v, code = %q, want %q", err, ErrorCode(err), test.code)
			}
			message := err.Error()
			if strings.Contains(message, string(secret)) || strings.Contains(message, string(passphrase)) {
				t.Errorf("error exposes secret: %q", message)
			}
		})
	}
}

func TestSaveLoadPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission semantics are not available")
	}

	encoded, err := Seal(RoleTrustee, "trustee-key", []byte("secret"), []byte("passphrase"), testOptions())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "trustee.vota-key")
	if err := Save(path, encoded); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("permissions = %o, want 600", got)
	}
	if _, _, err := Load(path, RoleTrustee, []byte("passphrase")); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, _, err := Load(path, RoleTrustee, []byte("passphrase")); ErrorCode(err) != "insecure_key_permissions" {
		t.Fatalf("load insecure file error = %v", err)
	}
}

func TestTamperingReturnsUnlockFailure(t *testing.T) {
	t.Parallel()

	encoded, err := Seal(RoleVoter, "voter-key", []byte("secret"), []byte("passphrase"), testOptions())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	var envelope Envelope
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	envelope.Ciphertext = strings.Repeat("00", len(envelope.Ciphertext)/2)
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("encode tampered envelope: %v", err)
	}
	_, _, err = Open(tampered, RoleVoter, []byte("passphrase"))
	if ErrorCode(err) != "key_unlock_failed" {
		t.Fatalf("tamper error = %v, want key_unlock_failed", err)
	}
}

func TestOpenRejectsUppercaseHex(t *testing.T) {
	t.Parallel()

	encoded, err := Seal(RoleVoter, "voter-key", []byte("secret"), []byte("passphrase"), testOptions())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	var envelope Envelope
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}

	tests := []struct {
		name   string
		change func(*Envelope)
	}{
		{"salt", func(value *Envelope) { value.Salt = strings.ToUpper(value.Salt) }},
		{"nonce", func(value *Envelope) { value.Nonce = strings.ToUpper(value.Nonce) }},
		{"ciphertext", func(value *Envelope) { value.Ciphertext = strings.ToUpper(value.Ciphertext) }},
		{"ciphertext checksum", func(value *Envelope) {
			prefix, payload, _ := strings.Cut(value.CiphertextChecksum, ":")
			value.CiphertextChecksum = prefix + ":" + strings.ToUpper(payload)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := envelope
			test.change(&mutated)
			encoded, err := protocol.MarshalCanonical(mutated)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = Open(encoded, RoleVoter, []byte("passphrase"))
			if ErrorCode(err) != "invalid_keystore" {
				t.Fatalf("open error = %v, want invalid_keystore", err)
			}
		})
	}
}

func testOptions() Options {
	return testOptionsWithByte(0x5a)
}

func testOptionsWithByte(value byte) Options {
	return Options{
		KDF:  testKDF,
		Rand: bytes.NewReader(bytes.Repeat([]byte{value}, 4096)),
		Now: func() time.Time {
			return time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
		},
	}
}
