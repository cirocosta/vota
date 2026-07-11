package main

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestHSMatchesMoneroHashToScalar(t *testing.T) {
	t.Parallel()

	var input [32]byte
	for i := range input {
		input[i] = byte(i)
	}

	want, err := hex.DecodeString("b039bf9f4adb213b27713da72243483edea5e526567e92b0321816a4e895bd0d")
	if err != nil {
		t.Fatalf("decode expected scalar: %v", err)
	}

	got := hs(input)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("hs = %s, want %s", hex.EncodeToString(got[:]), hex.EncodeToString(want))
	}
}

func TestEncryptUsesUniqueNonce(t *testing.T) {
	t.Parallel()

	var key [32]byte
	copy(key[:], "0123456789abcdef0123456789abcdef")
	plaintext := []byte("same plaintext")

	first, err := encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("first encrypt: %v", err)
	}
	second, err := encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("second encrypt: %v", err)
	}

	if bytes.Equal(first, second) {
		t.Fatal("encrypt returned identical ciphertext for the same key and plaintext")
	}

	for _, message := range [][]byte{first, second} {
		got, err := decrypt(key, message)
		if err != nil {
			t.Errorf("decrypt: %v", err)
			continue
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("decrypt = %q, want %q", got, plaintext)
		}
	}
}

func TestDecryptRejectsTruncatedMessage(t *testing.T) {
	t.Parallel()

	var key [32]byte
	_, err := decrypt(key, make([]byte, 11))
	if err == nil {
		t.Fatal("decrypt returned nil error for a truncated message")
	}
	if !strings.Contains(err.Error(), "ciphertext too short") {
		t.Errorf("decrypt error = %q, want ciphertext-too-short context", err)
	}
}
