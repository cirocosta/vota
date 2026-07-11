package main

import (
	"bytes"
	"strings"
	"testing"
)

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
