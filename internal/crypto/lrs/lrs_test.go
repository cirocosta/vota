package lrs

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gtank/ristretto255"
)

func TestSignVerifyEveryPosition(t *testing.T) {
	t.Parallel()

	privateKeys, ring := deterministicRing(t, 16)
	pollID := digest32("poll")
	message := digest32("ballot")
	for index := range ring {
		t.Run(fmt.Sprintf("index_%d", index), func(t *testing.T) {
			signature, err := Sign(pollID, message, ring, privateKeys[index], index, newHashReader(fmt.Sprintf("sign-%d", index)))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if err := Verify(pollID, message, ring, signature); err != nil {
				t.Fatalf("verify: %v", err)
			}
		})
	}
}

func TestLinkIsStableWithinPollKey(t *testing.T) {
	t.Parallel()

	privateKeys, ring := deterministicRing(t, 3)
	pollID := digest32("poll")
	first, err := Sign(pollID, digest32("choice-a"), ring, privateKeys[1], 1, newHashReader("first"))
	if err != nil {
		t.Fatalf("sign first: %v", err)
	}
	second, err := Sign(pollID, digest32("choice-b"), ring, privateKeys[1], 1, newHashReader("second"))
	if err != nil {
		t.Fatalf("sign second: %v", err)
	}
	other, err := Sign(pollID, digest32("choice-a"), ring, privateKeys[2], 2, newHashReader("other"))
	if err != nil {
		t.Fatalf("sign other: %v", err)
	}
	if !Link(first, second) {
		t.Fatal("same poll key did not link")
	}
	if Link(first, other) {
		t.Fatal("different poll keys linked")
	}
}

func TestVerifyRejectsMutations(t *testing.T) {
	t.Parallel()

	privateKeys, ring := deterministicRing(t, 5)
	pollID := digest32("poll")
	message := digest32("ballot")
	signature, err := Sign(pollID, message, ring, privateKeys[2], 2, newHashReader("signature"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	t.Run("message", func(t *testing.T) {
		if err := Verify(pollID, digest32("other"), ring, signature); ErrorCode(err) != "invalid_signature" {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("poll", func(t *testing.T) {
		if err := Verify(digest32("other-poll"), message, ring, signature); ErrorCode(err) != "invalid_signature" {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("ring order", func(t *testing.T) {
		mutated := append([]PublicKey(nil), ring...)
		mutated[0], mutated[1] = mutated[1], mutated[0]
		if err := Verify(pollID, message, mutated, signature); ErrorCode(err) != "invalid_signature" {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("response", func(t *testing.T) {
		mutated := cloneSignature(signature)
		mutated.Responses[0][0] ^= 1
		if err := Verify(pollID, message, ring, mutated); err == nil {
			t.Fatal("mutated response verified")
		}
	})
}

func TestRingValidation(t *testing.T) {
	t.Parallel()

	privateKeys, ring := deterministicRing(t, 3)
	tests := []struct {
		name string
		ring func() []PublicKey
		code string
	}{
		{"duplicate", func() []PublicKey { return []PublicKey{ring[0], ring[0]} }, "duplicate_ring_key"},
		{"identity", func() []PublicKey {
			identity := PublicKey(elementBytes(ristretto255.NewIdentityElement()))
			return []PublicKey{ring[0], identity}
		}, "invalid_ring_key"},
		{"too small", func() []PublicKey { return ring[:1] }, "invalid_ring_size"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Sign(digest32("poll"), digest32("message"), test.ring(), privateKeys[0], 0, newHashReader("random"))
			if ErrorCode(err) != test.code {
				t.Fatalf("error = %v, code = %q, want %q", err, ErrorCode(err), test.code)
			}
		})
	}
}

func TestSignatureBinaryRoundTrip(t *testing.T) {
	t.Parallel()

	privateKeys, ring := deterministicRing(t, 4)
	pollID := digest32("poll")
	message := digest32("message")
	signature, err := Sign(pollID, message, ring, privateKeys[0], 0, newHashReader("binary"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	encoded, err := signature.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded, err := ParseSignature(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Verify(pollID, message, ring, decoded); err != nil {
		t.Fatalf("verify decoded: %v", err)
	}
	if !bytes.Equal(signature.KeyImage[:], decoded.KeyImage[:]) {
		t.Fatal("key image changed across encoding")
	}
}

func TestVector(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "crypto", "lrs", "vector.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vector struct {
		PrivateKey  string   `json:"private_key"`
		Ring        []string `json:"ring"`
		SignerIndex int      `json:"signer_index"`
		PollID      string   `json:"poll_id"`
		Message     string   `json:"message"`
		RandomSeed  string   `json:"random_seed"`
		Signature   string   `json:"signature"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	privateBytes := mustDecodeHex(t, vector.PrivateKey, ScalarSize)
	var privateKey PrivateKey
	copy(privateKey[:], privateBytes)
	ring := make([]PublicKey, len(vector.Ring))
	for index, encoded := range vector.Ring {
		copy(ring[index][:], mustDecodeHex(t, encoded, PublicKeySize))
	}
	var pollID [PollIDSize]byte
	copy(pollID[:], mustDecodeHex(t, vector.PollID, PollIDSize))
	var message [MessageSize]byte
	copy(message[:], mustDecodeHex(t, vector.Message, MessageSize))

	signature, err := Sign(pollID, message, ring, privateKey, vector.SignerIndex, newHashReader(vector.RandomSeed))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	encoded, err := signature.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := hex.EncodeToString(encoded); got != vector.Signature {
		t.Fatalf("signature vector = %s", got)
	}
	if err := Verify(pollID, message, ring, signature); err != nil {
		t.Fatalf("verify vector: %v", err)
	}
}

func FuzzParseSignature(f *testing.F) {
	privateKeys, ring := deterministicRing(f, 3)
	pollID := digest32("fuzz-poll")
	message := digest32("fuzz-message")
	signature, err := Sign(pollID, message, ring, privateKeys[1], 1, newHashReader("fuzz-random"))
	if err != nil {
		f.Fatalf("sign seed: %v", err)
	}
	encoded, err := signature.MarshalBinary()
	if err != nil {
		f.Fatalf("marshal seed: %v", err)
	}
	f.Add(encoded)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := ParseSignature(data)
		if err == nil {
			_ = Verify(pollID, message, ring, parsed)
		}
	})
}

func BenchmarkVerify(b *testing.B) {
	for _, size := range []int{16, 64, 128, 256} {
		b.Run(fmt.Sprintf("ring_%d", size), func(b *testing.B) {
			privateKeys, ring := deterministicRing(b, size)
			pollID := digest32("benchmark-poll")
			message := digest32("benchmark-message")
			signature, err := Sign(pollID, message, ring, privateKeys[size/2], size/2, newHashReader("benchmark-random"))
			if err != nil {
				b.Fatalf("sign: %v", err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if err := Verify(pollID, message, ring, signature); err != nil {
					b.Fatalf("verify: %v", err)
				}
			}
		})
	}
}

func BenchmarkSign(b *testing.B) {
	for _, size := range []int{16, 64, 128, 256} {
		b.Run(fmt.Sprintf("ring_%d", size), func(b *testing.B) {
			privateKeys, ring := deterministicRing(b, size)
			pollID := digest32("benchmark-poll")
			message := digest32("benchmark-message")
			signerIndex := size / 2
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Sign(pollID, message, ring, privateKeys[signerIndex], signerIndex, newHashReader("benchmark-random")); err != nil {
					b.Fatalf("sign: %v", err)
				}
			}
		})
	}
}

type testingTB interface {
	Helper()
	Fatalf(string, ...any)
}

func deterministicRing(tb testingTB, size int) ([]PrivateKey, []PublicKey) {
	tb.Helper()
	privateKeys := make([]PrivateKey, size)
	ring := make([]PublicKey, size)
	for index := range size {
		privateKey, publicKey, err := GenerateKey(newHashReader(fmt.Sprintf("key-%d", index)))
		if err != nil {
			tb.Fatalf("generate key %d: %v", index, err)
		}
		privateKeys[index] = privateKey
		ring[index] = publicKey
	}
	return privateKeys, ring
}

func digest32(value string) [32]byte {
	digest := sha512.Sum512([]byte(value))
	var output [32]byte
	copy(output[:], digest[:32])
	return output
}

func cloneSignature(signature Signature) Signature {
	cloned := signature
	cloned.Responses = append([][ScalarSize]byte(nil), signature.Responses...)
	return cloned
}

func mustDecodeHex(t *testing.T, value string, size int) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	if len(decoded) != size {
		t.Fatalf("decoded size = %d, want %d", len(decoded), size)
	}
	return decoded
}

type hashReader struct {
	seed    string
	counter uint64
	buffer  []byte
}

func newHashReader(seed string) io.Reader {
	return &hashReader{seed: seed}
}

func (reader *hashReader) Read(target []byte) (int, error) {
	written := 0
	for written < len(target) {
		if len(reader.buffer) == 0 {
			digest := sha512.Sum512(fmt.Appendf(nil, "%s:%d", reader.seed, reader.counter))
			reader.counter++
			reader.buffer = digest[:]
		}
		count := copy(target[written:], reader.buffer)
		reader.buffer = reader.buffer[count:]
		written += count
	}
	return written, nil
}
