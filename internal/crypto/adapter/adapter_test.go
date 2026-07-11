package adapter

import (
	"crypto/sha512"
	"fmt"
	"io"
	"testing"

	"github.com/cirocosta/vota/internal/crypto/lrs"
)

func TestRingV1RoundTripThroughInterfaces(t *testing.T) {
	t.Parallel()

	privateKeys, encodedRing := testRing(t, 5)
	pollID := digest32("poll")
	prover, err := NewRingV1Prover(pollID, encodedRing, privateKeys[3][:], 3)
	if err != nil {
		t.Fatalf("new prover: %v", err)
	}
	verifier, err := NewVerifier("ring-v1", pollID, encodedRing)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	message := digest32("ballot")
	artifact, err := prover.Prove(message, newHashReader("proof"))
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := verifyAsCollector(verifier, message, artifact); err != nil {
		t.Fatalf("verify: %v", err)
	}

	second, err := prover.Prove(digest32("other-ballot"), newHashReader("other-proof"))
	if err != nil {
		t.Fatalf("prove second: %v", err)
	}
	if artifact.Nullifier != second.Nullifier {
		t.Fatal("poll nullifier changed")
	}
	mutated := artifact
	mutated.Nullifier[0] ^= 1
	if err := verifier.Verify(message, mutated); ErrorCode(err) != "nullifier_mismatch" {
		t.Fatalf("nullifier error = %v", err)
	}
}

func TestUnknownSchemeFailsClosed(t *testing.T) {
	t.Parallel()

	_, encodedRing := testRing(t, 2)
	if _, err := NewVerifier("future-v2", digest32("poll"), encodedRing); ErrorCode(err) != "unsupported_eligibility_scheme" {
		t.Fatalf("factory error = %v", err)
	}
	verifier, err := NewVerifier("ring-v1", digest32("poll"), encodedRing)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(digest32("ballot"), Artifact{Scheme: "future-v2"}); ErrorCode(err) != "unsupported_eligibility_scheme" {
		t.Fatalf("artifact error = %v", err)
	}
}

func verifyAsCollector(verifier Verifier, message [32]byte, artifact Artifact) error {
	return verifier.Verify(message, artifact)
}

func testRing(tb testing.TB, size int) ([]lrs.PrivateKey, [][]byte) {
	tb.Helper()
	privateKeys := make([]lrs.PrivateKey, size)
	encodedRing := make([][]byte, size)
	for index := range size {
		privateKey, publicKey, err := lrs.GenerateKey(newHashReader(fmt.Sprintf("key-%d", index)))
		if err != nil {
			tb.Fatalf("generate key %d: %v", index, err)
		}
		privateKeys[index] = privateKey
		encodedRing[index] = append([]byte(nil), publicKey[:]...)
	}
	return privateKeys, encodedRing
}

func digest32(value string) [32]byte {
	digest := sha512.Sum512([]byte(value))
	var result [32]byte
	copy(result[:], digest[:32])
	return result
}

type hashReader struct {
	seed    []byte
	counter uint64
	buffer  []byte
}

func newHashReader(seed string) io.Reader {
	return &hashReader{seed: []byte(seed)}
}

func (reader *hashReader) Read(output []byte) (int, error) {
	written := 0
	for written < len(output) {
		if len(reader.buffer) == 0 {
			input := append([]byte(nil), reader.seed...)
			input = append(input,
				byte(reader.counter>>56), byte(reader.counter>>48), byte(reader.counter>>40), byte(reader.counter>>32),
				byte(reader.counter>>24), byte(reader.counter>>16), byte(reader.counter>>8), byte(reader.counter),
			)
			digest := sha512.Sum512(input)
			reader.buffer = append(reader.buffer[:0], digest[:]...)
			reader.counter++
		}
		count := copy(output[written:], reader.buffer)
		reader.buffer = reader.buffer[count:]
		written += count
	}
	return written, nil
}
