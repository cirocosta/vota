package app

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cirocosta/vota/internal/crypto/lrs"
	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
)

func TestCastAndVerifyBallot(t *testing.T) {
	t.Parallel()

	value := testManifest(t)
	privateKey, signerIndex := eligibleCredential(t, value, "voter-0")
	ballot, err := CastBallot(value, privateKey, signerIndex, 1, newHashReader("cast"))
	if err != nil {
		t.Fatalf("cast: %v", err)
	}
	if err := VerifyBallot(value, ballot); err != nil {
		t.Fatalf("verify: %v", err)
	}
	encoded, err := MarshalBallot(ballot)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	fixture, err := os.ReadFile(filepath.Join("..", "..", "testdata", "app", "ballot.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if !bytes.Equal(encoded, bytes.TrimSpace(fixture)) {
		t.Fatalf("ballot differs from fixture: %s", encoded)
	}
	parsed, err := ParseBallot(encoded)
	if err != nil || VerifyBallot(value, parsed) != nil {
		t.Fatalf("parse and verify: %v", err)
	}
	for _, label := range []string{"Blue", "Green"} {
		if bytes.Contains(encoded, []byte(label)) {
			t.Fatalf("ballot exposes choice label %q", label)
		}
	}
}

func TestBallotMutationsAndLinking(t *testing.T) {
	t.Parallel()

	value := testManifest(t)
	privateKey, signerIndex := eligibleCredential(t, value, "voter-1")
	first, err := CastBallot(value, privateKey, signerIndex, 0, newHashReader("first"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := CastBallot(value, privateKey, signerIndex, 1, newHashReader("second"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Nullifier != second.Nullifier {
		t.Fatal("same eligibility key produced different nullifiers")
	}
	mutated := first
	mutated.Ciphertexts = append([]string(nil), first.Ciphertexts...)
	mutated.Ciphertexts[0] = mutated.Ciphertexts[0][:len(mutated.Ciphertexts[0])-2] + "00"
	if err := VerifyBallot(value, mutated); ErrorCode(err) != "ballot_hash_mismatch" {
		t.Fatalf("ciphertext mutation error = %v", err)
	}
	mutated = first
	mutated.ManifestHash = hashString("other-manifest")
	if err := VerifyBallot(value, mutated); ErrorCode(err) != "wrong_manifest" {
		t.Fatalf("manifest mutation error = %v", err)
	}
	mutated = first
	mutated.Nullifier = "ristretto255:" + strings.Repeat("00", 32)
	if err := VerifyBallot(value, mutated); ErrorCode(err) != "nullifier_mismatch" {
		t.Fatalf("nullifier mutation error = %v", err)
	}
}

func TestCastRejectsIneligibleCredential(t *testing.T) {
	t.Parallel()

	value := testManifest(t)
	privateKey, _, err := lrs.GenerateKey(newHashReader("outsider"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CastBallot(value, privateKey, 0, 0, newHashReader("cast")); ErrorCode(err) != "credential_not_eligible" {
		t.Fatalf("error = %v", err)
	}
}

func testManifest(tb testing.TB) protocol.Manifest {
	tb.Helper()
	encoded, err := os.ReadFile(filepath.Join("..", "..", "testdata", "manifest", "canonical.json"))
	if err != nil {
		tb.Fatalf("read manifest: %v", err)
	}
	frozen, err := manifest.Parse(bytes.TrimSpace(encoded))
	if err != nil {
		tb.Fatalf("parse manifest: %v", err)
	}
	return frozen.Manifest()
}

func eligibleCredential(tb testing.TB, value protocol.Manifest, seed string) (lrs.PrivateKey, int) {
	tb.Helper()
	privateKey, publicKey, err := lrs.GenerateKey(newHashReader(seed))
	if err != nil {
		tb.Fatalf("generate credential: %v", err)
	}
	encoded := fmt.Sprintf("ristretto255:%x", publicKey)
	for index, member := range value.EligibleKeys {
		if member == encoded {
			return privateKey, index
		}
	}
	tb.Fatalf("credential %s is not in fixture", seed)
	return lrs.PrivateKey{}, -1
}

func hashString(value string) string {
	digest := sha512.Sum512([]byte(value))
	return fmt.Sprintf("sha256:%x", digest[:32])
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
