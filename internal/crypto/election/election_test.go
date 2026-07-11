package election

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gtank/ristretto255"
)

func TestCeremonyAndDealerVerification(t *testing.T) {
	t.Parallel()

	contributions := deterministicContributions(t, 3, 2)
	for _, contribution := range contributions {
		for recipient := 1; recipient <= 3; recipient++ {
			share, err := contribution.ShareFor(recipient)
			if err != nil {
				t.Fatalf("get dealer %d recipient %d: %v", contribution.DealerIndex, recipient, err)
			}
			if err := VerifyDealerShare(contribution.Public(), 3, share); err != nil {
				t.Fatalf("verify dealer %d recipient %d: %v", contribution.DealerIndex, recipient, err)
			}
		}
	}
	ceremony, shares, err := finalizeCeremony(contributions)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if ceremony.TrusteeCount != 3 || ceremony.Quorum != 2 || len(shares) != 3 {
		t.Fatalf("ceremony = %+v, shares = %d", ceremony, len(shares))
	}

	mutated := cloneContribution(contributions[0])
	share, _ := mutated.ShareFor(2)
	share.Value[0] ^= 1
	if err := VerifyDealerShare(mutated.Public(), 3, share); ErrorCode(err) != "invalid_ceremony_share" {
		t.Fatalf("mutated share error = %v", err)
	}
	if _, _, err := finalizeCeremony([]DealerContribution{contributions[0], contributions[0], contributions[2]}); ErrorCode(err) != "invalid_dealer_set" {
		t.Fatalf("duplicate dealer error = %v", err)
	}
}

func TestEncryptVerifyEveryChoice(t *testing.T) {
	t.Parallel()

	ceremony, _ := deterministicCeremony(t, 3, 2)
	binding := testBinding("poll")
	for count := MinChoices; count <= MaxChoices; count++ {
		for selected := range count {
			ballot, err := EncryptChoice(binding, ceremony.ElectionKey, count, selected, newHashReader(fmt.Sprintf("ballot-%d-%d", count, selected)))
			if err != nil {
				t.Fatalf("encrypt %d/%d: %v", selected, count, err)
			}
			if err := VerifyBallot(binding, ceremony.ElectionKey, ballot); err != nil {
				t.Fatalf("verify %d/%d: %v", selected, count, err)
			}
		}
	}
}

func TestBallotRejectsMutations(t *testing.T) {
	t.Parallel()

	ceremony, _ := deterministicCeremony(t, 3, 2)
	binding := testBinding("poll")
	ballot, err := EncryptChoice(binding, ceremony.ElectionKey, 3, 1, newHashReader("valid-ballot"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	tests := []struct {
		name   string
		change func(*EncryptedBallot) Binding
	}{
		{"ciphertext", func(value *EncryptedBallot) Binding { value.Ciphertexts[0].B[0] ^= 1; return binding }},
		{"bit proof", func(value *EncryptedBallot) Binding { value.Proof.Bits[0].Responses[0][0] ^= 1; return binding }},
		{"sum proof", func(value *EncryptedBallot) Binding { value.Proof.Sum.Response[0] ^= 1; return binding }},
		{"poll", func(_ *EncryptedBallot) Binding { return testBinding("other-poll") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := cloneBallot(ballot)
			mutatedBinding := test.change(&mutated)
			if err := VerifyBallot(mutatedBinding, ceremony.ElectionKey, mutated); err == nil {
				t.Fatal("mutation verified")
			}
		})
	}

	malformed := cloneBallot(ballot)
	malformed.Ciphertexts[0].A = Point{}
	if err := VerifyBallot(binding, ceremony.ElectionKey, malformed); ErrorCode(err) != "invalid_ciphertext" {
		t.Fatalf("malformed point error = %v", err)
	}

	for _, values := range [][]int{{0, 0}, {1, 1}} {
		invalid := encryptBitsForTest(t, binding, ceremony.ElectionKey, values)
		if err := VerifyBallot(binding, ceremony.ElectionKey, invalid); ErrorCode(err) != "invalid_choice_sum_proof" {
			t.Fatalf("values %v error = %v", values, err)
		}
	}
	negative := cloneBallot(ballot)
	b, err := decodePoint(negative.Ciphertexts[1].B)
	if err != nil {
		t.Fatal(err)
	}
	twoGenerators := ristretto255.NewIdentityElement().Add(ristretto255.NewGeneratorElement(), ristretto255.NewGeneratorElement())
	negative.Ciphertexts[1].B = pointBytes(subtractPoints(b, twoGenerators))
	if err := VerifyBallot(binding, ceremony.ElectionKey, negative); err == nil {
		t.Fatal("negative plaintext mutation verified")
	}
	otherCeremony, _ := deterministicCeremony(t, 2, 2)
	if err := VerifyBallot(binding, otherCeremony.ElectionKey, ballot); err == nil {
		t.Fatal("wrong election key verified")
	}
}

func TestAggregateThresholdTally(t *testing.T) {
	t.Parallel()

	ceremony, secrets := deterministicCeremony(t, 3, 2)
	binding := testBinding("tally-poll")
	selections := []int{0, 1, 0}
	ballots := make([]EncryptedBallot, len(selections))
	for index, selected := range selections {
		var err error
		ballots[index], err = EncryptChoice(binding, ceremony.ElectionKey, 2, selected, newHashReader(fmt.Sprintf("vote-%d", index)))
		if err != nil {
			t.Fatalf("encrypt %d: %v", index, err)
		}
	}
	aggregate, err := AggregateBallots(binding, ceremony.ElectionKey, ballots)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	aggregateHash := digest32("aggregate")
	shares := make([]DecryptionShare, 2)
	for index := range shares {
		shares[index], err = CreateDecryptionShare(ceremony, secrets[index], aggregateHash, aggregate, newHashReader(fmt.Sprintf("share-%d", index)))
		if err != nil {
			t.Fatalf("share %d: %v", index, err)
		}
		if err := VerifyDecryptionShare(ceremony, aggregateHash, aggregate, shares[index]); err != nil {
			t.Fatalf("verify share %d: %v", index, err)
		}
	}
	totals, err := CombineShares(ceremony, aggregateHash, aggregate, shares)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if fmt.Sprint(totals) != "[2 1]" {
		t.Fatalf("totals = %v", totals)
	}

	if _, err := CombineShares(ceremony, aggregateHash, aggregate, shares[:1]); ErrorCode(err) != "insufficient_decryption_shares" {
		t.Fatalf("insufficient error = %v", err)
	}
	if _, err := CombineShares(ceremony, aggregateHash, aggregate, []DecryptionShare{shares[0], shares[0]}); ErrorCode(err) != "duplicate_trustee_share" {
		t.Fatalf("duplicate error = %v", err)
	}
	if _, err := CombineShares(ceremony, digest32("stale"), aggregate, shares); ErrorCode(err) != "wrong_aggregate_hash" {
		t.Fatalf("stale error = %v", err)
	}
	unknown := shares[0]
	unknown.TrusteeIndex = 4
	if err := VerifyDecryptionShare(ceremony, aggregateHash, aggregate, unknown); ErrorCode(err) != "unknown_trustee" {
		t.Fatalf("unknown trustee error = %v", err)
	}
	wrongAggregate := aggregate
	wrongAggregate.Ciphertexts = append([]Ciphertext(nil), aggregate.Ciphertexts...)
	wrongAggregate.Ciphertexts[0], wrongAggregate.Ciphertexts[1] = wrongAggregate.Ciphertexts[1], wrongAggregate.Ciphertexts[0]
	if err := VerifyDecryptionShare(ceremony, aggregateHash, wrongAggregate, shares[0]); ErrorCode(err) != "invalid_decryption_share_proof" {
		t.Fatalf("wrong aggregate error = %v", err)
	}
	mutated := shares[0]
	mutated.Proofs = append([]EqualityProof(nil), shares[0].Proofs...)
	mutated.Proofs[0].Response[0] ^= 1
	if err := VerifyDecryptionShare(ceremony, aggregateHash, aggregate, mutated); ErrorCode(err) != "invalid_decryption_share_proof" {
		t.Fatalf("mutated proof error = %v", err)
	}
}

func TestReferenceVector(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "crypto", "election", "vector.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vector struct {
		PollID            string   `json:"poll_id"`
		ManifestHash      string   `json:"manifest_hash"`
		ElectionKey       string   `json:"election_key"`
		TrusteePublicKeys []string `json:"trustee_public_keys"`
		DealerCommitments []string `json:"dealer_commitments"`
		Ballots           []string `json:"ballots"`
		Aggregate         string   `json:"aggregate"`
		AggregateHash     string   `json:"aggregate_hash"`
		Shares            []string `json:"shares"`
		TallyEvidence     string   `json:"tally_evidence"`
		Totals            []int    `json:"totals"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	contributions := deterministicContributions(t, 3, 2)
	ceremony, secrets, err := finalizeCeremony(contributions)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if hex.EncodeToString(ceremony.ElectionKey[:]) != vector.ElectionKey {
		t.Fatal("election key differs from vector")
	}
	for index, key := range ceremony.TrusteePublicKeys {
		if hex.EncodeToString(key[:]) != vector.TrusteePublicKeys[index] {
			t.Fatalf("trustee public key %d differs", index)
		}
		encoded, err := contributions[index].MarshalPublicCommitment()
		if err != nil || hex.EncodeToString(encoded) != vector.DealerCommitments[index] {
			t.Fatalf("dealer commitment %d differs: %v", index, err)
		}
	}
	var binding Binding
	copy(binding.PollID[:], mustHex(t, vector.PollID, 32))
	copy(binding.ManifestHash[:], mustHex(t, vector.ManifestHash, 32))
	selections := []int{0, 1, 0}
	ballots := make([]EncryptedBallot, len(selections))
	for index, selected := range selections {
		ballots[index], err = EncryptChoice(binding, ceremony.ElectionKey, 2, selected, newHashReader(fmt.Sprintf("reference-ballot-%d", index)))
		if err != nil {
			t.Fatalf("encrypt vector ballot %d: %v", index, err)
		}
		encoded, _ := ballots[index].MarshalBinary()
		if hex.EncodeToString(encoded) != vector.Ballots[index] {
			t.Fatalf("ballot %d differs from vector", index)
		}
		parsed, err := ParseBallot(encoded)
		if err != nil || VerifyBallot(binding, ceremony.ElectionKey, parsed) != nil {
			t.Fatalf("parse ballot %d: %v", index, err)
		}
	}
	aggregate, err := AggregateBallots(binding, ceremony.ElectionKey, ballots)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	aggregateEncoded, _ := aggregate.MarshalBinary()
	if hex.EncodeToString(aggregateEncoded) != vector.Aggregate {
		t.Fatal("aggregate differs from vector")
	}
	parsedAggregate, err := ParseAggregate(aggregateEncoded)
	if err != nil {
		t.Fatalf("parse aggregate: %v", err)
	}
	var aggregateHash [32]byte
	copy(aggregateHash[:], mustHex(t, vector.AggregateHash, 32))
	shares := make([]DecryptionShare, 2)
	for index := range shares {
		shares[index], err = CreateDecryptionShare(ceremony, secrets[index], aggregateHash, parsedAggregate, newHashReader(fmt.Sprintf("reference-share-%d", index)))
		if err != nil {
			t.Fatalf("create share %d: %v", index, err)
		}
		encoded, _ := shares[index].MarshalBinary()
		if hex.EncodeToString(encoded) != vector.Shares[index] {
			t.Fatalf("share %d differs from vector", index)
		}
		if _, err := ParseDecryptionShare(encoded); err != nil {
			t.Fatalf("parse share %d: %v", index, err)
		}
	}
	totals, err := CombineShares(ceremony, aggregateHash, aggregate, shares)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if !reflect.DeepEqual(totals, vector.Totals) {
		t.Fatalf("totals = %v, want %v", totals, vector.Totals)
	}
	evidence, err := CombineTally(ceremony, aggregateHash, aggregate, []DecryptionShare{shares[1], shares[0]})
	if err != nil {
		t.Fatalf("combine evidence: %v", err)
	}
	encodedEvidence, err := evidence.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	if hex.EncodeToString(encodedEvidence) != vector.TallyEvidence {
		t.Fatalf("tally evidence = %x", encodedEvidence)
	}
	parsedEvidence, err := ParseTallyEvidence(encodedEvidence)
	if err != nil || !reflect.DeepEqual(parsedEvidence, evidence) {
		t.Fatalf("parse tally evidence: %v", err)
	}
}

func FuzzArtifactParsers(f *testing.F) {
	contributions := deterministicContributions(f, 3, 2)
	ceremony, secrets, err := finalizeCeremony(contributions)
	if err != nil {
		f.Fatal(err)
	}
	binding := testBinding("fuzz")
	ballot, err := EncryptChoice(binding, ceremony.ElectionKey, 2, 0, newHashReader("fuzz-ballot"))
	if err != nil {
		f.Fatal(err)
	}
	aggregate, err := AggregateBallots(binding, ceremony.ElectionKey, []EncryptedBallot{ballot})
	if err != nil {
		f.Fatal(err)
	}
	share, err := CreateDecryptionShare(ceremony, secrets[0], digest32("fuzz-aggregate"), aggregate, newHashReader("fuzz-share"))
	if err != nil {
		f.Fatal(err)
	}
	ballotBytes, _ := ballot.MarshalBinary()
	aggregateBytes, _ := aggregate.MarshalBinary()
	shareBytes, _ := share.MarshalBinary()
	publicBytes, _ := contributions[0].MarshalPublicCommitment()
	dealerShare, _ := contributions[0].ShareFor(1)
	dealerShareBytes, _ := dealerShare.MarshalBinary()
	_, err = CombineTally(ceremony, digest32("fuzz-aggregate"), aggregate, []DecryptionShare{share})
	if ErrorCode(err) != "insufficient_decryption_shares" {
		f.Fatalf("single-share evidence error = %v", err)
	}
	secondShare, err := CreateDecryptionShare(ceremony, secrets[1], digest32("fuzz-aggregate"), aggregate, newHashReader("fuzz-share-2"))
	if err != nil {
		f.Fatal(err)
	}
	evidence, err := CombineTally(ceremony, digest32("fuzz-aggregate"), aggregate, []DecryptionShare{share, secondShare})
	if err != nil {
		f.Fatal(err)
	}
	evidenceBytes, _ := evidence.MarshalBinary()
	f.Add(byte(0), ballotBytes)
	f.Add(byte(1), aggregateBytes)
	f.Add(byte(2), shareBytes)
	f.Add(byte(3), publicBytes)
	f.Add(byte(4), dealerShareBytes)
	f.Add(byte(5), evidenceBytes)
	f.Fuzz(func(t *testing.T, kind byte, data []byte) {
		switch kind % 6 {
		case 0:
			if parsed, err := ParseBallot(data); err == nil {
				_ = VerifyBallot(binding, ceremony.ElectionKey, parsed)
			}
		case 1:
			_, _ = ParseAggregate(data)
		case 2:
			if parsed, err := ParseDecryptionShare(data); err == nil {
				_ = VerifyDecryptionShare(ceremony, digest32("fuzz-aggregate"), aggregate, parsed)
			}
		case 3:
			_, _ = ParsePublicContribution(data)
		case 4:
			if parsed, err := ParseDealerShare(data); err == nil {
				_ = VerifyDealerShare(contributions[0].Public(), 3, parsed)
			}
		case 5:
			_, _ = ParseTallyEvidence(data)
		}
	})
}

func BenchmarkBallotProof(b *testing.B) {
	ceremony, _ := deterministicCeremony(b, 3, 2)
	binding := testBinding("benchmark")
	ballot, err := EncryptChoice(binding, ceremony.ElectionKey, MaxChoices, 4, newHashReader("benchmark-ballot"))
	if err != nil {
		b.Fatal(err)
	}
	b.Run("encrypt_10_choices", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := EncryptChoice(binding, ceremony.ElectionKey, MaxChoices, 4, newHashReader("benchmark-ballot")); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("verify_10_choices", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := VerifyBallot(binding, ceremony.ElectionKey, ballot); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkThresholdTally(b *testing.B) {
	ceremony, secrets := deterministicCeremony(b, 3, 2)
	binding := testBinding("benchmark-tally")
	ballots := make([]EncryptedBallot, MaxBallots)
	for index := range ballots {
		var err error
		ballots[index], err = EncryptChoice(binding, ceremony.ElectionKey, 2, index%2, newHashReader(fmt.Sprintf("benchmark-vote-%d", index)))
		if err != nil {
			b.Fatal(err)
		}
	}
	aggregate, err := AggregateBallots(binding, ceremony.ElectionKey, ballots)
	if err != nil {
		b.Fatal(err)
	}
	aggregateHash := digest32("benchmark-aggregate")
	shares := make([]DecryptionShare, 2)
	for index := range shares {
		shares[index], err = CreateDecryptionShare(ceremony, secrets[index], aggregateHash, aggregate, newHashReader(fmt.Sprintf("benchmark-share-%d", index)))
		if err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := CombineShares(ceremony, aggregateHash, aggregate, shares); err != nil {
			b.Fatal(err)
		}
	}
}

func deterministicContributions(tb testing.TB, trusteeCount, quorum int) []DealerContribution {
	tb.Helper()
	contributions := make([]DealerContribution, trusteeCount)
	for index := 1; index <= trusteeCount; index++ {
		contribution, err := GenerateDealerContribution(index, trusteeCount, quorum, newHashReader(fmt.Sprintf("dealer-%d", index)))
		if err != nil {
			tb.Fatalf("generate dealer %d: %v", index, err)
		}
		contributions[index-1] = contribution
	}
	return contributions
}

func deterministicCeremony(tb testing.TB, trusteeCount, quorum int) (Ceremony, []TrusteeSecretShare) {
	tb.Helper()
	ceremony, shares, err := finalizeCeremony(deterministicContributions(tb, trusteeCount, quorum))
	if err != nil {
		tb.Fatalf("finalize ceremony: %v", err)
	}
	return ceremony, shares
}

func cloneContribution(value DealerContribution) DealerContribution {
	value.Commitments = append([]Point(nil), value.Commitments...)
	value.shares = append([]Scalar(nil), value.shares...)
	return value
}

func cloneBallot(value EncryptedBallot) EncryptedBallot {
	value.Ciphertexts = append([]Ciphertext(nil), value.Ciphertexts...)
	value.Proof.Bits = append([]BitProof(nil), value.Proof.Bits...)
	return value
}

func encryptBitsForTest(tb testing.TB, binding Binding, electionKey Point, values []int) EncryptedBallot {
	tb.Helper()
	publicKey, err := decodePublicPoint(electionKey)
	if err != nil {
		tb.Fatal(err)
	}
	ballot := EncryptedBallot{
		Ciphertexts: make([]Ciphertext, len(values)),
		Proof:       ValidityProof{Bits: make([]BitProof, len(values))},
	}
	sumRandomness := ristretto255.NewScalar()
	for index, value := range values {
		randomness, err := randomScalar(newHashReader(fmt.Sprintf("invalid-bit-%d-%d", index, value)))
		if err != nil {
			tb.Fatal(err)
		}
		ballot.Ciphertexts[index] = encryptBit(publicKey, randomness, value)
		ballot.Proof.Bits[index], err = proveBit(binding, electionKey, ballot.Ciphertexts[index], index, value, randomness, newHashReader(fmt.Sprintf("invalid-proof-%d-%d", index, value)))
		if err != nil {
			tb.Fatal(err)
		}
		sumRandomness.Add(sumRandomness, randomness)
	}
	sum, err := sumCiphertexts(ballot.Ciphertexts)
	if err != nil {
		tb.Fatal(err)
	}
	a, _ := decodePoint(sum.A)
	b, _ := decodePoint(sum.B)
	ballot.Proof.Sum, err = proveEquality(
		"vota:v1:choice-sum-proof",
		sumProofFields(binding, electionKey, sum),
		ristretto255.NewGeneratorElement(), publicKey,
		a, subtractPoints(b, ristretto255.NewGeneratorElement()),
		sumRandomness, newHashReader("invalid-sum-proof"),
	)
	if err != nil {
		tb.Fatal(err)
	}
	return ballot
}

func testBinding(seed string) Binding {
	return Binding{PollID: digest32(seed), ManifestHash: digest32(seed + "-manifest")}
}

func digest32(value string) [32]byte {
	digest := sha512.Sum512([]byte(value))
	var result [32]byte
	copy(result[:], digest[:32])
	return result
}

func mustHex(tb testing.TB, value string, length int) []byte {
	tb.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != length {
		tb.Fatalf("decode %d-byte hex: %v", length, err)
	}
	return decoded
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
