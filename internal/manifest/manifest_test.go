package manifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cirocosta/vota/internal/crypto/election"
	"github.com/cirocosta/vota/internal/crypto/lrs"
	"github.com/cirocosta/vota/internal/protocol"
)

func TestFreezeIsCanonicalAndImmutable(t *testing.T) {
	t.Parallel()

	draft, authorityPrivateKey := completeDraft(t)
	first, err := Freeze(draft, authorityPrivateKey)
	if err != nil {
		t.Fatalf("freeze first: %v", err)
	}
	firstBytes, err := first.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal first: %v", err)
	}
	fixture, err := os.ReadFile(filepath.Join("..", "..", "testdata", "manifest", "canonical.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	fixture = bytes.TrimSpace(fixture)
	if !bytes.Equal(firstBytes, fixture) {
		t.Fatalf("manifest differs from canonical fixture:\n%s", firstBytes)
	}

	reordered := cloneDraft(draft)
	slices.Reverse(reordered.Choices)
	slices.Reverse(reordered.Trustees)
	slices.Reverse(reordered.Enrollments)
	reordered.OpensAt = reordered.OpensAt.In(time.FixedZone("offset", -4*60*60))
	reordered.ClosesAt = reordered.ClosesAt.In(time.FixedZone("offset", -4*60*60))
	second, err := Freeze(reordered, authorityPrivateKey)
	if err != nil {
		t.Fatalf("freeze reordered: %v", err)
	}
	secondBytes, _ := second.MarshalCanonical()
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatalf("canonical manifests differ:\n%s\n%s", firstBytes, secondBytes)
	}

	manifest := first.Manifest()
	if !manifest.ExperimentalNotForElections {
		t.Fatal("experimental warning is false")
	}
	if err := Verify(manifest); err != nil {
		t.Fatalf("verify: %v", err)
	}
	parsed, err := Parse(firstBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	parsedManifest := parsed.Manifest()
	if parsedManifest.PollID != manifest.PollID {
		t.Fatal("poll ID changed after parse")
	}

	manifest.Question = "mutated"
	manifest.Choices[0].Label = "mutated"
	if err := Verify(manifest); ErrorCode(err) != "poll_draft_id_mismatch" {
		t.Fatalf("mutated manifest error = %v", err)
	}
	if first.Manifest().Question == "mutated" || first.Manifest().Choices[0].Label == "mutated" {
		t.Fatal("frozen manifest was changed through returned copy")
	}
}

func TestEnrollmentProofBindsDraftAndKey(t *testing.T) {
	t.Parallel()

	draft, _ := baseDraft(t)
	draftID, err := DraftID(draft)
	if err != nil {
		t.Fatalf("draft ID: %v", err)
	}
	privateKey, _, err := lrs.GenerateKey(newHashReader("voter"))
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	enrollment, err := CreateEnrollment(draftID, privateKey, newHashReader("enrollment"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := VerifyEnrollment(enrollment); err != nil {
		t.Fatalf("verify: %v", err)
	}
	mutated := enrollment
	mutated.Proof = mutated.Proof[:len(mutated.Proof)-2] + "00"
	if err := VerifyEnrollment(mutated); ErrorCode(err) != "invalid_enrollment_proof" {
		t.Fatalf("proof mutation error = %v", err)
	}
	mutated = enrollment
	mutated.PollDraftID = "sha256:" + fmt.Sprintf("%064x", 1)
	if err := VerifyEnrollment(mutated); ErrorCode(err) != "invalid_enrollment_proof" {
		t.Fatalf("draft mutation error = %v", err)
	}
}

func TestVerifyEnrollmentRejectsUppercaseHex(t *testing.T) {
	t.Parallel()

	draft, _ := baseDraft(t)
	draftID, err := DraftID(draft)
	if err != nil {
		t.Fatalf("draft ID: %v", err)
	}
	privateKey, _, err := lrs.GenerateKey(newHashReader("uppercase-enrollment-voter"))
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	enrollment, err := CreateEnrollment(draftID, privateKey, newHashReader("uppercase-enrollment-proof"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	tests := []struct {
		name   string
		change func(*protocol.Enrollment)
		code   string
	}{
		{"draft id", func(value *protocol.Enrollment) {
			prefix, payload, _ := strings.Cut(value.PollDraftID, ":")
			value.PollDraftID = prefix + ":" + strings.ToUpper(payload)
		}, "invalid_draft_id"},
		{"eligibility key", func(value *protocol.Enrollment) {
			prefix, payload, _ := strings.Cut(value.EligibilityKey, ":")
			value.EligibilityKey = prefix + ":" + strings.ToUpper(payload)
		}, "invalid_eligibility_key"},
		{"proof", func(value *protocol.Enrollment) {
			prefix, payload, _ := strings.Cut(value.Proof, ":")
			value.Proof = prefix + ":" + strings.ToUpper(payload)
		}, "invalid_enrollment_proof"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := enrollment
			test.change(&mutated)
			if err := VerifyEnrollment(mutated); ErrorCode(err) != test.code {
				t.Fatalf("verify error = %v, want %s", err, test.code)
			}
		})
	}
}

func TestDraftBoundaryTable(t *testing.T) {
	t.Parallel()

	complete, authorityPrivateKey := completeDraft(t)
	tests := []struct {
		name   string
		change func(*Draft)
		code   string
	}{
		{"one choice", func(draft *Draft) { draft.Choices = draft.Choices[:1] }, "invalid_choice_count"},
		{"eleven choices", func(draft *Draft) {
			for len(draft.Choices) < 11 {
				index := len(draft.Choices)
				draft.Choices = append(draft.Choices, protocol.Choice{ID: fmt.Sprintf("c%02d", index), Label: "Choice"})
			}
		}, "invalid_choice_count"},
		{"one voter", func(draft *Draft) { draft.Enrollments = draft.Enrollments[:1] }, "invalid_eligibility_count"},
		{"quorum one", func(draft *Draft) { draft.TrusteeQuorum = 1 }, "invalid_trustee_quorum"},
		{"privacy one", func(draft *Draft) { draft.PrivacyThreshold = 1 }, "invalid_privacy_threshold"},
		{"reversed window", func(draft *Draft) { draft.ClosesAt = draft.OpensAt }, "invalid_poll_window"},
		{"duplicate voter", func(draft *Draft) { draft.Enrollments[1] = draft.Enrollments[0] }, "duplicate_eligibility_key"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			draft := cloneDraft(complete)
			test.change(&draft)
			_, err := Freeze(draft, authorityPrivateKey)
			if ErrorCode(err) != test.code {
				t.Fatalf("error = %v, code = %q, want %q", err, ErrorCode(err), test.code)
			}
		})
	}
}

func TestAcceptedSizeBoundaries(t *testing.T) {
	if testing.Short() {
		t.Skip("maximum boundary creates 256 enrollment proofs")
	}

	tests := []struct {
		name     string
		voters   int
		choices  int
		trustees int
		quorum   int
	}{
		{"minimum", 2, 2, 2, 2},
		{"maximum", 256, 10, 9, 9},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			draft, authorityPrivateKey := sizedDraft(t, test.voters, test.choices, test.trustees, test.quorum)
			frozen, err := Freeze(draft, authorityPrivateKey)
			if err != nil {
				t.Fatalf("freeze: %v", err)
			}
			manifest := frozen.Manifest()
			if len(manifest.EligibleKeys) != test.voters || len(manifest.Choices) != test.choices || len(manifest.Trustees.Members) != test.trustees {
				t.Fatalf("manifest sizes = voters %d, choices %d, trustees %d", len(manifest.EligibleKeys), len(manifest.Choices), len(manifest.Trustees.Members))
			}
		})
	}
}

func TestVerifyRejectsCeremonyMutation(t *testing.T) {
	t.Parallel()

	draft, authorityPrivateKey := completeDraft(t)
	frozen, err := Freeze(draft, authorityPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	manifest := frozen.Manifest()
	manifest.Trustees.ElectionPublicKey = "ristretto255:" + fmt.Sprintf("%064x", 1)
	if err := Verify(manifest); ErrorCode(err) != "poll_draft_id_mismatch" {
		t.Fatalf("election key error = %v", err)
	}
}

func TestVerifyRejectsUppercaseOpaqueCommitment(t *testing.T) {
	t.Parallel()

	draft, authorityPrivateKey := completeDraft(t)
	frozen, err := Freeze(draft, authorityPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	value := frozen.Manifest()
	prefix, payload, ok := strings.Cut(value.Trustees.Members[0].Commitment, ":")
	if !ok {
		t.Fatal("commitment missing prefix")
	}
	value.Trustees.Members[0].Commitment = prefix + ":" + strings.ToUpper(payload)
	value.PollDraftID, err = manifestDraftID(value)
	if err != nil {
		t.Fatal(err)
	}
	value.PollID, err = pollID(value)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signManifest(authorityPrivateKey, value)
	if err != nil {
		t.Fatal(err)
	}
	value.AuthoritySignature = "ed25519sig:" + hex.EncodeToString(signature)
	if err := Verify(value); ErrorCode(err) != "invalid_trustee_commitment" {
		t.Fatalf("verify error = %v", err)
	}
}

func completeDraft(tb testing.TB) (Draft, ed25519.PrivateKey) {
	tb.Helper()
	draft, authorityPrivateKey := baseDraft(tb)
	draftID, err := DraftID(draft)
	if err != nil {
		tb.Fatalf("draft ID: %v", err)
	}
	for index := range 3 {
		privateKey, _, err := lrs.GenerateKey(newHashReader(fmt.Sprintf("voter-%d", index)))
		if err != nil {
			tb.Fatalf("voter key %d: %v", index, err)
		}
		enrollment, err := CreateEnrollment(draftID, privateKey, newHashReader(fmt.Sprintf("enrollment-%d", index)))
		if err != nil {
			tb.Fatalf("enrollment %d: %v", index, err)
		}
		draft.Enrollments = append(draft.Enrollments, enrollment)
	}
	return draft, authorityPrivateKey
}

func baseDraft(tb testing.TB) (Draft, ed25519.PrivateKey) {
	tb.Helper()
	authorityPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	trustees := make([]Trustee, 3)
	for index := range 3 {
		contribution, err := election.GenerateDealerContribution(index+1, 3, 2, newHashReader(fmt.Sprintf("dealer-%d", index)))
		if err != nil {
			tb.Fatalf("dealer %d: %v", index, err)
		}
		signingKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(0x51 + index)}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
		trustees[index] = Trustee{
			ID:           fmt.Sprintf("trustee-%d", index+1),
			SigningKey:   signingKey,
			Contribution: contribution.Public(),
		}
	}
	return Draft{
		Question: "Which release color?",
		Choices: []protocol.Choice{
			{ID: "green", Label: "Green"},
			{ID: "blue", Label: "Blue"},
		},
		Trustees:         trustees,
		TrusteeQuorum:    2,
		PrivacyThreshold: 2,
		OpensAt:          time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
		ClosesAt:         time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC),
		AuthorityKey:     authorityPrivateKey.Public().(ed25519.PublicKey),
	}, authorityPrivateKey
}

func sizedDraft(tb testing.TB, voterCount, choiceCount, trusteeCount, quorum int) (Draft, ed25519.PrivateKey) {
	tb.Helper()
	authorityPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize))
	trustees := make([]Trustee, trusteeCount)
	for index := range trusteeCount {
		contribution, err := election.GenerateDealerContribution(index+1, trusteeCount, quorum, newHashReader(fmt.Sprintf("sized-dealer-%d", index)))
		if err != nil {
			tb.Fatalf("dealer %d: %v", index, err)
		}
		signingKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(0x70 + index)}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
		trustees[index] = Trustee{ID: fmt.Sprintf("trustee-%02d", index+1), SigningKey: signingKey, Contribution: contribution.Public()}
	}
	choices := make([]protocol.Choice, choiceCount)
	for index := range choiceCount {
		choices[index] = protocol.Choice{ID: fmt.Sprintf("choice-%02d", index+1), Label: fmt.Sprintf("Choice %d", index+1)}
	}
	draft := Draft{
		Question:         "Boundary poll",
		Choices:          choices,
		Trustees:         trustees,
		TrusteeQuorum:    quorum,
		PrivacyThreshold: min(voterCount, 2),
		OpensAt:          time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
		ClosesAt:         time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC),
		AuthorityKey:     authorityPrivateKey.Public().(ed25519.PublicKey),
	}
	draftID, err := DraftID(draft)
	if err != nil {
		tb.Fatalf("draft ID: %v", err)
	}
	for index := range voterCount {
		privateKey, _, err := lrs.GenerateKey(newHashReader(fmt.Sprintf("sized-voter-%d", index)))
		if err != nil {
			tb.Fatalf("voter %d: %v", index, err)
		}
		enrollment, err := CreateEnrollment(draftID, privateKey, newHashReader(fmt.Sprintf("sized-enrollment-%d", index)))
		if err != nil {
			tb.Fatalf("enrollment %d: %v", index, err)
		}
		draft.Enrollments = append(draft.Enrollments, enrollment)
	}
	return draft, authorityPrivateKey
}

func cloneDraft(draft Draft) Draft {
	draft.Choices = append([]protocol.Choice(nil), draft.Choices...)
	draft.Enrollments = append([]protocol.Enrollment(nil), draft.Enrollments...)
	draft.Trustees = append([]Trustee(nil), draft.Trustees...)
	return draft
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
