// Package manifest creates and verifies immutable Vota poll manifests.
package manifest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cirocosta/vota/internal/crypto/election"
	"github.com/cirocosta/vota/internal/protocol"
)

type Trustee struct {
	ID           string
	SigningKey   ed25519.PublicKey
	Contribution election.PublicContribution
}

type Draft struct {
	Question         string
	Choices          []protocol.Choice
	Enrollments      []protocol.Enrollment
	Trustees         []Trustee
	TrusteeQuorum    int
	PrivacyThreshold int
	OpensAt          time.Time
	ClosesAt         time.Time
	AuthorityKey     ed25519.PublicKey
}

type Frozen struct {
	manifest protocol.Manifest
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

func (e *Error) Unwrap() error { return e.Err }

func ErrorCode(err error) string {
	var target *Error
	if errors.As(err, &target) {
		return target.Code
	}
	return protocol.ErrorCode(err)
}

// DraftID returns the stable identifier enrollment proofs must bind to.
func DraftID(draft Draft) (string, error) {
	identity, err := draftIdentityFor(draft)
	if err != nil {
		return "", err
	}
	value, err := protocol.HashCanonical(protocol.DomainPollDraftID, identity)
	if err != nil {
		return "", &Error{Code: "draft_id_failed", Err: err}
	}
	return value, nil
}

// Freeze verifies enrollments and signs one canonical immutable manifest.
func Freeze(draft Draft, authorityPrivateKey ed25519.PrivateKey) (Frozen, error) {
	if len(authorityPrivateKey) != ed25519.PrivateKeySize {
		return Frozen{}, &Error{Code: "invalid_authority_private_key"}
	}
	public := authorityPrivateKey.Public().(ed25519.PublicKey)
	if !public.Equal(draft.AuthorityKey) {
		return Frozen{}, &Error{Code: "wrong_authority_private_key"}
	}
	if len(draft.Enrollments) < protocol.MinEligibleKeys || len(draft.Enrollments) > protocol.MaxEligibleKeys {
		return Frozen{}, &Error{Code: "invalid_eligibility_count"}
	}
	if draft.PrivacyThreshold < protocol.MinPrivacyThreshold || draft.PrivacyThreshold > len(draft.Enrollments) {
		return Frozen{}, &Error{Code: "invalid_privacy_threshold"}
	}
	draftID, err := DraftID(draft)
	if err != nil {
		return Frozen{}, err
	}

	eligibleKeys := make([]string, len(draft.Enrollments))
	for index, enrollment := range draft.Enrollments {
		if enrollment.PollDraftID != draftID {
			return Frozen{}, &Error{Code: "wrong_draft_enrollment", Err: fmt.Errorf("index %d", index)}
		}
		if err := VerifyEnrollment(enrollment); err != nil {
			return Frozen{}, &Error{Code: "invalid_enrollment", Err: fmt.Errorf("index %d: %w", index, err)}
		}
		eligibleKeys[index] = enrollment.EligibilityKey
	}
	slices.Sort(eligibleKeys)
	for index := 1; index < len(eligibleKeys); index++ {
		if eligibleKeys[index] == eligibleKeys[index-1] {
			return Frozen{}, &Error{Code: "duplicate_eligibility_key"}
		}
	}

	identity, err := draftIdentityFor(draft)
	if err != nil {
		return Frozen{}, err
	}
	manifest := protocol.Manifest{
		SchemaVersion:               protocol.SchemaVersion,
		Protocol:                    protocol.ProtocolVersion,
		EligibilityScheme:           protocol.EligibilityScheme,
		PollDraftID:                 draftID,
		Question:                    identity.Question,
		Choices:                     identity.Choices,
		EligibleKeys:                eligibleKeys,
		Trustees:                    identity.Trustees,
		PrivacyThreshold:            identity.PrivacyThreshold,
		OpensAt:                     identity.OpensAt,
		ClosesAt:                    identity.ClosesAt,
		AuthorityKey:                identity.AuthorityKey,
		ExperimentalNotForElections: true,
	}
	manifest.PollID, err = pollID(manifest)
	if err != nil {
		return Frozen{}, err
	}
	signature, err := signManifest(authorityPrivateKey, manifest)
	if err != nil {
		return Frozen{}, err
	}
	manifest.AuthoritySignature = "ed25519sig:" + hex.EncodeToString(signature)
	if err := Verify(manifest); err != nil {
		return Frozen{}, err
	}
	return Frozen{manifest: cloneManifest(manifest)}, nil
}

// Parse verifies a public manifest and returns an immutable wrapper.
func Parse(encoded []byte) (Frozen, error) {
	var manifest protocol.Manifest
	if err := protocol.DecodeStrict(encoded, &manifest); err != nil {
		return Frozen{}, &Error{Code: "invalid_manifest", Err: err}
	}
	if err := Verify(manifest); err != nil {
		return Frozen{}, err
	}
	return Frozen{manifest: cloneManifest(manifest)}, nil
}

// Verify checks shape, poll ID, and authority signature.
func Verify(manifest protocol.Manifest) error {
	if err := protocol.ValidateManifest(manifest); err != nil {
		return &Error{Code: protocol.ErrorCode(err), Err: err}
	}
	expectedDraftID, err := manifestDraftID(manifest)
	if err != nil {
		return err
	}
	if manifest.PollDraftID != expectedDraftID {
		return &Error{Code: "poll_draft_id_mismatch"}
	}
	if !slices.IsSortedFunc(manifest.Choices, func(left, right protocol.Choice) int { return strings.Compare(left.ID, right.ID) }) {
		return &Error{Code: "noncanonical_choice_order"}
	}
	if !slices.IsSortedFunc(manifest.Trustees.Members, func(left, right protocol.Trustee) int { return strings.Compare(left.ID, right.ID) }) {
		return &Error{Code: "noncanonical_trustee_order"}
	}
	if err := verifyTrusteeCeremony(manifest.Trustees); err != nil {
		return err
	}
	expectedPollID, err := pollID(manifest)
	if err != nil {
		return err
	}
	if manifest.PollID != expectedPollID {
		return &Error{Code: "poll_id_mismatch"}
	}
	publicKey, err := decodePrefixed("ed25519", manifest.AuthorityKey, ed25519.PublicKeySize)
	if err != nil {
		return &Error{Code: "invalid_authority_key", Err: err}
	}
	signature, err := decodePrefixed("ed25519sig", manifest.AuthoritySignature, ed25519.SignatureSize)
	if err != nil {
		return &Error{Code: "invalid_authority_signature", Err: err}
	}
	message, err := manifestSignatureMessage(manifest)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return &Error{Code: "invalid_authority_signature"}
	}
	return nil
}

func verifyTrusteeCeremony(set protocol.TrusteeSet) error {
	contributions := make([]election.PublicContribution, len(set.Members))
	for index, trustee := range set.Members {
		payload, ok := strings.CutPrefix(trustee.Commitment, "vota-ceremony-commitment-v1:")
		if !ok {
			return &Error{Code: "invalid_trustee_commitment"}
		}
		encoded, err := hex.DecodeString(payload)
		if err != nil {
			return &Error{Code: "invalid_trustee_commitment", Err: err}
		}
		contributions[index], err = election.ParsePublicContribution(encoded)
		if err != nil {
			return &Error{Code: "invalid_trustee_commitment", Err: err}
		}
	}
	ceremony, err := election.FinalizePublicCeremony(contributions)
	if err != nil || ceremony.Quorum != set.Quorum {
		return &Error{Code: "invalid_trustee_ceremony", Err: err}
	}
	expectedKey := "ristretto255:" + hex.EncodeToString(ceremony.ElectionKey[:])
	if set.ElectionPublicKey != expectedKey {
		return &Error{Code: "election_key_mismatch"}
	}
	return nil
}

// Manifest returns a deep copy of the frozen manifest.
func (frozen Frozen) Manifest() protocol.Manifest {
	return cloneManifest(frozen.manifest)
}

// MarshalCanonical returns the verified canonical public artifact.
func (frozen Frozen) MarshalCanonical() ([]byte, error) {
	if err := Verify(frozen.manifest); err != nil {
		return nil, err
	}
	encoded, err := protocol.MarshalCanonical(frozen.manifest)
	if err != nil {
		return nil, &Error{Code: "manifest_encode_failed", Err: err}
	}
	return encoded, nil
}

type draftIdentity struct {
	SchemaVersion               int                 `json:"schema_version"`
	Protocol                    string              `json:"protocol"`
	EligibilityScheme           string              `json:"eligibility_scheme"`
	Question                    string              `json:"question"`
	Choices                     []protocol.Choice   `json:"choices"`
	Trustees                    protocol.TrusteeSet `json:"trustees"`
	PrivacyThreshold            int                 `json:"privacy_threshold"`
	OpensAt                     string              `json:"opens_at"`
	ClosesAt                    string              `json:"closes_at"`
	AuthorityKey                string              `json:"authority_key"`
	ExperimentalNotForElections bool                `json:"experimental_not_for_real_elections"`
}

func draftIdentityFor(draft Draft) (draftIdentity, error) {
	if len(draft.AuthorityKey) != ed25519.PublicKeySize {
		return draftIdentity{}, &Error{Code: "invalid_authority_key"}
	}
	if strings.TrimSpace(draft.Question) == "" || len(draft.Question) > 500 {
		return draftIdentity{}, &Error{Code: "invalid_question"}
	}
	if len(draft.Choices) < protocol.MinChoices || len(draft.Choices) > protocol.MaxChoices {
		return draftIdentity{}, &Error{Code: "invalid_choice_count"}
	}
	if draft.OpensAt.IsZero() || draft.ClosesAt.IsZero() || !draft.OpensAt.Before(draft.ClosesAt) {
		return draftIdentity{}, &Error{Code: "invalid_poll_window"}
	}
	choices := append([]protocol.Choice(nil), draft.Choices...)
	slices.SortFunc(choices, func(left, right protocol.Choice) int { return strings.Compare(left.ID, right.ID) })
	for index := 1; index < len(choices); index++ {
		if choices[index].ID == choices[index-1].ID {
			return draftIdentity{}, &Error{Code: "duplicate_choice_id"}
		}
	}
	trustees, err := buildTrusteeSet(draft.Trustees, draft.TrusteeQuorum)
	if err != nil {
		return draftIdentity{}, err
	}
	return draftIdentity{
		SchemaVersion:               protocol.SchemaVersion,
		Protocol:                    protocol.ProtocolVersion,
		EligibilityScheme:           protocol.EligibilityScheme,
		Question:                    draft.Question,
		Choices:                     choices,
		Trustees:                    trustees,
		PrivacyThreshold:            draft.PrivacyThreshold,
		OpensAt:                     draft.OpensAt.UTC().Format(time.RFC3339),
		ClosesAt:                    draft.ClosesAt.UTC().Format(time.RFC3339),
		AuthorityKey:                "ed25519:" + hex.EncodeToString(draft.AuthorityKey),
		ExperimentalNotForElections: true,
	}, nil
}

func buildTrusteeSet(trustees []Trustee, quorum int) (protocol.TrusteeSet, error) {
	if len(trustees) < election.MinTrustees || len(trustees) > election.MaxTrustees {
		return protocol.TrusteeSet{}, &Error{Code: "invalid_trustee_count"}
	}
	if quorum < election.MinTrustees || quorum > len(trustees) {
		return protocol.TrusteeSet{}, &Error{Code: "invalid_trustee_quorum"}
	}
	trustees = append([]Trustee(nil), trustees...)
	slices.SortFunc(trustees, func(left, right Trustee) int { return strings.Compare(left.ID, right.ID) })
	publicContributions := make([]election.PublicContribution, len(trustees))
	byDealer := make(map[uint16]Trustee, len(trustees))
	for _, trustee := range trustees {
		if _, exists := byDealer[trustee.Contribution.DealerIndex]; exists {
			return protocol.TrusteeSet{}, &Error{Code: "duplicate_trustee_contribution"}
		}
		byDealer[trustee.Contribution.DealerIndex] = trustee
	}
	for index := 1; index <= len(trustees); index++ {
		trustee, exists := byDealer[uint16(index)]
		if !exists {
			return protocol.TrusteeSet{}, &Error{Code: "invalid_trustee_contribution"}
		}
		publicContributions[index-1] = trustee.Contribution
	}
	ceremony, err := election.FinalizePublicCeremony(publicContributions)
	if err != nil || ceremony.Quorum != quorum {
		return protocol.TrusteeSet{}, &Error{Code: "invalid_trustee_ceremony", Err: err}
	}
	members := make([]protocol.Trustee, len(trustees))
	for index, trustee := range trustees {
		if len(trustee.SigningKey) != ed25519.PublicKeySize {
			return protocol.TrusteeSet{}, &Error{Code: "invalid_trustee_signing_key"}
		}
		commitment, err := trustee.Contribution.MarshalBinary()
		if err != nil {
			return protocol.TrusteeSet{}, &Error{Code: "invalid_trustee_commitment", Err: err}
		}
		members[index] = protocol.Trustee{
			ID:         trustee.ID,
			SigningKey: "ed25519:" + hex.EncodeToString(trustee.SigningKey),
			Commitment: "vota-ceremony-commitment-v1:" + hex.EncodeToString(commitment),
		}
	}
	return protocol.TrusteeSet{
		Quorum:            quorum,
		Members:           members,
		ElectionPublicKey: "ristretto255:" + hex.EncodeToString(ceremony.ElectionKey[:]),
	}, nil
}

func pollID(manifest protocol.Manifest) (string, error) {
	unsigned := cloneManifest(manifest)
	unsigned.PollID = ""
	unsigned.AuthoritySignature = ""
	value, err := protocol.HashCanonical(protocol.DomainPollID, unsigned)
	if err != nil {
		return "", &Error{Code: "poll_id_failed", Err: err}
	}
	return value, nil
}

func manifestDraftID(manifest protocol.Manifest) (string, error) {
	identity := draftIdentity{
		SchemaVersion:               manifest.SchemaVersion,
		Protocol:                    manifest.Protocol,
		EligibilityScheme:           manifest.EligibilityScheme,
		Question:                    manifest.Question,
		Choices:                     append([]protocol.Choice(nil), manifest.Choices...),
		Trustees:                    manifest.Trustees,
		PrivacyThreshold:            manifest.PrivacyThreshold,
		OpensAt:                     manifest.OpensAt,
		ClosesAt:                    manifest.ClosesAt,
		AuthorityKey:                manifest.AuthorityKey,
		ExperimentalNotForElections: manifest.ExperimentalNotForElections,
	}
	value, err := protocol.HashCanonical(protocol.DomainPollDraftID, identity)
	if err != nil {
		return "", &Error{Code: "draft_id_failed", Err: err}
	}
	return value, nil
}

func signManifest(privateKey ed25519.PrivateKey, manifest protocol.Manifest) ([]byte, error) {
	message, err := manifestSignatureMessage(manifest)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(privateKey, message), nil
}

func manifestSignatureMessage(manifest protocol.Manifest) ([]byte, error) {
	unsigned := cloneManifest(manifest)
	unsigned.AuthoritySignature = ""
	canonical, err := protocol.MarshalCanonical(unsigned)
	if err != nil {
		return nil, &Error{Code: "manifest_encode_failed", Err: err}
	}
	pollIDBytes, err := decodePrefixed("sha256", manifest.PollID, sha256.Size)
	if err != nil {
		return nil, &Error{Code: "invalid_poll_id", Err: err}
	}
	message := append([]byte(protocol.DomainManifestSignature), 0)
	message = appendField(message, pollIDBytes)
	message = appendField(message, canonical)
	return message, nil
}

func appendField(output, value []byte) []byte {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	output = append(output, length[:]...)
	return append(output, value...)
}

func decodePrefixed(prefix, value string, length int) ([]byte, error) {
	payload, ok := strings.CutPrefix(value, prefix+":")
	if !ok {
		return nil, fmt.Errorf("expected %s prefix", prefix)
	}
	decoded, err := hex.DecodeString(payload)
	if err != nil || len(decoded) != length {
		return nil, fmt.Errorf("expected %d-byte %s value", length, prefix)
	}
	return decoded, nil
}

func cloneManifest(manifest protocol.Manifest) protocol.Manifest {
	manifest.Choices = append([]protocol.Choice(nil), manifest.Choices...)
	manifest.EligibleKeys = append([]string(nil), manifest.EligibleKeys...)
	manifest.Trustees.Members = append([]protocol.Trustee(nil), manifest.Trustees.Members...)
	return manifest
}
