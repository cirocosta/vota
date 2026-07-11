package protocol

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

var identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

type ValidationError struct {
	Code    string
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s: %s", e.Code, e.Field, e.Message)
}

func validationError(code, field, message string) error {
	return &ValidationError{Code: code, Field: field, Message: message}
}

func ErrorCode(err error) string {
	var target *ValidationError
	if errors.As(err, &target) {
		return target.Code
	}
	return "internal_error"
}

func ValidateDomain(domain string) error {
	for _, allowed := range DomainSeparators() {
		if domain == allowed {
			return nil
		}
	}
	return validationError("unknown_domain", "domain", "domain separator is not registered")
}

func ValidateManifest(manifest Manifest) error {
	if err := validateHeader(manifest.SchemaVersion, manifest.Protocol); err != nil {
		return err
	}
	if manifest.EligibilityScheme != EligibilityScheme {
		return validationError("unsupported_eligibility_scheme", "eligibility_scheme", manifest.EligibilityScheme)
	}
	if err := validateEncoded("sha256", 32, manifest.PollDraftID); err != nil {
		return validationError("invalid_poll_draft_id", "poll_draft_id", err.Error())
	}
	if !manifest.ExperimentalNotForElections {
		return validationError("missing_experimental_warning", "experimental_not_for_real_elections", "must be true")
	}
	if strings.TrimSpace(manifest.Question) == "" || len(manifest.Question) > 500 {
		return validationError("invalid_question", "question", "question must contain 1 to 500 bytes")
	}
	if len(manifest.Choices) < MinChoices || len(manifest.Choices) > MaxChoices {
		return validationError("invalid_choice_count", "choices", "choice count must be between 2 and 10")
	}
	seenChoice := make(map[string]struct{}, len(manifest.Choices))
	for index, choice := range manifest.Choices {
		if !identifierPattern.MatchString(choice.ID) {
			return validationError("invalid_choice_id", fmt.Sprintf("choices[%d].id", index), choice.ID)
		}
		if _, exists := seenChoice[choice.ID]; exists {
			return validationError("duplicate_choice_id", fmt.Sprintf("choices[%d].id", index), choice.ID)
		}
		seenChoice[choice.ID] = struct{}{}
		if strings.TrimSpace(choice.Label) == "" || len(choice.Label) > 200 {
			return validationError("invalid_choice_label", fmt.Sprintf("choices[%d].label", index), "label must contain 1 to 200 bytes")
		}
	}
	if len(manifest.EligibleKeys) < MinEligibleKeys || len(manifest.EligibleKeys) > MaxEligibleKeys {
		return validationError("invalid_eligibility_count", "eligible_keys", "eligible key count must be between 2 and 256")
	}
	if !slices.IsSorted(manifest.EligibleKeys) {
		return validationError("noncanonical_eligibility_order", "eligible_keys", "keys must be sorted by encoded bytes")
	}
	for index, key := range manifest.EligibleKeys {
		if err := validateEncoded("ristretto255", 32, key); err != nil {
			return validationError("invalid_eligibility_key", fmt.Sprintf("eligible_keys[%d]", index), err.Error())
		}
		if index > 0 && key == manifest.EligibleKeys[index-1] {
			return validationError("duplicate_eligibility_key", fmt.Sprintf("eligible_keys[%d]", index), key)
		}
	}
	if len(manifest.Trustees.Members) < 2 || len(manifest.Trustees.Members) > 9 {
		return validationError("invalid_trustee_count", "trustees.members", "trustee count must be between 2 and 9")
	}
	if manifest.Trustees.Quorum < 2 || manifest.Trustees.Quorum > len(manifest.Trustees.Members) {
		return validationError("invalid_trustee_quorum", "trustees.quorum", "quorum must be between 2 and trustee count")
	}
	if err := validateEncoded("ristretto255", 32, manifest.Trustees.ElectionPublicKey); err != nil {
		return validationError("invalid_election_public_key", "trustees.election_public_key", err.Error())
	}
	seenTrustee := make(map[string]struct{}, len(manifest.Trustees.Members))
	for index, trustee := range manifest.Trustees.Members {
		if !identifierPattern.MatchString(trustee.ID) {
			return validationError("invalid_trustee_id", fmt.Sprintf("trustees.members[%d].id", index), trustee.ID)
		}
		if _, exists := seenTrustee[trustee.ID]; exists {
			return validationError("duplicate_trustee_id", fmt.Sprintf("trustees.members[%d].id", index), trustee.ID)
		}
		seenTrustee[trustee.ID] = struct{}{}
		if err := validateEncoded("ed25519", 32, trustee.SigningKey); err != nil {
			return validationError("invalid_trustee_signing_key", fmt.Sprintf("trustees.members[%d].signing_key", index), err.Error())
		}
		if err := validateOpaque("vota-ceremony-commitment-v1", trustee.Commitment); err != nil {
			return validationError("invalid_trustee_commitment", fmt.Sprintf("trustees.members[%d].commitment", index), err.Error())
		}
	}
	if manifest.PrivacyThreshold < MinPrivacyThreshold || manifest.PrivacyThreshold > len(manifest.EligibleKeys) {
		return validationError("invalid_privacy_threshold", "privacy_threshold", "threshold must be between 2 and eligible key count")
	}
	opensAt, err := time.Parse(time.RFC3339, manifest.OpensAt)
	if err != nil {
		return validationError("invalid_opens_at", "opens_at", err.Error())
	}
	closesAt, err := time.Parse(time.RFC3339, manifest.ClosesAt)
	if err != nil {
		return validationError("invalid_closes_at", "closes_at", err.Error())
	}
	if !opensAt.Before(closesAt) {
		return validationError("invalid_poll_window", "closes_at", "close time must be after open time")
	}
	if err := validateEncoded("ed25519", 32, manifest.AuthorityKey); err != nil {
		return validationError("invalid_authority_key", "authority_key", err.Error())
	}
	if err := validateEncoded("ed25519sig", 64, manifest.AuthoritySignature); err != nil {
		return validationError("invalid_authority_signature", "authority_signature", err.Error())
	}
	if err := validateEncoded("sha256", 32, manifest.PollID); err != nil {
		return validationError("invalid_poll_id", "poll_id", err.Error())
	}
	return nil
}

func ValidateBallotShape(manifest Manifest, ballot BallotEnvelope) error {
	if err := validateHeader(ballot.SchemaVersion, ballot.Protocol); err != nil {
		return err
	}
	if ballot.PollID != manifest.PollID {
		return validationError("wrong_poll", "poll_id", "ballot poll does not match manifest")
	}
	if ballot.EligibilityScheme != manifest.EligibilityScheme {
		return validationError("unsupported_eligibility_scheme", "eligibility_scheme", ballot.EligibilityScheme)
	}
	if len(ballot.Ciphertexts) != len(manifest.Choices) {
		return validationError("invalid_ciphertext_count", "ciphertexts", "one ciphertext is required per choice")
	}
	for index, ciphertext := range ballot.Ciphertexts {
		if err := validateOpaque("vota-elgamal-v1", ciphertext); err != nil {
			return validationError("invalid_ciphertext", fmt.Sprintf("ciphertexts[%d]", index), err.Error())
		}
	}
	checks := []struct {
		field  string
		prefix string
		value  string
	}{
		{"manifest_hash", "sha256", ballot.ManifestHash},
		{"validity_proof", "vota-choice-proof-v1", ballot.ValidityProof},
		{"nullifier", "ristretto255", ballot.Nullifier},
		{"eligibility_proof", "vota-lsag-v1", ballot.EligibilityProof},
		{"ballot_hash", "sha256", ballot.BallotHash},
	}
	for _, check := range checks {
		var err error
		if check.prefix == "sha256" || check.prefix == "ristretto255" {
			err = validateEncoded(check.prefix, 32, check.value)
		} else {
			err = validateOpaque(check.prefix, check.value)
		}
		if err != nil {
			return validationError("invalid_ballot_field", check.field, err.Error())
		}
	}
	return nil
}

func validateHeader(schema int, protocol string) error {
	if schema != SchemaVersion {
		return validationError("unsupported_schema_version", "schema_version", fmt.Sprint(schema))
	}
	if protocol != ProtocolVersion {
		return validationError("unsupported_protocol", "protocol", protocol)
	}
	return nil
}

func validateEncoded(prefix string, byteLength int, value string) error {
	encoded, ok := strings.CutPrefix(value, prefix+":")
	if !ok {
		return fmt.Errorf("expected %s prefix", prefix)
	}
	if len(encoded) != byteLength*2 {
		return fmt.Errorf("expected %d encoded bytes", byteLength)
	}
	if _, err := hex.DecodeString(encoded); err != nil {
		return fmt.Errorf("decode hex: %w", err)
	}
	if encoded != strings.ToLower(encoded) {
		return fmt.Errorf("hex must be lowercase")
	}
	return nil
}

func validateOpaque(prefix, value string) error {
	encoded, ok := strings.CutPrefix(value, prefix+":")
	if !ok {
		return fmt.Errorf("expected %s prefix", prefix)
	}
	if len(encoded) < 2 || len(encoded)%2 != 0 {
		return fmt.Errorf("opaque value must contain non-empty even-length hex")
	}
	if _, err := hex.DecodeString(encoded); err != nil {
		return fmt.Errorf("decode hex: %w", err)
	}
	return nil
}
