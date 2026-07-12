package sequencer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/cirocosta/vota/internal/crypto/blind"
	"github.com/cirocosta/vota/internal/crypto/sshsig"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/sequencerstore"
	"golang.org/x/crypto/ssh"
)

var choiceDashPattern = regexp.MustCompile(`-+`)

type memberKey struct {
	Encoded     string
	Fingerprint string
}

func (service *Service) validateCreateRequest(request CreatePollRequest) (CreatePollRequest, ssh.PublicKey, error) {
	requestID, err := decodeBase64(request.RequestID, 16)
	if err != nil {
		return CreatePollRequest{}, nil, &Error{Code: "invalid_request_id", Err: err}
	}
	request.RequestID = base64.RawURLEncoding.EncodeToString(requestID)
	if request.Question == "" || request.Question != strings.TrimSpace(request.Question) || len(request.Question) > 500 {
		return CreatePollRequest{}, nil, &Error{Code: "invalid_question"}
	}
	if len(request.Choices) < 2 || len(request.Choices) > 20 {
		return CreatePollRequest{}, nil, &Error{Code: "invalid_choices"}
	}
	seen := make(map[string]struct{}, len(request.Choices))
	for _, label := range request.Choices {
		if label == "" || label != strings.TrimSpace(label) || len(label) > 100 {
			return CreatePollRequest{}, nil, &Error{Code: "invalid_choice"}
		}
		folded := strings.ToLower(label)
		if _, exists := seen[folded]; exists {
			return CreatePollRequest{}, nil, &Error{Code: "duplicate_choice"}
		}
		seen[folded] = struct{}{}
	}
	closesAt, err := time.Parse(time.RFC3339, request.ClosesAt)
	if err != nil || closesAt.UTC().Format(time.RFC3339) != request.ClosesAt || !closesAt.After(service.now().UTC()) {
		return CreatePollRequest{}, nil, &Error{Code: "invalid_close_time", Err: err}
	}
	members, _, err := normalizeMembers(request.Members)
	if err != nil {
		return CreatePollRequest{}, nil, err
	}
	request.Members = make([]string, len(members))
	for index, member := range members {
		request.Members[index] = member.Encoded
	}
	adminKey, err := sshsig.ParsePublicKey([]byte(request.AdminPublicKey))
	if err != nil {
		return CreatePollRequest{}, nil, &Error{Code: "invalid_admin_key", Err: err}
	}
	canonical, _ := sshsig.CanonicalPublicKey(adminKey)
	if request.AdminPublicKey != string(canonical) {
		return CreatePollRequest{}, nil, &Error{Code: "invalid_admin_key"}
	}
	fingerprint, _ := sshsig.Fingerprint(adminKey)
	if _, authorized := service.adminFingerprints[fingerprint]; !authorized {
		return CreatePollRequest{}, nil, &Error{Code: "admin_not_authorized"}
	}
	return request, adminKey, nil
}

func normalizeMembers(encoded []string) ([]memberKey, string, error) {
	if len(encoded) < 2 || len(encoded) > 1000 {
		return nil, "", &Error{Code: "invalid_members"}
	}
	output := make([]memberKey, 0, len(encoded))
	seen := make(map[string]struct{}, len(encoded))
	for _, value := range encoded {
		key, err := sshsig.ParsePublicKey([]byte(value))
		if err != nil {
			return nil, "", &Error{Code: "invalid_member_key", Err: err}
		}
		canonical, _ := sshsig.CanonicalPublicKey(key)
		fingerprint, _ := sshsig.Fingerprint(key)
		if _, exists := seen[fingerprint]; exists {
			return nil, "", &Error{Code: "duplicate_eligible_key"}
		}
		seen[fingerprint] = struct{}{}
		output = append(output, memberKey{Encoded: string(canonical), Fingerprint: fingerprint})
	}
	slices.SortFunc(output, func(a, b memberKey) int { return bytes.Compare([]byte(a.Encoded), []byte(b.Encoded)) })
	commitmentInput := make([]string, len(output))
	for index, value := range output {
		commitmentInput[index] = value.Encoded
	}
	encodedCommitment, err := protocol.MarshalCanonical(commitmentInput)
	if err != nil {
		return nil, "", &Error{Code: "eligibility_encode_failed", Err: err}
	}
	commitment := hashBytes("vota:eligibility:v1", encodedCommitment)
	return output, commitment, nil
}

func normalizedChoices(labels []string) []Choice {
	output := make([]Choice, len(labels))
	used := make(map[string]int, len(labels))
	for index, label := range labels {
		identifier := choiceID(label)
		used[identifier]++
		if used[identifier] > 1 {
			identifier = fmt.Sprintf("%s-%d", identifier, used[identifier])
		}
		output[index] = Choice{ID: identifier, Label: label}
	}
	return output
}

func choiceID(label string) string {
	var output strings.Builder
	for _, value := range strings.ToLower(label) {
		switch {
		case value >= 'a' && value <= 'z', value >= '0' && value <= '9':
			output.WriteRune(value)
		case unicode.IsSpace(value), value == '-', value == '_':
			output.WriteByte('-')
		}
	}
	identifier := strings.Trim(choiceDashPattern.ReplaceAllString(output.String(), "-"), "-")
	if identifier == "" {
		return "choice"
	}
	return identifier
}

func CreatePollMessage(request CreatePollRequest) ([]byte, error) {
	request.SSHSIG = ""
	return protocol.MarshalCanonical(struct {
		RequestID      string   `json:"request_id"`
		Question       string   `json:"question"`
		Choices        []string `json:"choices"`
		ClosesAt       string   `json:"closes_at"`
		Members        []string `json:"members"`
		AdminPublicKey string   `json:"admin_public_key"`
	}{request.RequestID, request.Question, request.Choices, request.ClosesAt, request.Members, request.AdminPublicKey})
}

func ClaimMessage(pollID, requestID string, blindedMessage []byte) ([]byte, error) {
	digest := sha256.Sum256(blindedMessage)
	return protocol.MarshalCanonical(struct {
		PollID               string `json:"poll_id"`
		IssuanceRequestID    string `json:"issuance_request_id"`
		BlindedMessageSHA256 string `json:"blinded_message_sha256"`
	}{pollID, requestID, base64.RawURLEncoding.EncodeToString(digest[:])})
}

func ClosePollMessage(pollID, adminPublicKey string) ([]byte, error) {
	return protocol.MarshalCanonical(struct {
		PollID         string `json:"poll_id"`
		AdminPublicKey string `json:"admin_public_key"`
	}{pollID, adminPublicKey})
}

func (service *Service) requireOpen(poll sequencerstore.Poll) error {
	if poll.State != "open" {
		return &Error{Code: "poll_not_open"}
	}
	closesAt, err := time.Parse(time.RFC3339, poll.ClosesAt)
	if err != nil {
		return &Error{Code: "invalid_stored_poll", Err: err}
	}
	if !service.now().UTC().Before(closesAt) {
		return &Error{Code: "poll_not_open"}
	}
	return nil
}

func (service *Service) checkpoint(pollID string, sequence uint64, eventHash string) (Checkpoint, []byte, error) {
	return service.streamCheckpoint("vota:checkpoint:v1", pollID, sequence, eventHash)
}

func (service *Service) creditCheckpoint(pollID string, sequence uint64, eventHash string) (Checkpoint, []byte, error) {
	return service.streamCheckpoint("vota:credit-checkpoint:v1", pollID, sequence, eventHash)
}

func (service *Service) streamCheckpoint(domain, pollID string, sequence uint64, eventHash string) (Checkpoint, []byte, error) {
	checkpoint := Checkpoint{SchemaVersion: SchemaVersion, Protocol: Protocol, PollID: pollID, Sequence: sequence, EventHash: eventHash}
	signature, err := service.signValue(domain, checkpoint)
	if err != nil {
		return Checkpoint{}, nil, err
	}
	checkpoint.Signature = signature
	encoded, err := protocol.MarshalCanonical(checkpoint)
	return checkpoint, encoded, err
}

func (service *Service) signValue(domain string, value any) (string, error) {
	encoded, err := protocol.MarshalCanonical(value)
	if err != nil {
		return "", &Error{Code: "signature_encode_failed", Err: err}
	}
	message := append(append([]byte(domain), 0), encoded...)
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(service.checkpointPrivate, message)), nil
}

func verifyValue(publicKey ed25519.PublicKey, domain string, value any, signature string) error {
	decoded, err := decodeBase64(signature, ed25519.SignatureSize)
	if err != nil {
		return &Error{Code: "invalid_sequencer_signature", Err: err}
	}
	encoded, err := protocol.MarshalCanonical(value)
	if err != nil {
		return &Error{Code: "invalid_sequencer_signature", Err: err}
	}
	message := append(append([]byte(domain), 0), encoded...)
	if !ed25519.Verify(publicKey, message, decoded) {
		return &Error{Code: "invalid_sequencer_signature"}
	}
	return nil
}

func decodeBase64(value string, size int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || (size >= 0 && len(decoded) != size) || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("invalid base64url")
	}
	return decoded, nil
}

func hashBytes(domain string, value []byte) string {
	hash := sha256.New()
	hash.Write([]byte(domain))
	hash.Write([]byte{0})
	hash.Write(value)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func credentialHash(credential blind.Credential) string {
	encoded, _ := protocol.MarshalCanonical(struct {
		IssuerKeyID string `json:"issuer_key_id"`
		Serial      string `json:"serial"`
		Signature   string `json:"signature"`
	}{credential.IssuerKeyID, base64.RawURLEncoding.EncodeToString(credential.Serial), base64.RawURLEncoding.EncodeToString(credential.Signature)})
	return hashBytes("vota:credential-hash:v1", encoded)
}

func verifyWireCredential(poll Poll, wire Credential) (blind.Credential, string, error) {
	issuerPublic, err := blind.ParsePublicKey(poll.IssuerPublicKey)
	if err != nil {
		return blind.Credential{}, "", &Error{Code: "invalid_stored_poll", Err: err}
	}
	serial, err := decodeBase64(wire.Serial, blind.SerialSize)
	if err != nil {
		return blind.Credential{}, "", &Error{Code: "invalid_credential", Err: err}
	}
	signature, err := decodeBase64(wire.Signature, blind.MessagePrefixSize+issuerPublic.Size())
	if err != nil {
		return blind.Credential{}, "", &Error{Code: "invalid_credential", Err: err}
	}
	credential := blind.Credential{IssuerKeyID: wire.IssuerKeyID, Serial: serial, Signature: signature}
	if err := blind.Verify(issuerPublic, poll.PollID, credential); err != nil {
		return blind.Credential{}, "", &Error{Code: "invalid_credential", Err: err}
	}
	return credential, credentialHash(credential), nil
}

func canonicalTime(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format(time.RFC3339)
}

func eventDay(value time.Time) string {
	return value.UTC().Format("2006-01-02")
}
