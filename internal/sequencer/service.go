// Package sequencer implements SSH-credited anonymous poll state transitions.
package sequencer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/cirocosta/vota/internal/crypto/blind"
	"github.com/cirocosta/vota/internal/crypto/sshsig"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/sequencerstore"
)

type Config struct {
	Store                *sequencerstore.Store
	IssuerPrivateKey     *rsa.PrivateKey
	CheckpointPrivateKey ed25519.PrivateKey
	AdminPublicKeys      []string
	Now                  func() time.Time
}

type Service struct {
	store             *sequencerstore.Store
	issuer            *rsa.PrivateKey
	checkpointPrivate ed25519.PrivateKey
	checkpointPublic  ed25519.PublicKey
	adminFingerprints map[string]struct{}
	now               func() time.Time
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
	for _, code := range []string{
		sequencerstore.ErrorCode(err), blind.ErrorCode(err), sshsig.ErrorCode(err),
	} {
		if code != "internal_error" {
			return code
		}
	}
	return "internal_error"
}

func New(config Config) (*Service, error) {
	if config.Store == nil || config.IssuerPrivateKey == nil {
		return nil, errors.New("missing sequencer dependencies")
	}
	if err := config.IssuerPrivateKey.Validate(); err != nil || config.IssuerPrivateKey.N.BitLen() < blind.MinRSAKeyBits {
		return nil, &Error{Code: "invalid_issuer_private_key", Err: err}
	}
	if len(config.CheckpointPrivateKey) != ed25519.PrivateKeySize {
		return nil, &Error{Code: "invalid_checkpoint_private_key"}
	}
	admins := make(map[string]struct{}, len(config.AdminPublicKeys))
	for _, encoded := range config.AdminPublicKeys {
		key, err := sshsig.ParsePublicKey([]byte(encoded))
		if err != nil {
			return nil, &Error{Code: "invalid_admin_key", Err: err}
		}
		fingerprint, _ := sshsig.Fingerprint(key)
		admins[fingerprint] = struct{}{}
	}
	if len(admins) == 0 {
		return nil, &Error{Code: "no_admin_keys"}
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	public := config.CheckpointPrivateKey.Public().(ed25519.PublicKey)
	return &Service{
		store: config.Store, issuer: config.IssuerPrivateKey,
		checkpointPrivate: append(ed25519.PrivateKey(nil), config.CheckpointPrivateKey...),
		checkpointPublic:  append(ed25519.PublicKey(nil), public...),
		adminFingerprints: admins, now: config.Now,
	}, nil
}

func (service *Service) CreatePoll(ctx context.Context, request CreatePollRequest) (Poll, bool, error) {
	normalized, adminKey, err := service.validateCreateRequest(request)
	if err != nil {
		return Poll{}, false, err
	}
	message, err := CreatePollMessage(normalized)
	if err != nil {
		return Poll{}, false, err
	}
	signature, err := decodeBase64(request.SSHSIG, -1)
	if err != nil {
		return Poll{}, false, &Error{Code: "invalid_ssh_signature", Err: err}
	}
	if err := sshsig.Verify(adminKey, AdminNamespace, message, signature); err != nil {
		return Poll{}, false, &Error{Code: "invalid_ssh_signature", Err: err}
	}

	memberKeys, commitment, err := normalizeMembers(normalized.Members)
	if err != nil {
		return Poll{}, false, err
	}
	choices := normalizedChoices(normalized.Choices)
	issuerPublic, _ := blind.EncodePublicKey(&service.issuer.PublicKey)
	checkpointPublic := base64.RawURLEncoding.EncodeToString(service.checkpointPublic)
	unsignedID := struct {
		RequestID             string   `json:"request_id"`
		Question              string   `json:"question"`
		Choices               []Choice `json:"choices"`
		ClosesAt              string   `json:"closes_at"`
		IssuerKeyID           string   `json:"issuer_key_id"`
		EligibilityCommitment string   `json:"eligibility_commitment"`
	}{normalized.RequestID, normalized.Question, choices, normalized.ClosesAt, blind.KeyID(&service.issuer.PublicKey), commitment}
	encodedID, err := protocol.MarshalCanonical(unsignedID)
	if err != nil {
		return Poll{}, false, &Error{Code: "poll_encode_failed", Err: err}
	}
	pollID := hashBytes("vota:poll-id:v1", encodedID)
	poll := Poll{
		SchemaVersion: SchemaVersion, Protocol: Protocol, PollID: pollID,
		Question: normalized.Question, Choices: choices, ClosesAt: normalized.ClosesAt,
		IssuerKeyID: blind.KeyID(&service.issuer.PublicKey), IssuerPublicKey: issuerPublic,
		CheckpointPublicKey: checkpointPublic, EligibilityCommitment: commitment,
		EligibleCount: len(memberKeys),
	}
	poll.Signature, err = service.signValue("vota:poll-artifact:v1", poll)
	if err != nil {
		return Poll{}, false, err
	}
	artifact, _ := protocol.MarshalCanonical(poll)
	artifactHash := hashBytes("vota:poll-artifact:v1", artifact)
	now := canonicalTime(service.now())
	err = service.store.Transaction(ctx, func(tx *sequencerstore.Tx) error {
		if existing, lookupErr := tx.Poll(ctx, pollID); lookupErr == nil {
			if !bytes.Equal(existing.Artifact, artifact) {
				return &Error{Code: "poll_conflict"}
			}
			return errPollExists
		}
		stored := sequencerstore.Poll{PollID: pollID, ArtifactHash: artifactHash, Artifact: artifact, CreatedAt: now, ClosesAt: normalized.ClosesAt, IssuerKeyID: poll.IssuerKeyID, EligibilityCommitment: commitment}
		if err := tx.InsertPoll(ctx, stored); err != nil {
			return err
		}
		for index, choice := range choices {
			if err := tx.InsertChoice(ctx, sequencerstore.Choice{PollID: pollID, ChoiceID: choice.ID, Label: choice.Label, Position: index}); err != nil {
				return err
			}
		}
		for _, member := range memberKeys {
			if err := tx.InsertCredit(ctx, sequencerstore.Credit{PollID: pollID, SSHFingerprint: member.Fingerprint, SSHPublicKey: member.Encoded}); err != nil {
				return err
			}
		}
		eventArtifact, _ := protocol.MarshalCanonical(struct {
			Type     string `json:"type"`
			PollHash string `json:"poll_hash"`
		}{"poll_created", artifactHash})
		event := sequencerstore.BallotEvent{PollID: pollID, Sequence: 1, Type: "poll_created", PreviousHash: sequencerstore.EmptyHash(), Artifact: eventArtifact, RecordedAt: now}
		event.EventHash = sequencerstore.EventHash("ballot", pollID, 1, event.PreviousHash, eventArtifact)
		checkpoint, encodedCheckpoint, err := service.checkpoint(pollID, 1, event.EventHash)
		if err != nil {
			return err
		}
		if err := tx.InsertBallotEvent(ctx, event); err != nil {
			return err
		}
		return tx.SaveCheckpoint(ctx, sequencerstore.Checkpoint{PollID: pollID, BallotSequence: 1, EventHash: checkpoint.EventHash, Artifact: encodedCheckpoint})
	})
	if errors.Is(err, errPollExists) {
		return poll, false, nil
	}
	if err != nil {
		return Poll{}, false, err
	}
	return poll, true, nil
}

var errPollExists = errors.New("poll exists")

func (service *Service) Poll(ctx context.Context, pollID string) (Poll, error) {
	stored, err := service.store.Poll(ctx, pollID)
	if err != nil {
		return Poll{}, err
	}
	var poll Poll
	if err := protocol.DecodeStrict(stored.Artifact, &poll); err != nil {
		return Poll{}, &Error{Code: "invalid_stored_poll", Err: err}
	}
	return poll, nil
}

func (service *Service) Claim(ctx context.Context, pollID string, request ClaimRequest) (ClaimResponse, bool, error) {
	publicKey, err := sshsig.ParsePublicKey([]byte(request.SSHPublicKey))
	if err != nil {
		return ClaimResponse{}, false, &Error{Code: "invalid_ssh_public_key", Err: err}
	}
	canonicalKey, _ := sshsig.CanonicalPublicKey(publicKey)
	if string(canonicalKey) != request.SSHPublicKey {
		return ClaimResponse{}, false, &Error{Code: "invalid_ssh_public_key"}
	}
	fingerprint, _ := sshsig.Fingerprint(publicKey)
	requestID, err := decodeBase64(request.IssuanceRequestID, 16)
	if err != nil {
		return ClaimResponse{}, false, &Error{Code: "invalid_issuance_request_id", Err: err}
	}
	blinded, err := decodeBase64(request.BlindedMessage, service.issuer.Size())
	if err != nil {
		return ClaimResponse{}, false, &Error{Code: "invalid_blinded_message", Err: err}
	}
	message, err := ClaimMessage(pollID, request.IssuanceRequestID, blinded)
	if err != nil {
		return ClaimResponse{}, false, err
	}
	encodedSignature, err := decodeBase64(request.SSHSIG, -1)
	if err != nil || sshsig.Verify(publicKey, CreditClaimNamespace, message, encodedSignature) != nil {
		return ClaimResponse{}, false, &Error{Code: "invalid_ssh_signature", Err: err}
	}
	blindedHash := hashBytes("vota:blinded-message:v1", blinded)
	requestIDCanonical := base64.RawURLEncoding.EncodeToString(requestID)
	var response ClaimResponse
	created := false
	err = service.store.Transaction(ctx, func(tx *sequencerstore.Tx) error {
		poll, err := tx.Poll(ctx, pollID)
		if err != nil {
			return err
		}
		if err := service.requireOpen(poll); err != nil {
			return err
		}
		credit, err := tx.Credit(ctx, pollID, fingerprint)
		if err != nil {
			return err
		}
		if credit.SSHPublicKey != request.SSHPublicKey {
			return &Error{Code: "not_eligible"}
		}
		if credit.IssuanceRequestID != "" {
			if credit.IssuanceRequestID == requestIDCanonical && credit.BlindedMessageHash == blindedHash {
				response.BlindSignature = base64.RawURLEncoding.EncodeToString(credit.BlindSignature)
				return nil
			}
			if credit.IssuanceRequestID == requestIDCanonical {
				return &Error{Code: "issuance_request_mismatch"}
			}
			return &Error{Code: "credit_already_claimed"}
		}
		blindSignature, err := blind.BlindSign(service.issuer, blinded, nil)
		if err != nil {
			return err
		}
		now := eventDay(service.now())
		if err := tx.ClaimCredit(ctx, pollID, fingerprint, requestIDCanonical, blindedHash, blindSignature, now); err != nil {
			return err
		}
		sequence, previous, err := tx.NextCreditEvent(ctx, pollID)
		if err != nil {
			return err
		}
		artifact, _ := protocol.MarshalCanonical(struct {
			Type               string `json:"type"`
			SSHFingerprint     string `json:"ssh_fingerprint"`
			IssuanceRequestID  string `json:"issuance_request_id"`
			BlindedMessageHash string `json:"blinded_message_hash"`
		}{"credit_claimed", fingerprint, requestIDCanonical, blindedHash})
		event := sequencerstore.CreditEvent{PollID: pollID, Sequence: sequence, PreviousHash: previous, Artifact: artifact, RecordedAt: now}
		event.EventHash = sequencerstore.EventHash("credit", pollID, sequence, previous, artifact)
		_, event.Signature, err = service.creditCheckpoint(pollID, sequence, event.EventHash)
		if err != nil {
			return err
		}
		if err := tx.InsertCreditEvent(ctx, event); err != nil {
			return err
		}
		response.BlindSignature = base64.RawURLEncoding.EncodeToString(blindSignature)
		created = true
		return nil
	})
	return response, created, err
}

func (service *Service) Vote(ctx context.Context, pollID string, request BallotRequest) (Receipt, error) {
	poll, err := service.Poll(ctx, pollID)
	if err != nil {
		return Receipt{}, err
	}
	_, credentialHash, err := verifyWireCredential(poll, request.Credential)
	if err != nil {
		return Receipt{}, err
	}
	var receipt Receipt
	err = service.store.Transaction(ctx, func(tx *sequencerstore.Tx) error {
		storedPoll, err := tx.Poll(ctx, pollID)
		if err != nil {
			return err
		}
		if err := service.requireOpen(storedPoll); err != nil {
			return err
		}
		choices, err := tx.Choices(ctx, pollID)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(choices, func(choice sequencerstore.Choice) bool { return choice.ChoiceID == request.ChoiceID }) {
			return &Error{Code: "invalid_choice"}
		}
		sequence, previous, err := tx.NextBallotEvent(ctx, pollID)
		if err != nil {
			return err
		}
		record := BallotRecord{SchemaVersion: SchemaVersion, Protocol: Protocol, PollID: pollID, Sequence: sequence, Credential: request.Credential, CredentialHash: credentialHash, ChoiceID: request.ChoiceID}
		artifact, _ := protocol.MarshalCanonical(record)
		eventHash := sequencerstore.EventHash("ballot", pollID, sequence, previous, artifact)
		checkpoint, encodedCheckpoint, err := service.checkpoint(pollID, sequence, eventHash)
		if err != nil {
			return err
		}
		receipt = Receipt{SchemaVersion: SchemaVersion, Protocol: Protocol, PollID: pollID, Sequence: sequence, CredentialHash: credentialHash, EventHash: eventHash, Checkpoint: checkpoint}
		receipt.Signature, err = service.signValue("vota:receipt:v1", receipt)
		if err != nil {
			return err
		}
		encodedReceipt, _ := protocol.MarshalCanonical(receipt)
		event := sequencerstore.BallotEvent{PollID: pollID, Sequence: sequence, Type: "ballot_accepted", PreviousHash: previous, EventHash: eventHash, Artifact: artifact, Receipt: encodedReceipt, RecordedAt: eventDay(service.now())}
		if err := tx.SpendCredential(ctx, pollID, credentialHash, sequence); err != nil {
			return err
		}
		if err := tx.InsertBallotEvent(ctx, event); err != nil {
			return err
		}
		return tx.SaveCheckpoint(ctx, sequencerstore.Checkpoint{PollID: pollID, BallotSequence: sequence, EventHash: eventHash, Artifact: encodedCheckpoint})
	})
	return receipt, err
}
