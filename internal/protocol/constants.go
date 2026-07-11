// Package protocol defines Vota's versioned public artifact contract.
package protocol

const (
	SchemaVersion     = 1
	ProtocolVersion   = "vota-v1-experimental"
	EligibilityScheme = "ring-v1"

	MinChoices          = 2
	MaxChoices          = 10
	MinEligibleKeys     = 2
	MaxEligibleKeys     = 256
	MinPrivacyThreshold = 2
	MaxArtifactBytes    = 1 << 20
)

const (
	DomainPollID               = "vota:v1:poll-id"
	DomainPollDraftID          = "vota:v1:poll-draft-id"
	DomainManifestSignature    = "vota:v1:manifest-signature"
	DomainEnrollmentProof      = "vota:v1:enrollment-proof"
	DomainRingHash             = "vota:v1:ring-hash"
	DomainRingChallenge        = "vota:v1:ring-challenge"
	DomainRingHashToGroup      = "vota:v1:ring-hash-to-group"
	DomainBallotHash           = "vota:v1:ballot-hash"
	DomainChoiceProof          = "vota:v1:choice-proof"
	DomainChoiceSumProof       = "vota:v1:choice-sum-proof"
	DomainCeremonyCommitment   = "vota:v1:ceremony-commitment"
	DomainAggregateHash        = "vota:v1:aggregate-hash"
	DomainDecryptionShare      = "vota:v1:decryption-share"
	DomainDecryptionShareProof = "vota:v1:decryption-share-proof"
	DomainAuditEvent           = "vota:v1:audit-event"
	DomainCheckpointHash       = "vota:v1:checkpoint-hash"
	DomainCheckpointSignature  = "vota:v1:checkpoint-signature"
	DomainReceiptSignature     = "vota:v1:receipt-signature"
	DomainTallyEvidence        = "vota:v1:tally-evidence"
)

// DomainSeparators returns every protocol operation separator in stable order.
func DomainSeparators() []string {
	return []string{
		DomainPollID,
		DomainPollDraftID,
		DomainManifestSignature,
		DomainEnrollmentProof,
		DomainRingHash,
		DomainRingChallenge,
		DomainRingHashToGroup,
		DomainBallotHash,
		DomainChoiceProof,
		DomainChoiceSumProof,
		DomainCeremonyCommitment,
		DomainAggregateHash,
		DomainDecryptionShare,
		DomainDecryptionShareProof,
		DomainAuditEvent,
		DomainCheckpointHash,
		DomainCheckpointSignature,
		DomainReceiptSignature,
		DomainTallyEvidence,
	}
}
