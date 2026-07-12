package sequencer

const (
	SchemaVersion        = 1
	Protocol             = "vota-ssh-credit-v1"
	AdminNamespace       = "vota-poll-admin@vota.local"
	CreditClaimNamespace = "vota-credit-claim@vota.local"
)

type Choice struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type Poll struct {
	SchemaVersion         int      `json:"schema_version"`
	Protocol              string   `json:"protocol"`
	PollID                string   `json:"poll_id"`
	Question              string   `json:"question"`
	Choices               []Choice `json:"choices"`
	ClosesAt              string   `json:"closes_at"`
	IssuerKeyID           string   `json:"issuer_key_id"`
	IssuerPublicKey       string   `json:"issuer_public_key"`
	CheckpointPublicKey   string   `json:"checkpoint_public_key"`
	EligibilityCommitment string   `json:"eligibility_commitment"`
	EligibleCount         int      `json:"eligible_count"`
	Signature             string   `json:"signature"`
}

type CreatePollRequest struct {
	RequestID      string   `json:"request_id"`
	Question       string   `json:"question"`
	Choices        []string `json:"choices"`
	ClosesAt       string   `json:"closes_at"`
	Members        []string `json:"members"`
	AdminPublicKey string   `json:"admin_public_key"`
	SSHSIG         string   `json:"sshsig"`
}

type CreatePollResponse struct {
	Poll    Poll   `json:"poll"`
	PollURL string `json:"poll_url"`
}

type ClaimRequest struct {
	SSHPublicKey      string `json:"ssh_public_key"`
	IssuanceRequestID string `json:"issuance_request_id"`
	BlindedMessage    string `json:"blinded_message"`
	SSHSIG            string `json:"sshsig"`
}

type ClaimResponse struct {
	BlindSignature string `json:"blind_signature"`
}

type Credential struct {
	IssuerKeyID string `json:"issuer_key_id"`
	Serial      string `json:"serial"`
	Signature   string `json:"signature"`
}

type BallotRequest struct {
	Credential Credential `json:"credential"`
	ChoiceID   string     `json:"choice_id"`
}

type BallotRecord struct {
	SchemaVersion  int        `json:"schema_version"`
	Protocol       string     `json:"protocol"`
	PollID         string     `json:"poll_id"`
	Sequence       uint64     `json:"sequence"`
	Credential     Credential `json:"credential"`
	CredentialHash string     `json:"credential_hash"`
	ChoiceID       string     `json:"choice_id"`
}

type Checkpoint struct {
	SchemaVersion int    `json:"schema_version"`
	Protocol      string `json:"protocol"`
	PollID        string `json:"poll_id"`
	Sequence      uint64 `json:"sequence"`
	EventHash     string `json:"event_hash"`
	Signature     string `json:"signature"`
}

type Receipt struct {
	SchemaVersion  int        `json:"schema_version"`
	Protocol       string     `json:"protocol"`
	PollID         string     `json:"poll_id"`
	Sequence       uint64     `json:"sequence"`
	CredentialHash string     `json:"credential_hash"`
	EventHash      string     `json:"event_hash"`
	Checkpoint     Checkpoint `json:"checkpoint"`
	Signature      string     `json:"signature"`
}

type ChoiceTotal struct {
	ChoiceID string `json:"choice_id"`
	Total    int    `json:"total"`
}

type Tally struct {
	SchemaVersion int           `json:"schema_version"`
	Protocol      string        `json:"protocol"`
	PollID        string        `json:"poll_id"`
	BallotCount   int           `json:"ballot_count"`
	Totals        []ChoiceTotal `json:"totals"`
	ClosedAt      string        `json:"closed_at"`
	Signature     string        `json:"signature"`
}

type ClosePollRequest struct {
	AdminPublicKey string `json:"admin_public_key"`
	SSHSIG         string `json:"sshsig"`
}

type AuditEvent struct {
	Sequence     uint64 `json:"sequence"`
	Type         string `json:"type"`
	PreviousHash string `json:"previous_hash"`
	EventHash    string `json:"event_hash"`
	Artifact     []byte `json:"artifact"`
	Receipt      []byte `json:"receipt,omitempty"`
}

type AuditBundle struct {
	SchemaVersion       int          `json:"schema_version"`
	Protocol            string       `json:"protocol"`
	Poll                Poll         `json:"poll"`
	Events              []AuditEvent `json:"events"`
	Checkpoints         []Checkpoint `json:"checkpoints"`
	Tally               Tally        `json:"tally"`
	CheckpointPublicKey string       `json:"checkpoint_public_key"`
}
