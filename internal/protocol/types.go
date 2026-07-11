package protocol

type Choice struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type Trustee struct {
	ID         string `json:"id"`
	SigningKey string `json:"signing_key"`
	Commitment string `json:"commitment"`
}

type TrusteeSet struct {
	Quorum            int       `json:"quorum"`
	Members           []Trustee `json:"members"`
	ElectionPublicKey string    `json:"election_public_key"`
}

type Manifest struct {
	SchemaVersion               int        `json:"schema_version"`
	Protocol                    string     `json:"protocol"`
	EligibilityScheme           string     `json:"eligibility_scheme"`
	PollID                      string     `json:"poll_id"`
	Question                    string     `json:"question"`
	Choices                     []Choice   `json:"choices"`
	EligibleKeys                []string   `json:"eligible_keys"`
	Trustees                    TrusteeSet `json:"trustees"`
	PrivacyThreshold            int        `json:"privacy_threshold"`
	OpensAt                     string     `json:"opens_at"`
	ClosesAt                    string     `json:"closes_at"`
	AuthorityKey                string     `json:"authority_key"`
	AuthoritySignature          string     `json:"authority_signature"`
	ExperimentalNotForElections bool       `json:"experimental_not_for_real_elections"`
}

type Enrollment struct {
	SchemaVersion  int    `json:"schema_version"`
	Protocol       string `json:"protocol"`
	PollDraftID    string `json:"poll_draft_id"`
	EligibilityKey string `json:"eligibility_key"`
	Proof          string `json:"proof_of_possession"`
}

type BallotEnvelope struct {
	SchemaVersion     int      `json:"schema_version"`
	Protocol          string   `json:"protocol"`
	PollID            string   `json:"poll_id"`
	ManifestHash      string   `json:"manifest_hash"`
	EligibilityScheme string   `json:"eligibility_scheme"`
	Ciphertexts       []string `json:"ciphertexts"`
	ValidityProof     string   `json:"validity_proof"`
	Nullifier         string   `json:"nullifier"`
	EligibilityProof  string   `json:"eligibility_proof"`
	BallotHash        string   `json:"ballot_hash"`
}

type Receipt struct {
	SchemaVersion  int    `json:"schema_version"`
	Protocol       string `json:"protocol"`
	PollID         string `json:"poll_id"`
	BallotHash     string `json:"ballot_hash"`
	Sequence       uint64 `json:"sequence"`
	EventHash      string `json:"event_hash"`
	CheckpointHash string `json:"checkpoint_hash"`
	Signature      string `json:"signature"`
}

type AuditEvent struct {
	SchemaVersion int    `json:"schema_version"`
	Protocol      string `json:"protocol"`
	PollID        string `json:"poll_id"`
	Sequence      uint64 `json:"sequence"`
	Type          string `json:"type"`
	ObjectHash    string `json:"object_hash"`
	PreviousHash  string `json:"previous_hash"`
	EventHash     string `json:"event_hash"`
	AcceptedAt    string `json:"accepted_at"`
}

type Checkpoint struct {
	SchemaVersion  int    `json:"schema_version"`
	Protocol       string `json:"protocol"`
	PollID         string `json:"poll_id"`
	Sequence       uint64 `json:"sequence"`
	EventHash      string `json:"event_hash"`
	CheckpointHash string `json:"checkpoint_hash"`
	Signature      string `json:"signature"`
}

type EncryptedAggregate struct {
	SchemaVersion int      `json:"schema_version"`
	Protocol      string   `json:"protocol"`
	PollID        string   `json:"poll_id"`
	BallotCount   int      `json:"ballot_count"`
	Ciphertexts   []string `json:"ciphertexts"`
	AggregateHash string   `json:"aggregate_hash"`
}

type TrusteeShare struct {
	SchemaVersion int      `json:"schema_version"`
	Protocol      string   `json:"protocol"`
	PollID        string   `json:"poll_id"`
	TrusteeID     string   `json:"trustee_id"`
	AggregateHash string   `json:"aggregate_hash"`
	Shares        []string `json:"shares"`
	Proofs        []string `json:"proofs"`
	Signature     string   `json:"signature"`
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
	AggregateHash string        `json:"aggregate_hash"`
	Totals        []ChoiceTotal `json:"totals"`
	TrusteeIDs    []string      `json:"trustee_ids"`
	EvidenceHash  string        `json:"evidence_hash"`
}

type ReferenceElection struct {
	Manifest  Manifest           `json:"manifest"`
	Ballots   []BallotEnvelope   `json:"ballots"`
	Events    []AuditEvent       `json:"events"`
	Aggregate EncryptedAggregate `json:"aggregate"`
	Shares    []TrusteeShare     `json:"shares"`
	Tally     Tally              `json:"tally"`
}
