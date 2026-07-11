// Package auditverify replays complete public Vota election records.
package auditverify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/cirocosta/vota/internal/app"
	"github.com/cirocosta/vota/internal/audit"
	"github.com/cirocosta/vota/internal/protocol"
)

type Report struct {
	SchemaVersion       int                    `json:"schema_version"`
	Protocol            string                 `json:"protocol"`
	PollID              string                 `json:"poll_id"`
	ManifestHash        string                 `json:"manifest_hash"`
	EventCount          int                    `json:"event_count"`
	AcceptedBallotCount int                    `json:"accepted_ballot_count"`
	AggregateHash       string                 `json:"aggregate_hash,omitempty"`
	ValidTrusteeIDs     []string               `json:"valid_trustee_ids"`
	Totals              []protocol.ChoiceTotal `json:"totals"`
	FinalSequence       uint64                 `json:"final_sequence"`
	FinalCheckpoint     string                 `json:"final_checkpoint"`
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

// Verify parses and fully replays one canonical public record.
func Verify(encoded []byte) (Report, error) {
	bundle, err := audit.ParseBundle(encoded)
	if err != nil {
		return Report{}, &Error{Code: "invalid_audit_chain", Err: err}
	}
	manifestHash, err := app.ManifestHash(bundle.Manifest)
	if err != nil {
		return Report{}, err
	}
	position := 0
	if err := expectEvent(bundle, &position, "poll_published", manifestHash); err != nil {
		return Report{}, err
	}
	seenBallots := make(map[string]bool, len(bundle.Ballots))
	seenNullifiers := make(map[string]bool, len(bundle.Ballots))
	for index, ballot := range bundle.Ballots {
		if seenBallots[ballot.BallotHash] {
			return Report{}, &Error{Code: "duplicate_ballot_hash", Err: fmt.Errorf("index %d", index)}
		}
		if seenNullifiers[ballot.Nullifier] {
			return Report{}, &Error{Code: "duplicate_nullifier", Err: fmt.Errorf("index %d", index)}
		}
		seenBallots[ballot.BallotHash] = true
		seenNullifiers[ballot.Nullifier] = true
		if err := app.VerifyBallot(bundle.Manifest, ballot); err != nil {
			return Report{}, &Error{Code: "invalid_ballot", Err: fmt.Errorf("index %d: %w", index, err)}
		}
		if err := expectEvent(bundle, &position, "ballot_accepted", ballot.BallotHash); err != nil {
			return Report{}, err
		}
	}
	report := Report{
		SchemaVersion: protocol.SchemaVersion, Protocol: protocol.ProtocolVersion,
		PollID: bundle.Manifest.PollID, ManifestHash: manifestHash, EventCount: len(bundle.Events),
		AcceptedBallotCount: len(bundle.Ballots), ValidTrusteeIDs: []string{}, Totals: []protocol.ChoiceTotal{},
		FinalSequence:   bundle.Checkpoints[len(bundle.Checkpoints)-1].Sequence,
		FinalCheckpoint: bundle.Checkpoints[len(bundle.Checkpoints)-1].CheckpointHash,
	}
	if bundle.Aggregate == nil {
		if len(bundle.Shares) != 0 || bundle.Tally != nil || position != len(bundle.Events) {
			return Report{}, &Error{Code: "incomplete_audit_record"}
		}
		return report, nil
	}
	recomputed, err := app.RecomputeAggregate(bundle.Manifest, bundle.Ballots)
	if err != nil {
		return Report{}, err
	}
	expectedAggregate, _ := protocol.MarshalCanonical(recomputed)
	actualAggregate, _ := protocol.MarshalCanonical(bundle.Aggregate)
	if !bytes.Equal(expectedAggregate, actualAggregate) {
		return Report{}, &Error{Code: "aggregate_mismatch"}
	}
	report.AggregateHash = bundle.Aggregate.AggregateHash
	if err := expectEvent(bundle, &position, "poll_closed", bundle.Aggregate.AggregateHash); err != nil {
		return Report{}, err
	}
	if err := expectEvent(bundle, &position, "aggregate_published", bundle.Aggregate.AggregateHash); err != nil {
		return Report{}, err
	}
	seenTrustees := make(map[string]bool, len(bundle.Shares))
	for _, share := range bundle.Shares {
		if seenTrustees[share.TrusteeID] {
			return Report{}, &Error{Code: "duplicate_trustee_share"}
		}
		seenTrustees[share.TrusteeID] = true
		if err := app.VerifyTrusteeShare(bundle.Manifest, *bundle.Aggregate, share); err != nil {
			return Report{}, &Error{Code: "invalid_trustee_share", Err: err}
		}
		hash, err := app.HashTrusteeShare(share)
		if err != nil {
			return Report{}, err
		}
		if err := expectEvent(bundle, &position, "share_accepted", hash); err != nil {
			return Report{}, err
		}
		report.ValidTrusteeIDs = append(report.ValidTrusteeIDs, share.TrusteeID)
	}
	if bundle.Tally != nil {
		if len(bundle.Shares) < bundle.Manifest.Trustees.Quorum || bundle.Aggregate.BallotCount < bundle.Manifest.PrivacyThreshold {
			return Report{}, &Error{Code: "premature_tally"}
		}
		checkpointKey, err := checkpointKey(bundle.CheckpointKey)
		if err != nil {
			return Report{}, err
		}
		if err := app.VerifyTallyRecord(bundle.Manifest, *bundle.Aggregate, bundle.Shares, *bundle.Tally, checkpointKey); err != nil {
			return Report{}, &Error{Code: "invalid_tally", Err: err}
		}
		if err := expectEvent(bundle, &position, "tally_published", bundle.Tally.EvidenceHash); err != nil {
			return Report{}, err
		}
		report.Totals = append([]protocol.ChoiceTotal(nil), bundle.Tally.Totals...)
	} else if len(bundle.Shares) >= bundle.Manifest.Trustees.Quorum && bundle.Aggregate.BallotCount >= bundle.Manifest.PrivacyThreshold {
		return Report{}, &Error{Code: "missing_tally"}
	}
	if position != len(bundle.Events) {
		return Report{}, &Error{Code: "unexpected_audit_event"}
	}
	return report, nil
}

func expectEvent(bundle audit.Bundle, position *int, eventType, objectHash string) error {
	if *position >= len(bundle.Events) {
		return &Error{Code: "missing_audit_event", Err: fmt.Errorf("%s", eventType)}
	}
	event := bundle.Events[*position]
	if event.Type != eventType || event.ObjectHash != objectHash {
		return &Error{Code: "audit_object_mismatch", Err: fmt.Errorf("sequence %d", event.Sequence)}
	}
	*position++
	return nil
}

func checkpointKey(value string) (ed25519.PublicKey, error) {
	payload, ok := strings.CutPrefix(value, "ed25519:")
	decoded, err := hex.DecodeString(payload)
	if !ok || err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, &Error{Code: "invalid_checkpoint_key"}
	}
	return ed25519.PublicKey(decoded), nil
}
