package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"time"

	"github.com/cirocosta/vota/internal/audit"
	"github.com/cirocosta/vota/internal/crypto/election"
	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/store"
)

// SubmitTrusteeShare verifies one aggregate share and publishes a tally at quorum.
func (service *Service) SubmitTrusteeShare(ctx context.Context, share protocol.TrusteeShare) (*protocol.Tally, bool, error) {
	poll, err := service.store.Poll(ctx, share.PollID)
	if err != nil {
		return nil, false, &Error{Code: store.ErrorCode(err), Err: err}
	}
	if len(poll.Aggregate) == 0 {
		return nil, false, &Error{Code: "poll_not_closed"}
	}
	frozen, err := manifest.Parse(poll.Manifest)
	if err != nil {
		return nil, false, &Error{Code: "invalid_stored_manifest", Err: err}
	}
	value := frozen.Manifest()
	aggregate, err := ParseAggregate(poll.Aggregate)
	if err != nil {
		return nil, false, &Error{Code: "invalid_stored_aggregate", Err: err}
	}
	if err := VerifyTrusteeShare(value, aggregate, share); err != nil {
		return nil, false, err
	}
	encodedShare, err := protocol.MarshalCanonical(share)
	if err != nil {
		return nil, false, &Error{Code: "trustee_share_encode_failed", Err: err}
	}
	shareHash, err := HashTrusteeShare(share)
	if err != nil {
		return nil, false, err
	}
	created := false
	var published *protocol.Tally
	now := service.now().UTC()
	err = service.store.Transaction(ctx, func(tx *store.Tx) error {
		current, err := tx.Poll(ctx, share.PollID)
		if err != nil {
			return &Error{Code: store.ErrorCode(err), Err: err}
		}
		if current.AggregateHash != share.AggregateHash {
			return &Error{Code: "wrong_aggregate_hash"}
		}
		existingShares, err := tx.TrusteeShares(ctx, share.PollID)
		if err != nil {
			return &Error{Code: store.ErrorCode(err), Err: err}
		}
		for _, existing := range existingShares {
			if existing.TrusteeID != share.TrusteeID {
				continue
			}
			if !bytes.Equal(existing.Artifact, encodedShare) {
				return &Error{Code: "duplicate_trustee_share"}
			}
			storedTally, tallyErr := tx.Tally(ctx, share.PollID)
			if tallyErr == nil {
				var value protocol.Tally
				if err := protocol.DecodeStrict(storedTally.Artifact, &value); err != nil {
					return &Error{Code: "invalid_stored_tally", Err: err}
				}
				published = &value
			} else if store.ErrorCode(tallyErr) != "tally_not_found" {
				return &Error{Code: store.ErrorCode(tallyErr), Err: tallyErr}
			}
			return nil
		}
		if current.State == "tallied" {
			return &Error{Code: "tally_final"}
		}
		if current.State != "closed" {
			return &Error{Code: "poll_not_closed"}
		}
		if err := tx.InsertTrusteeShare(ctx, store.TrusteeShare{
			PollID:        share.PollID,
			TrusteeID:     share.TrusteeID,
			AggregateHash: share.AggregateHash,
			ArtifactHash:  shareHash,
			Artifact:      encodedShare,
			SubmittedAt:   now.Format(time.RFC3339),
		}); err != nil {
			return &Error{Code: store.ErrorCode(err), Err: err}
		}
		events, err := loadEvents(ctx, tx, share.PollID)
		if err != nil {
			return err
		}
		shareEvent, err := audit.Append(events, share.PollID, "share_accepted", shareHash, now)
		if err != nil {
			return &Error{Code: audit.ErrorCode(err), Err: err}
		}
		events = append(events, shareEvent)
		created = true

		allShares, err := tx.TrusteeShares(ctx, share.PollID)
		if err != nil {
			return &Error{Code: store.ErrorCode(err), Err: err}
		}
		if len(allShares) < value.Trustees.Quorum || aggregate.BallotCount < value.PrivacyThreshold {
			checkpoint, err := audit.CreateCheckpoint(service.checkpointPrivateKey, events)
			if err != nil {
				return &Error{Code: audit.ErrorCode(err), Err: err}
			}
			if err := insertEventAndCheckpoint(ctx, tx, shareEvent, checkpoint); err != nil {
				return err
			}
			return service.runBeforeCommit()
		}
		if err := insertEvent(ctx, tx, shareEvent); err != nil {
			return err
		}
		ceremony, encryptedAggregate, err := electionAggregate(value, aggregate)
		if err != nil {
			return err
		}
		partials := make([]election.DecryptionShare, len(allShares))
		for index, record := range allShares {
			var artifact protocol.TrusteeShare
			if err := protocol.DecodeStrict(record.Artifact, &artifact); err != nil {
				return &Error{Code: "invalid_stored_trustee_share", Err: err}
			}
			if err := VerifyTrusteeShare(value, aggregate, artifact); err != nil {
				return &Error{Code: "invalid_stored_trustee_share", Err: err}
			}
			_, trusteeIndex, _ := trusteeByID(value, artifact.TrusteeID)
			partials[index], err = electionShare(artifact, trusteeIndex)
			if err != nil {
				return err
			}
		}
		aggregateHashBytes, _ := decodeHash(aggregate.AggregateHash)
		var aggregateHash [32]byte
		copy(aggregateHash[:], aggregateHashBytes)
		evidence, err := election.CombineTally(ceremony, aggregateHash, encryptedAggregate, partials)
		if err != nil {
			return &Error{Code: election.ErrorCode(err), Err: err}
		}
		tally, err := evidenceTally(value, aggregate, evidence)
		if err != nil {
			return err
		}
		evidenceHash := mustDecode(tally.EvidenceHash, "sha256", 32)
		tally.Signature = "ed25519sig:" + hex.EncodeToString(ed25519.Sign(service.checkpointPrivateKey, lengthDelimitedDomain(protocol.DomainTallyEvidence, evidenceHash)))
		if err := VerifyTally(value, tally, service.CheckpointPublicKey()); err != nil {
			return err
		}
		encodedTally, err := protocol.MarshalCanonical(tally)
		if err != nil {
			return &Error{Code: "tally_encode_failed", Err: err}
		}
		if err := tx.InsertTally(ctx, store.Tally{PollID: share.PollID, AggregateHash: aggregate.AggregateHash, EvidenceHash: tally.EvidenceHash, Artifact: encodedTally, CreatedAt: now.Format(time.RFC3339)}); err != nil {
			return &Error{Code: store.ErrorCode(err), Err: err}
		}
		tallyEvent, err := audit.Append(events, share.PollID, "tally_published", tally.EvidenceHash, now)
		if err != nil {
			return &Error{Code: audit.ErrorCode(err), Err: err}
		}
		events = append(events, tallyEvent)
		checkpoint, err := audit.CreateCheckpoint(service.checkpointPrivateKey, events)
		if err != nil {
			return &Error{Code: audit.ErrorCode(err), Err: err}
		}
		if err := insertEventAndCheckpoint(ctx, tx, tallyEvent, checkpoint); err != nil {
			return err
		}
		published = &tally
		return service.runBeforeCommit()
	})
	if err != nil {
		return nil, false, err
	}
	return published, created, nil
}

func (service *Service) Tally(ctx context.Context, pollID string) (protocol.Tally, error) {
	record, err := service.store.Tally(ctx, pollID)
	if err != nil {
		if store.ErrorCode(err) == "tally_not_found" {
			poll, pollErr := service.store.Poll(ctx, pollID)
			if pollErr != nil {
				return protocol.Tally{}, &Error{Code: store.ErrorCode(pollErr), Err: pollErr}
			}
			if len(poll.Aggregate) > 0 {
				frozen, manifestErr := manifest.Parse(poll.Manifest)
				aggregate, aggregateErr := ParseAggregate(poll.Aggregate)
				if manifestErr == nil && aggregateErr == nil && aggregate.BallotCount < frozen.Manifest().PrivacyThreshold {
					return protocol.Tally{}, &Error{Code: "privacy_threshold_not_met"}
				}
			}
			return protocol.Tally{}, &Error{Code: "tally_unavailable"}
		}
		return protocol.Tally{}, &Error{Code: store.ErrorCode(err), Err: err}
	}
	var tally protocol.Tally
	if err := protocol.DecodeStrict(record.Artifact, &tally); err != nil {
		return protocol.Tally{}, &Error{Code: "invalid_stored_tally", Err: err}
	}
	return tally, nil
}
