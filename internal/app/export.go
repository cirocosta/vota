package app

import (
	"context"

	"github.com/cirocosta/vota/internal/audit"
	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/store"
)

// ExportAudit returns the complete public record available for one poll.
func (service *Service) ExportAudit(ctx context.Context, pollID string) ([]byte, error) {
	poll, err := service.store.Poll(ctx, pollID)
	if err != nil {
		return nil, &Error{Code: store.ErrorCode(err), Err: err}
	}
	frozen, err := manifest.Parse(poll.Manifest)
	if err != nil {
		return nil, &Error{Code: "invalid_stored_manifest", Err: err}
	}
	eventRecords, err := service.store.Events(ctx, pollID)
	if err != nil {
		return nil, &Error{Code: store.ErrorCode(err), Err: err}
	}
	events := make([]protocol.AuditEvent, len(eventRecords))
	for index, record := range eventRecords {
		if err := protocol.DecodeStrict(record.Artifact, &events[index]); err != nil {
			return nil, &Error{Code: "invalid_stored_event", Err: err}
		}
	}
	checkpointRecords, err := service.store.Checkpoints(ctx, pollID)
	if err != nil {
		return nil, &Error{Code: store.ErrorCode(err), Err: err}
	}
	checkpoints := make([]protocol.Checkpoint, len(checkpointRecords))
	for index, record := range checkpointRecords {
		if err := protocol.DecodeStrict(record.Artifact, &checkpoints[index]); err != nil {
			return nil, &Error{Code: "invalid_stored_checkpoint", Err: err}
		}
	}
	ballotRecords, err := service.store.Ballots(ctx, pollID)
	if err != nil {
		return nil, &Error{Code: store.ErrorCode(err), Err: err}
	}
	ballots := make([]protocol.BallotEnvelope, len(ballotRecords))
	for index, record := range ballotRecords {
		if err := protocol.DecodeStrict(record.Artifact, &ballots[index]); err != nil {
			return nil, &Error{Code: "invalid_stored_ballot", Err: err}
		}
	}
	var aggregate *protocol.EncryptedAggregate
	if len(poll.Aggregate) > 0 {
		value, err := ParseAggregate(poll.Aggregate)
		if err != nil {
			return nil, err
		}
		aggregate = &value
	}
	shareRecords, err := service.store.TrusteeShares(ctx, pollID)
	if err != nil {
		return nil, &Error{Code: store.ErrorCode(err), Err: err}
	}
	shares := make([]protocol.TrusteeShare, len(shareRecords))
	for index, record := range shareRecords {
		if err := protocol.DecodeStrict(record.Artifact, &shares[index]); err != nil {
			return nil, &Error{Code: "invalid_stored_trustee_share", Err: err}
		}
	}
	var tally *protocol.Tally
	tallyRecord, err := service.store.Tally(ctx, pollID)
	if err == nil {
		var value protocol.Tally
		if err := protocol.DecodeStrict(tallyRecord.Artifact, &value); err != nil {
			return nil, &Error{Code: "invalid_stored_tally", Err: err}
		}
		tally = &value
	} else if store.ErrorCode(err) != "tally_not_found" {
		return nil, &Error{Code: store.ErrorCode(err), Err: err}
	}
	return audit.Export(audit.Bundle{
		SchemaVersion: protocol.SchemaVersion,
		Protocol:      protocol.ProtocolVersion,
		Manifest:      frozen.Manifest(),
		Events:        events,
		Ballots:       ballots,
		Aggregate:     aggregate,
		Shares:        shares,
		Tally:         tally,
		Checkpoints:   checkpoints,
	}, service.CheckpointPublicKey())
}
