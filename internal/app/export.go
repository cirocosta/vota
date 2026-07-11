package app

import (
	"context"

	"github.com/cirocosta/vota/internal/audit"
	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/store"
)

// ExportAudit returns the currently implemented manifest, event, and checkpoint bundle.
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
	return audit.Export(audit.Bundle{
		SchemaVersion: protocol.SchemaVersion,
		Protocol:      protocol.ProtocolVersion,
		Manifest:      frozen.Manifest(),
		Events:        events,
		Checkpoints:   checkpoints,
	}, service.CheckpointPublicKey())
}
