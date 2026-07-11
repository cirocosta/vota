package app

import (
	"context"
	"encoding/hex"

	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/store"
)

type PollStatus struct {
	Manifest      protocol.Manifest   `json:"manifest"`
	State         string              `json:"state"`
	Checkpoint    protocol.Checkpoint `json:"checkpoint"`
	CheckpointKey string              `json:"checkpoint_key"`
}

func (service *Service) Ready(ctx context.Context) error {
	if err := service.store.Ping(ctx); err != nil {
		return &Error{Code: store.ErrorCode(err), Err: err}
	}
	return nil
}

func (service *Service) PollStatus(ctx context.Context, pollID string) (PollStatus, error) {
	poll, err := service.store.Poll(ctx, pollID)
	if err != nil {
		return PollStatus{}, &Error{Code: store.ErrorCode(err), Err: err}
	}
	frozen, err := manifest.Parse(poll.Manifest)
	if err != nil {
		return PollStatus{}, &Error{Code: "invalid_stored_manifest", Err: err}
	}
	checkpointRecord, err := service.store.LatestCheckpoint(ctx, pollID)
	if err != nil {
		return PollStatus{}, &Error{Code: store.ErrorCode(err), Err: err}
	}
	var checkpoint protocol.Checkpoint
	if err := protocol.DecodeStrict(checkpointRecord.Artifact, &checkpoint); err != nil {
		return PollStatus{}, &Error{Code: "invalid_stored_checkpoint", Err: err}
	}
	return PollStatus{
		Manifest:      frozen.Manifest(),
		State:         poll.State,
		Checkpoint:    checkpoint,
		CheckpointKey: "ed25519:" + hex.EncodeToString(service.CheckpointPublicKey()),
	}, nil
}
