package audit

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/cirocosta/vota/internal/protocol"
)

// CreateCheckpoint signs the exact head of a verified event chain.
func CreateCheckpoint(privateKey ed25519.PrivateKey, events []protocol.AuditEvent) (protocol.Checkpoint, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return protocol.Checkpoint{}, &Error{Code: "invalid_checkpoint_private_key"}
	}
	head, err := Replay(events)
	if err != nil {
		return protocol.Checkpoint{}, err
	}
	if len(events) == 0 {
		return protocol.Checkpoint{}, &Error{Code: "empty_audit_chain"}
	}
	last := events[len(events)-1]
	checkpoint := protocol.Checkpoint{
		SchemaVersion: protocol.SchemaVersion,
		Protocol:      protocol.ProtocolVersion,
		PollID:        last.PollID,
		Sequence:      last.Sequence,
		EventHash:     head,
	}
	checkpoint.CheckpointHash, err = checkpointHash(checkpoint)
	if err != nil {
		return protocol.Checkpoint{}, err
	}
	hashBytes, _ := decodeHash(checkpoint.CheckpointHash)
	signature := ed25519.Sign(privateKey, signedFields(protocol.DomainCheckpointSignature, hashBytes))
	checkpoint.Signature = "ed25519sig:" + hex.EncodeToString(signature)
	return checkpoint, nil
}

// VerifyCheckpoint validates a checkpoint hash and signature.
func VerifyCheckpoint(publicKey ed25519.PublicKey, checkpoint protocol.Checkpoint) error {
	if len(publicKey) != ed25519.PublicKeySize || checkpoint.SchemaVersion != protocol.SchemaVersion || checkpoint.Protocol != protocol.ProtocolVersion || checkpoint.Sequence < 1 {
		return &Error{Code: "invalid_checkpoint"}
	}
	if _, err := decodeHash(checkpoint.PollID); err != nil {
		return &Error{Code: "invalid_checkpoint", Err: err}
	}
	if _, err := decodeHash(checkpoint.EventHash); err != nil {
		return &Error{Code: "invalid_checkpoint", Err: err}
	}
	expected, err := checkpointHash(checkpoint)
	if err != nil || expected != checkpoint.CheckpointHash {
		return &Error{Code: "checkpoint_hash_mismatch", Err: err}
	}
	signature, err := decodeSignature(checkpoint.Signature)
	if err != nil {
		return &Error{Code: "invalid_checkpoint_signature", Err: err}
	}
	hashBytes, _ := decodeHash(checkpoint.CheckpointHash)
	if !ed25519.Verify(publicKey, signedFields(protocol.DomainCheckpointSignature, hashBytes), signature) {
		return &Error{Code: "invalid_checkpoint_signature"}
	}
	return nil
}

// CreateReceipt binds one accepted ballot to its event and checkpoint.
func CreateReceipt(
	privateKey ed25519.PrivateKey,
	ballotHash string,
	event protocol.AuditEvent,
	checkpoint protocol.Checkpoint,
) (protocol.Receipt, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return protocol.Receipt{}, &Error{Code: "invalid_checkpoint_private_key"}
	}
	if checkpoint.PollID != event.PollID || checkpoint.Sequence != event.Sequence || checkpoint.EventHash != event.EventHash || event.Type != "ballot_accepted" || event.ObjectHash != ballotHash {
		return protocol.Receipt{}, &Error{Code: "receipt_binding_mismatch"}
	}
	receipt := protocol.Receipt{
		SchemaVersion:  protocol.SchemaVersion,
		Protocol:       protocol.ProtocolVersion,
		PollID:         event.PollID,
		BallotHash:     ballotHash,
		Sequence:       event.Sequence,
		EventHash:      event.EventHash,
		CheckpointHash: checkpoint.CheckpointHash,
	}
	message, err := receiptMessage(receipt)
	if err != nil {
		return protocol.Receipt{}, err
	}
	receipt.Signature = "ed25519sig:" + hex.EncodeToString(ed25519.Sign(privateKey, message))
	return receipt, nil
}

// VerifyReceipt validates its signature and exact event and checkpoint binding.
func VerifyReceipt(
	publicKey ed25519.PublicKey,
	receipt protocol.Receipt,
	event protocol.AuditEvent,
	checkpoint protocol.Checkpoint,
) error {
	if receipt.SchemaVersion != protocol.SchemaVersion || receipt.Protocol != protocol.ProtocolVersion || receipt.PollID != event.PollID || receipt.BallotHash != event.ObjectHash || receipt.Sequence != event.Sequence || receipt.EventHash != event.EventHash || receipt.CheckpointHash != checkpoint.CheckpointHash || checkpoint.Sequence != event.Sequence || checkpoint.EventHash != event.EventHash {
		return &Error{Code: "receipt_binding_mismatch"}
	}
	if err := VerifyCheckpoint(publicKey, checkpoint); err != nil {
		return err
	}
	signature, err := decodeSignature(receipt.Signature)
	if err != nil {
		return &Error{Code: "invalid_receipt_signature", Err: err}
	}
	message, err := receiptMessage(receipt)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return &Error{Code: "invalid_receipt_signature"}
	}
	return nil
}

// CompareCheckpoints detects two signed histories at the same poll sequence.
func CompareCheckpoints(publicKey ed25519.PublicKey, first, second protocol.Checkpoint) error {
	if err := VerifyCheckpoint(publicKey, first); err != nil {
		return err
	}
	if err := VerifyCheckpoint(publicKey, second); err != nil {
		return err
	}
	if first.PollID == second.PollID && first.Sequence == second.Sequence && first.CheckpointHash != second.CheckpointHash {
		return &Error{Code: "audit_fork_detected"}
	}
	return nil
}

func checkpointHash(checkpoint protocol.Checkpoint) (string, error) {
	unsigned := checkpoint
	unsigned.CheckpointHash = ""
	unsigned.Signature = ""
	hash, err := protocol.HashCanonical(protocol.DomainCheckpointHash, unsigned)
	if err != nil {
		return "", &Error{Code: "checkpoint_hash_failed", Err: err}
	}
	return hash, nil
}

func receiptMessage(receipt protocol.Receipt) ([]byte, error) {
	pollID, err := decodeHash(receipt.PollID)
	if err != nil {
		return nil, &Error{Code: "invalid_receipt", Err: err}
	}
	ballotHash, err := decodeHash(receipt.BallotHash)
	if err != nil {
		return nil, &Error{Code: "invalid_receipt", Err: err}
	}
	eventHash, err := decodeHash(receipt.EventHash)
	if err != nil {
		return nil, &Error{Code: "invalid_receipt", Err: err}
	}
	checkpointHash, err := decodeHash(receipt.CheckpointHash)
	if err != nil {
		return nil, &Error{Code: "invalid_receipt", Err: err}
	}
	var sequence [8]byte
	binary.BigEndian.PutUint64(sequence[:], receipt.Sequence)
	return signedFields(protocol.DomainReceiptSignature, pollID, ballotHash, sequence[:], eventHash, checkpointHash), nil
}

func decodeSignature(value string) ([]byte, error) {
	payload, ok := strings.CutPrefix(value, "ed25519sig:")
	if !ok {
		return nil, fmt.Errorf("missing signature prefix")
	}
	decoded, err := hex.DecodeString(payload)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature")
	}
	return decoded, nil
}
