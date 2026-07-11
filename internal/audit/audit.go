// Package audit creates and verifies Vota's public append-only record.
package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cirocosta/vota/internal/protocol"
)

const zeroHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

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
	return "internal_error"
}

// Genesis creates the first event for a poll.
func Genesis(pollID, eventType, objectHash string, acceptedAt time.Time) (protocol.AuditEvent, error) {
	return Append(nil, pollID, eventType, objectHash, acceptedAt)
}

// Append creates the next canonical event after the supplied chain.
func Append(events []protocol.AuditEvent, pollID, eventType, objectHash string, acceptedAt time.Time) (protocol.AuditEvent, error) {
	if _, err := decodeHash(pollID); err != nil {
		return protocol.AuditEvent{}, &Error{Code: "invalid_poll_id", Err: err}
	}
	if _, err := decodeHash(objectHash); err != nil {
		return protocol.AuditEvent{}, &Error{Code: "invalid_object_hash", Err: err}
	}
	if !validEventType(eventType) {
		return protocol.AuditEvent{}, &Error{Code: "invalid_event_type"}
	}
	if acceptedAt.IsZero() {
		return protocol.AuditEvent{}, &Error{Code: "invalid_event_time"}
	}
	sequence := uint64(1)
	previousHash := zeroHash
	if len(events) > 0 {
		if _, err := Replay(events); err != nil {
			return protocol.AuditEvent{}, err
		}
		last := events[len(events)-1]
		if last.PollID != pollID {
			return protocol.AuditEvent{}, &Error{Code: "wrong_poll"}
		}
		sequence = last.Sequence + 1
		previousHash = last.EventHash
		lastTime, _ := time.Parse(time.RFC3339, last.AcceptedAt)
		if acceptedAt.UTC().Before(lastTime) {
			return protocol.AuditEvent{}, &Error{Code: "invalid_event_time"}
		}
	}
	event := protocol.AuditEvent{
		SchemaVersion: protocol.SchemaVersion,
		Protocol:      protocol.ProtocolVersion,
		PollID:        pollID,
		Sequence:      sequence,
		Type:          eventType,
		ObjectHash:    objectHash,
		PreviousHash:  previousHash,
		AcceptedAt:    acceptedAt.UTC().Format(time.RFC3339),
	}
	hash, err := eventHash(event)
	if err != nil {
		return protocol.AuditEvent{}, err
	}
	event.EventHash = hash
	return event, nil
}

// Replay validates every link and returns the final event hash.
func Replay(events []protocol.AuditEvent) (string, error) {
	if len(events) == 0 {
		return zeroHash, nil
	}
	pollID := events[0].PollID
	previous := zeroHash
	var previousTime time.Time
	for index, event := range events {
		if event.SchemaVersion != protocol.SchemaVersion || event.Protocol != protocol.ProtocolVersion || event.PollID != pollID || event.Sequence != uint64(index+1) || event.PreviousHash != previous || !validEventType(event.Type) {
			return "", &Error{Code: "audit_chain_mismatch", Err: fmt.Errorf("sequence %d", index+1)}
		}
		if _, err := decodeHash(event.PollID); err != nil {
			return "", &Error{Code: "audit_chain_mismatch", Err: err}
		}
		if _, err := decodeHash(event.ObjectHash); err != nil {
			return "", &Error{Code: "audit_chain_mismatch", Err: err}
		}
		parsedTime, err := time.Parse(time.RFC3339, event.AcceptedAt)
		if err != nil || parsedTime.UTC().Format(time.RFC3339) != event.AcceptedAt || (!previousTime.IsZero() && parsedTime.Before(previousTime)) {
			return "", &Error{Code: "audit_chain_mismatch", Err: fmt.Errorf("invalid time at sequence %d", event.Sequence)}
		}
		expected, err := eventHash(event)
		if err != nil || expected != event.EventHash {
			return "", &Error{Code: "audit_chain_mismatch", Err: fmt.Errorf("event hash at sequence %d", event.Sequence)}
		}
		previous = event.EventHash
		previousTime = parsedTime
	}
	return previous, nil
}

func eventHash(event protocol.AuditEvent) (string, error) {
	unsigned := event
	unsigned.EventHash = ""
	hash, err := protocol.HashCanonical(protocol.DomainAuditEvent, unsigned)
	if err != nil {
		return "", &Error{Code: "event_hash_failed", Err: err}
	}
	return hash, nil
}

func validEventType(value string) bool {
	switch value {
	case "poll_published", "ballot_accepted", "poll_closed", "aggregate_published", "share_accepted", "tally_published":
		return true
	default:
		return false
	}
}

func decodeHash(value string) ([]byte, error) {
	payload, ok := strings.CutPrefix(value, "sha256:")
	if !ok {
		return nil, fmt.Errorf("missing sha256 prefix")
	}
	decoded, err := hex.DecodeString(payload)
	if err != nil || len(decoded) != sha256.Size || payload != strings.ToLower(payload) {
		return nil, fmt.Errorf("invalid sha256 value")
	}
	return decoded, nil
}

func signedFields(domain string, fields ...[]byte) []byte {
	message := append([]byte(domain), 0)
	for _, field := range fields {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		message = append(message, length[:]...)
		message = append(message, field...)
	}
	return message
}
