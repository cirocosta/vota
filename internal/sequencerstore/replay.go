package sequencerstore

import "fmt"

type chainEvent struct {
	pollID       string
	sequence     uint64
	previousHash string
	eventHash    string
	artifact     []byte
}

func ReplayCredit(events []CreditEvent) (string, error) {
	values := make([]chainEvent, len(events))
	for index, event := range events {
		values[index] = chainEvent{event.PollID, event.Sequence, event.PreviousHash, event.EventHash, event.Artifact}
	}
	return replay("credit", values)
}

func ReplayBallot(events []BallotEvent) (string, error) {
	values := make([]chainEvent, len(events))
	for index, event := range events {
		values[index] = chainEvent{event.PollID, event.Sequence, event.PreviousHash, event.EventHash, event.Artifact}
	}
	return replay("ballot", values)
}

func replay(stream string, events []chainEvent) (string, error) {
	previous := emptyHash
	for index, event := range events {
		expectedSequence := uint64(index + 1)
		if event.sequence != expectedSequence {
			return "", &Error{Code: "event_sequence_gap", Err: fmt.Errorf("expected %d", expectedSequence)}
		}
		if event.previousHash != previous {
			return "", &Error{Code: "event_chain_broken"}
		}
		expected := EventHash(stream, event.pollID, event.sequence, event.previousHash, event.artifact)
		if event.eventHash != expected {
			return "", &Error{Code: "event_hash_mismatch"}
		}
		previous = expected
	}
	return previous, nil
}
