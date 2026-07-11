package app

import (
	"encoding/hex"
	"fmt"

	"github.com/cirocosta/vota/internal/crypto/election"
	"github.com/cirocosta/vota/internal/protocol"
)

func HashAggregate(aggregate protocol.EncryptedAggregate) (string, error) {
	unsigned := aggregate
	unsigned.AggregateHash = ""
	hash, err := protocol.HashCanonical(protocol.DomainAggregateHash, unsigned)
	if err != nil {
		return "", &Error{Code: "aggregate_hash_failed", Err: err}
	}
	return hash, nil
}

func MarshalAggregate(aggregate protocol.EncryptedAggregate) ([]byte, error) {
	encoded, err := protocol.MarshalCanonical(aggregate)
	if err != nil {
		return nil, &Error{Code: "aggregate_encode_failed", Err: err}
	}
	return encoded, nil
}

func ParseAggregate(encoded []byte) (protocol.EncryptedAggregate, error) {
	var aggregate protocol.EncryptedAggregate
	if err := protocol.DecodeStrict(encoded, &aggregate); err != nil {
		return protocol.EncryptedAggregate{}, &Error{Code: "invalid_aggregate", Err: err}
	}
	if aggregate.SchemaVersion != protocol.SchemaVersion || aggregate.Protocol != protocol.ProtocolVersion || aggregate.BallotCount < 1 || aggregate.BallotCount > election.MaxBallots || len(aggregate.BallotHashes) != aggregate.BallotCount || len(aggregate.Ciphertexts) < election.MinChoices || len(aggregate.Ciphertexts) > election.MaxChoices {
		return protocol.EncryptedAggregate{}, &Error{Code: "invalid_aggregate"}
	}
	for _, hash := range aggregate.BallotHashes {
		if _, err := decodeHash(hash); err != nil {
			return protocol.EncryptedAggregate{}, &Error{Code: "invalid_aggregate", Err: err}
		}
	}
	for _, ciphertext := range aggregate.Ciphertexts {
		payload, err := decodeOpaque("vota-elgamal-v1", ciphertext)
		if err != nil {
			return protocol.EncryptedAggregate{}, &Error{Code: "invalid_aggregate", Err: err}
		}
		if _, err := election.ParseCiphertext(payload); err != nil {
			return protocol.EncryptedAggregate{}, &Error{Code: "invalid_aggregate", Err: err}
		}
	}
	expected, err := HashAggregate(aggregate)
	if err != nil {
		return protocol.EncryptedAggregate{}, err
	}
	if expected != aggregate.AggregateHash {
		return protocol.EncryptedAggregate{}, &Error{Code: "aggregate_hash_mismatch"}
	}
	return aggregate, nil
}

func protocolAggregate(pollID string, ballotHashes []string, aggregate election.Aggregate) (protocol.EncryptedAggregate, error) {
	result := protocol.EncryptedAggregate{
		SchemaVersion: protocol.SchemaVersion,
		Protocol:      protocol.ProtocolVersion,
		PollID:        pollID,
		BallotCount:   aggregate.BallotCount,
		BallotHashes:  append([]string(nil), ballotHashes...),
		Ciphertexts:   make([]string, len(aggregate.Ciphertexts)),
	}
	for index, ciphertext := range aggregate.Ciphertexts {
		encoded, err := ciphertext.MarshalBinary()
		if err != nil {
			return protocol.EncryptedAggregate{}, &Error{Code: "aggregate_encode_failed", Err: err}
		}
		result.Ciphertexts[index] = "vota-elgamal-v1:" + hex.EncodeToString(encoded)
	}
	var err error
	result.AggregateHash, err = HashAggregate(result)
	if err != nil {
		return protocol.EncryptedAggregate{}, err
	}
	return result, nil
}

func electionAggregate(value protocol.Manifest, aggregate protocol.EncryptedAggregate) (election.Ceremony, election.Aggregate, error) {
	if aggregate.PollID != value.PollID || len(aggregate.Ciphertexts) != len(value.Choices) {
		return election.Ceremony{}, election.Aggregate{}, &Error{Code: "wrong_aggregate"}
	}
	ceremony, err := ceremonyFromManifest(value)
	if err != nil {
		return election.Ceremony{}, election.Aggregate{}, err
	}
	result := election.Aggregate{BallotCount: aggregate.BallotCount, Ciphertexts: make([]election.Ciphertext, len(aggregate.Ciphertexts))}
	for index, encoded := range aggregate.Ciphertexts {
		payload, err := decodeOpaque("vota-elgamal-v1", encoded)
		if err != nil {
			return election.Ceremony{}, election.Aggregate{}, &Error{Code: "invalid_aggregate", Err: err}
		}
		result.Ciphertexts[index], err = election.ParseCiphertext(payload)
		if err != nil {
			return election.Ceremony{}, election.Aggregate{}, &Error{Code: "invalid_aggregate", Err: err}
		}
	}
	return ceremony, result, nil
}

func ceremonyFromManifest(value protocol.Manifest) (election.Ceremony, error) {
	contributions := make([]election.PublicContribution, len(value.Trustees.Members))
	for index, trustee := range value.Trustees.Members {
		payload, err := decodeOpaque("vota-ceremony-commitment-v1", trustee.Commitment)
		if err != nil {
			return election.Ceremony{}, &Error{Code: "invalid_trustee_ceremony", Err: err}
		}
		contributions[index], err = election.ParsePublicContribution(payload)
		if err != nil {
			return election.Ceremony{}, &Error{Code: "invalid_trustee_ceremony", Err: err}
		}
	}
	ceremony, err := election.FinalizePublicCeremony(contributions)
	if err != nil || ceremony.Quorum != value.Trustees.Quorum {
		return election.Ceremony{}, &Error{Code: "invalid_trustee_ceremony", Err: err}
	}
	return ceremony, nil
}

func electionBallot(value protocol.Manifest, ballot protocol.BallotEnvelope) (election.EncryptedBallot, error) {
	result := election.EncryptedBallot{Ciphertexts: make([]election.Ciphertext, len(ballot.Ciphertexts))}
	for index, encoded := range ballot.Ciphertexts {
		payload, err := decodeOpaque("vota-elgamal-v1", encoded)
		if err != nil {
			return election.EncryptedBallot{}, &Error{Code: "invalid_stored_ballot", Err: err}
		}
		result.Ciphertexts[index], err = election.ParseCiphertext(payload)
		if err != nil {
			return election.EncryptedBallot{}, &Error{Code: "invalid_stored_ballot", Err: err}
		}
	}
	proof, err := decodeOpaque("vota-choice-proof-v1", ballot.ValidityProof)
	if err != nil {
		return election.EncryptedBallot{}, &Error{Code: "invalid_stored_ballot", Err: err}
	}
	result.Proof, err = election.ParseValidityProof(proof, len(value.Choices))
	if err != nil {
		return election.EncryptedBallot{}, &Error{Code: "invalid_stored_ballot", Err: err}
	}
	return result, nil
}

func validateAggregateBallotOrder(records []string, aggregate protocol.EncryptedAggregate) error {
	if len(records) != len(aggregate.BallotHashes) {
		return &Error{Code: "aggregate_ballot_mismatch"}
	}
	for index := range records {
		if records[index] != aggregate.BallotHashes[index] {
			return &Error{Code: "aggregate_ballot_mismatch", Err: fmt.Errorf("index %d", index)}
		}
	}
	return nil
}
