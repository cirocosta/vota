package app

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	"github.com/cirocosta/vota/internal/crypto/election"
	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
)

// RecomputeAggregate verifies ordered ballots and recreates their aggregate.
func RecomputeAggregate(value protocol.Manifest, ballots []protocol.BallotEnvelope) (protocol.EncryptedAggregate, error) {
	if err := manifest.Verify(value); err != nil {
		return protocol.EncryptedAggregate{}, &Error{Code: "invalid_manifest", Err: err}
	}
	if len(ballots) == 0 {
		return protocol.EncryptedAggregate{}, &Error{Code: "no_accepted_ballots"}
	}
	manifestHash, err := ManifestHash(value)
	if err != nil {
		return protocol.EncryptedAggregate{}, err
	}
	binding, electionKey, _, err := artifactContext(value, manifestHash)
	if err != nil {
		return protocol.EncryptedAggregate{}, err
	}
	verified := make([]election.EncryptedBallot, len(ballots))
	hashes := make([]string, len(ballots))
	for index, ballot := range ballots {
		if err := VerifyBallot(value, ballot); err != nil {
			return protocol.EncryptedAggregate{}, &Error{Code: "invalid_ballot", Err: fmt.Errorf("index %d: %w", index, err)}
		}
		verified[index], err = electionBallot(value, ballot)
		if err != nil {
			return protocol.EncryptedAggregate{}, err
		}
		hashes[index] = ballot.BallotHash
	}
	aggregate, err := election.AggregateBallots(binding, electionKey, verified)
	if err != nil {
		return protocol.EncryptedAggregate{}, &Error{Code: election.ErrorCode(err), Err: err}
	}
	return protocolAggregate(value.PollID, hashes, aggregate)
}

// VerifyTallyRecord recreates tally evidence from verified aggregate shares.
func VerifyTallyRecord(
	value protocol.Manifest,
	aggregate protocol.EncryptedAggregate,
	shares []protocol.TrusteeShare,
	tally protocol.Tally,
	signingKey ed25519.PublicKey,
) error {
	if err := VerifyTally(value, tally, signingKey); err != nil {
		return err
	}
	ceremony, encryptedAggregate, err := electionAggregate(value, aggregate)
	if err != nil {
		return err
	}
	partials := make([]election.DecryptionShare, len(shares))
	seen := make(map[string]bool, len(shares))
	for index, share := range shares {
		if seen[share.TrusteeID] {
			return &Error{Code: "duplicate_trustee_share"}
		}
		seen[share.TrusteeID] = true
		if err := VerifyTrusteeShare(value, aggregate, share); err != nil {
			return err
		}
		_, trusteeIndex, err := trusteeByID(value, share.TrusteeID)
		if err != nil {
			return err
		}
		partials[index], err = electionShare(share, trusteeIndex)
		if err != nil {
			return err
		}
	}
	aggregateHashBytes, err := decodeHash(aggregate.AggregateHash)
	if err != nil {
		return err
	}
	var aggregateHash [32]byte
	copy(aggregateHash[:], aggregateHashBytes)
	evidence, err := election.CombineTally(ceremony, aggregateHash, encryptedAggregate, partials)
	if err != nil {
		return &Error{Code: election.ErrorCode(err), Err: err}
	}
	expected, err := evidenceTally(value, aggregate, evidence)
	if err != nil {
		return err
	}
	expected.Signature = tally.Signature
	expectedBytes, _ := protocol.MarshalCanonical(expected)
	actualBytes, _ := protocol.MarshalCanonical(tally)
	if !bytes.Equal(expectedBytes, actualBytes) {
		return &Error{Code: "tally_evidence_mismatch"}
	}
	return nil
}
