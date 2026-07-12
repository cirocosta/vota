package app

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"slices"

	"github.com/cirocosta/vota/internal/crypto/election"
	"github.com/cirocosta/vota/internal/protocol"
)

// CreateTrusteeShare creates and signs one aggregate-only decryption share.
func CreateTrusteeShare(
	value protocol.Manifest,
	aggregate protocol.EncryptedAggregate,
	trusteeID string,
	secret election.TrusteeSecretShare,
	signingPrivateKey ed25519.PrivateKey,
	random io.Reader,
) (protocol.TrusteeShare, error) {
	if _, err := ParseAggregateMustMatch(value, aggregate); err != nil {
		return protocol.TrusteeShare{}, err
	}
	ceremony, encryptedAggregate, err := electionAggregate(value, aggregate)
	if err != nil {
		return protocol.TrusteeShare{}, err
	}
	member, trusteeIndex, err := trusteeByID(value, trusteeID)
	if err != nil {
		return protocol.TrusteeShare{}, err
	}
	if int(secret.TrusteeIndex) != trusteeIndex {
		return protocol.TrusteeShare{}, &Error{Code: "wrong_trustee_secret"}
	}
	if len(signingPrivateKey) != ed25519.PrivateKeySize || !signingPrivateKey.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(mustDecode(member.SigningKey, "ed25519", ed25519.PublicKeySize))) {
		return protocol.TrusteeShare{}, &Error{Code: "wrong_trustee_signing_key"}
	}
	aggregateHashBytes, _ := decodeHash(aggregate.AggregateHash)
	var aggregateHash [32]byte
	copy(aggregateHash[:], aggregateHashBytes)
	partial, err := election.CreateDecryptionShare(ceremony, secret, aggregateHash, encryptedAggregate, random)
	if err != nil {
		return protocol.TrusteeShare{}, &Error{Code: election.ErrorCode(err), Err: err}
	}
	share := protocol.TrusteeShare{
		SchemaVersion: protocol.SchemaVersion,
		Protocol:      protocol.ProtocolVersion,
		PollID:        value.PollID,
		TrusteeID:     trusteeID,
		AggregateHash: aggregate.AggregateHash,
		Shares:        make([]string, len(partial.Values)),
		Proofs:        make([]string, len(partial.Proofs)),
	}
	for index := range partial.Values {
		share.Shares[index] = "ristretto255:" + hex.EncodeToString(partial.Values[index][:])
		proof := make([]byte, election.ScalarSize*2)
		copy(proof[:election.ScalarSize], partial.Proofs[index].Challenge[:])
		copy(proof[election.ScalarSize:], partial.Proofs[index].Response[:])
		share.Proofs[index] = "vota-decryption-proof-v1:" + hex.EncodeToString(proof)
	}
	message, err := trusteeShareSignatureMessage(share)
	if err != nil {
		return protocol.TrusteeShare{}, err
	}
	share.Signature = "ed25519sig:" + hex.EncodeToString(ed25519.Sign(signingPrivateKey, message))
	return share, nil
}

func VerifyTrusteeShare(value protocol.Manifest, aggregate protocol.EncryptedAggregate, share protocol.TrusteeShare) error {
	if share.SchemaVersion != protocol.SchemaVersion || share.Protocol != protocol.ProtocolVersion || share.PollID != value.PollID || share.AggregateHash != aggregate.AggregateHash {
		return &Error{Code: "wrong_aggregate_hash"}
	}
	if _, err := ParseAggregateMustMatch(value, aggregate); err != nil {
		return err
	}
	ceremony, encryptedAggregate, err := electionAggregate(value, aggregate)
	if err != nil {
		return err
	}
	member, trusteeIndex, err := trusteeByID(value, share.TrusteeID)
	if err != nil {
		return err
	}
	partial, err := electionShare(share, trusteeIndex)
	if err != nil {
		return err
	}
	aggregateHashBytes, _ := decodeHash(aggregate.AggregateHash)
	var aggregateHash [32]byte
	copy(aggregateHash[:], aggregateHashBytes)
	if err := election.VerifyDecryptionShare(ceremony, aggregateHash, encryptedAggregate, partial); err != nil {
		return &Error{Code: election.ErrorCode(err), Err: err}
	}
	publicKey := ed25519.PublicKey(mustDecode(member.SigningKey, "ed25519", ed25519.PublicKeySize))
	signature := mustDecode(share.Signature, "ed25519sig", ed25519.SignatureSize)
	if publicKey == nil || signature == nil {
		return &Error{Code: "invalid_trustee_signature"}
	}
	message, err := trusteeShareSignatureMessage(share)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return &Error{Code: "invalid_trustee_signature"}
	}
	return nil
}

func ParseAggregateMustMatch(value protocol.Manifest, aggregate protocol.EncryptedAggregate) (protocol.EncryptedAggregate, error) {
	encoded, err := MarshalAggregate(aggregate)
	if err != nil {
		return protocol.EncryptedAggregate{}, err
	}
	parsed, err := ParseAggregate(encoded)
	if err != nil {
		return protocol.EncryptedAggregate{}, err
	}
	if parsed.PollID != value.PollID || len(parsed.Ciphertexts) != len(value.Choices) {
		return protocol.EncryptedAggregate{}, &Error{Code: "wrong_aggregate"}
	}
	return parsed, nil
}

func HashTrusteeShare(share protocol.TrusteeShare) (string, error) {
	hash, err := protocol.HashCanonical(protocol.DomainDecryptionShare, share)
	if err != nil {
		return "", &Error{Code: "trustee_share_hash_failed", Err: err}
	}
	return hash, nil
}

func VerifyTally(value protocol.Manifest, tally protocol.Tally, signingKey ed25519.PublicKey) error {
	if tally.SchemaVersion != protocol.SchemaVersion || tally.Protocol != protocol.ProtocolVersion || tally.PollID != value.PollID || len(tally.Totals) != len(value.Choices) {
		return &Error{Code: "invalid_tally"}
	}
	sum := 0
	for index, total := range tally.Totals {
		if total.ChoiceID != value.Choices[index].ID || total.Total < 0 || total.Total > tally.BallotCount {
			return &Error{Code: "invalid_tally"}
		}
		sum += total.Total
	}
	if sum != tally.BallotCount || !slices.IsSorted(tally.TrusteeIDs) {
		return &Error{Code: "tally_invariant_failed"}
	}
	unsigned := tally
	unsigned.EvidenceHash = ""
	unsigned.Signature = ""
	expected, err := protocol.HashCanonical(protocol.DomainTallyEvidence, unsigned)
	if err != nil {
		return &Error{Code: "tally_hash_failed", Err: err}
	}
	if expected != tally.EvidenceHash {
		return &Error{Code: "tally_evidence_mismatch"}
	}
	evidenceHash := mustDecode(tally.EvidenceHash, "sha256", 32)
	signature := mustDecode(tally.Signature, "ed25519sig", ed25519.SignatureSize)
	if len(signingKey) != ed25519.PublicKeySize || evidenceHash == nil || signature == nil || !ed25519.Verify(signingKey, lengthDelimitedDomain(protocol.DomainTallyEvidence, evidenceHash), signature) {
		return &Error{Code: "invalid_tally_signature"}
	}
	return nil
}

func trusteeByID(value protocol.Manifest, trusteeID string) (protocol.Trustee, int, error) {
	for _, member := range value.Trustees.Members {
		if member.ID != trusteeID {
			continue
		}
		commitment := mustDecode(member.Commitment, "vota-ceremony-commitment-v1", -1)
		if commitment == nil {
			return protocol.Trustee{}, 0, &Error{Code: "invalid_trustee_ceremony"}
		}
		contribution, err := election.ParsePublicContribution(commitment)
		if err != nil {
			return protocol.Trustee{}, 0, &Error{Code: "invalid_trustee_ceremony", Err: err}
		}
		return member, int(contribution.DealerIndex), nil
	}
	return protocol.Trustee{}, 0, &Error{Code: "unknown_trustee"}
}

func electionShare(share protocol.TrusteeShare, trusteeIndex int) (election.DecryptionShare, error) {
	if len(share.Shares) < election.MinChoices || len(share.Shares) > election.MaxChoices || len(share.Proofs) != len(share.Shares) {
		return election.DecryptionShare{}, &Error{Code: "invalid_decryption_share_size"}
	}
	aggregateHashBytes, err := decodeHash(share.AggregateHash)
	if err != nil {
		return election.DecryptionShare{}, &Error{Code: "wrong_aggregate_hash", Err: err}
	}
	partial := election.DecryptionShare{
		TrusteeIndex: uint16(trusteeIndex),
		Values:       make([]election.Point, len(share.Shares)),
		Proofs:       make([]election.EqualityProof, len(share.Proofs)),
	}
	copy(partial.AggregateHash[:], aggregateHashBytes)
	for index := range share.Shares {
		value := mustDecode(share.Shares[index], "ristretto255", election.PointSize)
		proof := mustDecode(share.Proofs[index], "vota-decryption-proof-v1", election.ScalarSize*2)
		if value == nil || proof == nil {
			return election.DecryptionShare{}, &Error{Code: "invalid_decryption_share"}
		}
		copy(partial.Values[index][:], value)
		copy(partial.Proofs[index].Challenge[:], proof[:election.ScalarSize])
		copy(partial.Proofs[index].Response[:], proof[election.ScalarSize:])
	}
	return partial, nil
}

func trusteeShareSignatureMessage(share protocol.TrusteeShare) ([]byte, error) {
	unsigned := share
	unsigned.Signature = ""
	canonical, err := protocol.MarshalCanonical(unsigned)
	if err != nil {
		return nil, &Error{Code: "trustee_share_encode_failed", Err: err}
	}
	return lengthDelimitedDomain(protocol.DomainDecryptionShare, canonical), nil
}

func lengthDelimitedDomain(domain string, fields ...[]byte) []byte {
	result := append([]byte(domain), 0)
	for _, field := range fields {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		result = append(result, length[:]...)
		result = append(result, field...)
	}
	return result
}

func mustDecode(value, prefix string, size int) []byte {
	var (
		decoded []byte
		err     error
	)
	if size >= 0 {
		decoded, err = decodeFixed(prefix, value, size)
	} else {
		decoded, err = decodeOpaque(prefix, value)
	}
	if err != nil {
		return nil
	}
	return decoded
}

func evidenceTally(value protocol.Manifest, aggregate protocol.EncryptedAggregate, evidence election.TallyEvidence) (protocol.Tally, error) {
	tally := protocol.Tally{
		SchemaVersion: protocol.SchemaVersion,
		Protocol:      protocol.ProtocolVersion,
		PollID:        value.PollID,
		BallotCount:   aggregate.BallotCount,
		AggregateHash: aggregate.AggregateHash,
		Totals:        make([]protocol.ChoiceTotal, len(value.Choices)),
		TrusteeIDs:    make([]string, len(evidence.TrusteeIndices)),
	}
	for index, choice := range value.Choices {
		tally.Totals[index] = protocol.ChoiceTotal{ChoiceID: choice.ID, Total: evidence.Totals[index]}
	}
	for index, trusteeIndex := range evidence.TrusteeIndices {
		found := false
		for _, member := range value.Trustees.Members {
			_, memberIndex, err := trusteeByID(value, member.ID)
			if err == nil && memberIndex == int(trusteeIndex) {
				tally.TrusteeIDs[index] = member.ID
				found = true
				break
			}
		}
		if !found {
			return protocol.Tally{}, &Error{Code: "unknown_trustee", Err: fmt.Errorf("index %d", trusteeIndex)}
		}
	}
	slices.Sort(tally.TrusteeIDs)
	unsigned := tally
	unsigned.EvidenceHash = ""
	unsigned.Signature = ""
	var err error
	tally.EvidenceHash, err = protocol.HashCanonical(protocol.DomainTallyEvidence, unsigned)
	if err != nil {
		return protocol.Tally{}, &Error{Code: "tally_hash_failed", Err: err}
	}
	return tally, nil
}
