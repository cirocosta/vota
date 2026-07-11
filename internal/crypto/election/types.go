// Package election implements Vota's experimental threshold election scheme.
package election

import (
	"errors"
	"fmt"
)

const (
	ScalarSize        = 32
	PointSize         = 32
	MinTrustees       = 2
	MaxTrustees       = 9
	MinChoices        = 2
	MaxChoices        = 10
	MaxBallots        = 256
	MaxCeremonyQuorum = MaxTrustees
)

type Scalar [ScalarSize]byte
type Point [PointSize]byte

type Binding struct {
	PollID       [32]byte
	ManifestHash [32]byte
}

type Ciphertext struct {
	A Point
	B Point
}

type BitProof struct {
	Challenges [2]Scalar
	Responses  [2]Scalar
}

type EqualityProof struct {
	Challenge Scalar
	Response  Scalar
}

type ValidityProof struct {
	Bits []BitProof
	Sum  EqualityProof
}

type EncryptedBallot struct {
	Ciphertexts []Ciphertext
	Proof       ValidityProof
}

type DealerContribution struct {
	DealerIndex uint16
	Commitments []Point
	shares      []Scalar
}

type PublicContribution struct {
	DealerIndex uint16
	Commitments []Point
}

type DealerShare struct {
	DealerIndex    uint16
	RecipientIndex uint16
	Value          Scalar
}

type Ceremony struct {
	TrusteeCount      int
	Quorum            int
	ElectionKey       Point
	TrusteePublicKeys []Point
}

type TrusteeSecretShare struct {
	TrusteeIndex uint16
	Value        Scalar
}

type Aggregate struct {
	BallotCount int
	Ciphertexts []Ciphertext
}

type DecryptionShare struct {
	TrusteeIndex  uint16
	AggregateHash [32]byte
	Values        []Point
	Proofs        []EqualityProof
}

type TallyEvidence struct {
	AggregateHash  [32]byte
	BallotCount    int
	Totals         []int
	TrusteeIndices []uint16
}

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
