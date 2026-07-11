/*
Dual-key one-time destination:

	recipient view key:   a, A = aG
	recipient spend key:  b, B = bG
	sender ephemeral key: r, R = rG

Both sides derive the same shared point:

	sender:    rA
	recipient: aR

For output index i, hash that point to scalar h. The sender publishes:

	P = hG + B

The recipient scans with private view key a and public spend key B. If the
derived P matches, private spend scalar p = h + b satisfies pG = P.

This uses Ristretto255 and SHA-512 to demonstrate the equations. It is not
Monero-compatible address or transaction code.
*/
package main

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/gtank/ristretto255"
)

type output struct {
	ephemeralPublic string
	destination     string
	sharedEqual     bool
	spendKeyMatches bool
}

func derive(random io.Reader, outputIndex uint64) (output, error) {
	viewSecret, err := randomNonzeroScalar(random)
	if err != nil {
		return output{}, err
	}
	spendSecret, err := randomNonzeroScalar(random)
	if err != nil {
		return output{}, err
	}
	ephemeralSecret, err := randomNonzeroScalar(random)
	if err != nil {
		return output{}, err
	}
	viewPublic := ristretto255.NewIdentityElement().ScalarBaseMult(viewSecret)
	spendPublic := ristretto255.NewIdentityElement().ScalarBaseMult(spendSecret)
	ephemeralPublic := ristretto255.NewIdentityElement().ScalarBaseMult(ephemeralSecret)
	senderShared := ristretto255.NewIdentityElement().ScalarMult(ephemeralSecret, viewPublic)
	recipientShared := ristretto255.NewIdentityElement().ScalarMult(viewSecret, ephemeralPublic)
	offset, err := hashToScalar(senderShared, outputIndex)
	if err != nil {
		return output{}, err
	}
	destination := ristretto255.NewIdentityElement().Add(
		ristretto255.NewIdentityElement().ScalarBaseMult(offset),
		spendPublic,
	)
	recipientOffset, err := hashToScalar(recipientShared, outputIndex)
	if err != nil {
		return output{}, err
	}
	oneTimeSecret := ristretto255.NewScalar().Add(recipientOffset, spendSecret)
	derivedPublic := ristretto255.NewIdentityElement().ScalarBaseMult(oneTimeSecret)
	return output{
		ephemeralPublic: hex.EncodeToString(ephemeralPublic.Bytes()),
		destination:     hex.EncodeToString(destination.Bytes()),
		sharedEqual:     senderShared.Equal(recipientShared) == 1,
		spendKeyMatches: destination.Equal(derivedPublic) == 1,
	}, nil
}

func hashToScalar(shared *ristretto255.Element, outputIndex uint64) (*ristretto255.Scalar, error) {
	hash := sha512.New()
	_, _ = hash.Write([]byte("vota:example:stealth-address"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(shared.Bytes())
	var index [8]byte
	binary.BigEndian.PutUint64(index[:], outputIndex)
	_, _ = hash.Write(index[:])
	return ristretto255.NewScalar().SetUniformBytes(hash.Sum(nil))
}

func randomNonzeroScalar(random io.Reader) (*ristretto255.Scalar, error) {
	for range 128 {
		uniform := make([]byte, 64)
		if _, err := io.ReadFull(random, uniform); err != nil {
			return nil, err
		}
		scalar, err := ristretto255.NewScalar().SetUniformBytes(uniform)
		if err != nil {
			return nil, err
		}
		if scalar.Equal(ristretto255.NewScalar()) != 1 {
			return scalar, nil
		}
	}
	return nil, fmt.Errorf("generated zero scalar repeatedly")
}

func main() {
	result, err := derive(rand.Reader, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("transaction public R: %s\n", result.ephemeralPublic)
	fmt.Printf("one-time destination P: %s\n", result.destination)
	fmt.Printf("rA equals aR: %t\n", result.sharedEqual)
	fmt.Printf("(h+b)G equals P: %t\n", result.spendKeyMatches)
}
