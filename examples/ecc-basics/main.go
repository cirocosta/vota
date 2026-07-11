/*
Ristretto255 basics:

	private scalar: x
	base point:     G
	public key:     X = xG

Alice and Bob derive the same Diffie-Hellman point without sending their
private scalars:

	A = aG    B = bG
	aB = abG = bA

Points can be added. Scalars can be added. The distributive law connects them:

	A + B = aG + bG = (a + b)G

The program prints public points and equality checks. It does not print private
scalars or the shared Diffie-Hellman point.
*/
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/gtank/ristretto255"
)

type demonstration struct {
	alicePublic   string
	bobPublic     string
	sharedEqual   bool
	additionEqual bool
}

func demonstrate(random io.Reader) (demonstration, error) {
	aliceSecret, err := randomScalar(random)
	if err != nil {
		return demonstration{}, err
	}
	bobSecret, err := randomScalar(random)
	if err != nil {
		return demonstration{}, err
	}
	alicePublic := ristretto255.NewIdentityElement().ScalarBaseMult(aliceSecret)
	bobPublic := ristretto255.NewIdentityElement().ScalarBaseMult(bobSecret)
	aliceShared := ristretto255.NewIdentityElement().ScalarMult(aliceSecret, bobPublic)
	bobShared := ristretto255.NewIdentityElement().ScalarMult(bobSecret, alicePublic)
	publicSum := ristretto255.NewIdentityElement().Add(alicePublic, bobPublic)
	secretSum := ristretto255.NewScalar().Add(aliceSecret, bobSecret)
	expectedSum := ristretto255.NewIdentityElement().ScalarBaseMult(secretSum)
	return demonstration{
		alicePublic:   hex.EncodeToString(alicePublic.Bytes()),
		bobPublic:     hex.EncodeToString(bobPublic.Bytes()),
		sharedEqual:   aliceShared.Equal(bobShared) == 1,
		additionEqual: publicSum.Equal(expectedSum) == 1,
	}, nil
}

func randomScalar(random io.Reader) (*ristretto255.Scalar, error) {
	for range 128 {
		uniform := make([]byte, 64)
		if _, err := io.ReadFull(random, uniform); err != nil {
			return nil, fmt.Errorf("read scalar randomness: %w", err)
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
	result, err := demonstrate(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("alice public: %s\n", result.alicePublic)
	fmt.Printf("bob public:   %s\n", result.bobPublic)
	fmt.Printf("aB equals bA: %t\n", result.sharedEqual)
	fmt.Printf("A+B equals (a+b)G: %t\n", result.additionEqual)
}
