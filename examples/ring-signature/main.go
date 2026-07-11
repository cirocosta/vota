/*
Linkable ring signature:

	public ring: P[0], P[1], ..., P[n-1]
	secret:      x where P[j] = xG
	message:     m

The signer creates one proof that verifies against the complete ring. The proof
does not carry an explicit signer index. A verifier learns that one ring member
signed, not which one.

Vota's LSAG proof also produces a deterministic key image I for the eligibility
scalar. Different messages signed by the same scalar have the same I, allowing
a collector to reject a second ballot without identifying the member.

In this implementation I does not include the poll ID. Reusing the same scalar
in another poll produces the same I and links participation. Vota's CLI avoids
ordinary reuse by creating an identity bound to one poll draft.
*/
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/cirocosta/vota/internal/crypto/lrs"
)

type demonstration struct {
	ringSize            int
	proofVerified       bool
	samePollLinked      bool
	crossPollLinked     bool
	changedMessageFails bool
	keyImage            string
}

func demonstrate(random io.Reader) (demonstration, error) {
	const signerIndex = 2
	ring := make([]lrs.PublicKey, 5)
	privateKeys := make([]lrs.PrivateKey, len(ring))
	for index := range ring {
		privateKey, publicKey, err := lrs.GenerateKey(random)
		if err != nil {
			return demonstration{}, err
		}
		privateKeys[index] = privateKey
		ring[index] = publicKey
	}
	pollID := sha256.Sum256([]byte("example poll"))
	message := sha256.Sum256([]byte("encrypted ballot A"))
	proof, err := lrs.Sign(pollID, message, ring, privateKeys[signerIndex], signerIndex, random)
	if err != nil {
		return demonstration{}, err
	}
	verified := lrs.Verify(pollID, message, ring, proof) == nil
	secondMessage := sha256.Sum256([]byte("encrypted ballot B"))
	second, err := lrs.Sign(pollID, secondMessage, ring, privateKeys[signerIndex], signerIndex, random)
	if err != nil {
		return demonstration{}, err
	}
	otherPollID := sha256.Sum256([]byte("another poll"))
	otherPoll, err := lrs.Sign(otherPollID, message, ring, privateKeys[signerIndex], signerIndex, random)
	if err != nil {
		return demonstration{}, err
	}
	changedMessage := sha256.Sum256([]byte("changed ballot"))
	return demonstration{
		ringSize:            len(ring),
		proofVerified:       verified,
		samePollLinked:      proof.KeyImage == second.KeyImage,
		crossPollLinked:     proof.KeyImage == otherPoll.KeyImage,
		changedMessageFails: lrs.Verify(pollID, changedMessage, ring, proof) != nil,
		keyImage:            hex.EncodeToString(proof.KeyImage[:]),
	}, nil
}

func main() {
	result, err := demonstrate(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("ring members: %d\n", result.ringSize)
	fmt.Printf("proof verifies: %t\n", result.proofVerified)
	fmt.Printf("key image: %s\n", result.keyImage)
	fmt.Printf("same scalar links two messages: %t\n", result.samePollLinked)
	fmt.Printf("reused scalar links two polls: %t\n", result.crossPollLinked)
	fmt.Printf("changed message fails verification: %t\n", result.changedMessageFails)
}
