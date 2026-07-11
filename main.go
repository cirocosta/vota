/*
ecc rules:

	- point on the curve can be added to or subtracted from another point
	  or itself
	- a point cacnnot be multipled or divided by another point


notation:

	- lowercase 'x': scalar (priv key)
	- uppercase 'P': public key
	- uppercase 'G': base / generator point

	(overall, lowercase == scalar, uppercase == point)


public key from private key:

	P = xG		(scalar mult of `x` over the base G)


ecdh (elliptic curve diffie-hellman):

	alice (a): A = aG
	bob (b):   B = bG

	alice's shared:	D  = aB
	bob's shared:	D' = bA

		D == D'

			- note that being a point, D must have a scalar 'd',
			  but that's only known if we know both private keys,
			  which is not the case in a normal setup where you're
			  either alice _or_ bob.


dual-key stealth addr:

	someone wants to send a payment to `bob`


	`bob`s public address is (A,B):
		- A, public view key (from `a`)
		- B, public private key (from `b`)
		- `a` and `b` (private keys) are not known to the sender


	sender:
		- generates a random scalar `r` (thus, public R, R = rG)
		- R is called the "one time public key" of the transaction


	given notation:

		- P:   	final stealth address (one-time output key,
			desttination where funds are sent to)
		- Hs:	hashing algo (keccak-256) that returns a scalar (hash
			output is interpreted as an integer and then `mod l`)
		- r:	random scalar chosen by the sender
		- A:	bob's public view key
		- G:	standard Ed25519 base point
		- B:	bob's public spend key


	we can generate the one-time stealth address:


		       N
		    .-----.
		P = Hs(rA)G + B
		|   |  '' |   |
		|   |  |  |   '- bob's public spend key
		|   |  |  |
		|   |  |  '----- base point
		|   |  |
		|   |  '-------- ECDH between random key and bob's public view
		|   |		 key (R = rG is attached to the txn)
		|   |
		|   '----------- hashing algo (keccak) producing a shared
		|                scalar `f`
		|
		'--------------- public one-time stealth address


	as there are no keys from the sender involved in these steps, from just
	the address point of view nothing can link back to the sender.

	note.: a stealth address is created _per output_. to allow for multiple
	outputs in a tx, an output idx is added to `rA` before hashing to
	create the shared scalar `f`

	note.: a view wallet requires (a,B), i.e., the private view key and the
	public spend key - in wallet-rpc, `B` comes from the primary address of
	the wallet.


*/
package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

var (
	ed25519Order = []byte{ // big-endian
		0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6,
		0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed,
	}

	keccak = sha3.NewLegacyKeccak256
)

type keypair struct {
	x [curve25519.ScalarSize]byte
	P [curve25519.PointSize]byte
}

// Hs(rA)
// where
//
// Hs == result of keccak over `rA` interpreted as a scalar mod l
//
func hs(D [curve25519.PointSize]byte) [curve25519.PointSize]byte {
	acc := keccak()
	_, _ = acc.Write(D[:]) // hash.Hash.Write always returns len(p), nil
	digest := acc.Sum(nil)
	reverse(digest)

	var order, scalar big.Int
	order.SetBytes(ed25519Order)
	scalar.SetBytes(digest)
	scalar.Mod(&scalar, &order)

	res := [curve25519.PointSize]byte{}
	scalar.FillBytes(res[:])
	reverse(res[:])
	return res
}

func reverse(data []byte) {
	for left, right := 0, len(data)-1; left < right; left, right = left+1, right-1 {
		data[left], data[right] = data[right], data[left]
	}
}

func random_scalar() [curve25519.ScalarSize]byte {
	var scalar [curve25519.ScalarSize]byte

	// setting up `x`, priv key (scalar)
	_, err := rand.Read(scalar[:])
	if err != nil {
		panic(err)
	}

	return scalar
}

func newkp() *keypair {
	kp := &keypair{
		x: random_scalar(),
	}

	// deriving `P`, pub key (P = xG)
	// ps.: "base" == G
	curve25519.ScalarBaseMult(&kp.P, &kp.x)

	return kp
}

func (p *keypair) dh(C [curve25519.PointSize]byte) ([curve25519.PointSize]byte, error) {
	var D [curve25519.PointSize]byte

	// deriving shared point `D` (D = xC)
	// i.e., our_priv * peer_pub
	shared, err := curve25519.X25519(p.x[:], C[:])
	if err != nil {
		return D, fmt.Errorf("derive shared secret: %w", err)
	}
	copy(D[:], shared)

	return D, nil
}

func (p *keypair) String() string {
	return fmt.Sprintf("\tpub:\t%x\n", p.P)
}

func encrypt(x [curve25519.PointSize]byte, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(x[:])
	if err != nil {
		return nil, err
	}

	nonce := make(
		[]byte,
		chacha20poly1305.NonceSize,
		chacha20poly1305.NonceSize+len(data)+aead.Overhead(),
	)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	return aead.Seal(nonce, nonce, data, nil), nil
}

func decrypt(x [curve25519.PointSize]byte, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(x[:])
	if err != nil {
		return nil, err
	}

	if len(data) < chacha20poly1305.NonceSize {
		return nil, fmt.Errorf(
			"ciphertext too short: got %d bytes, need at least %d",
			len(data),
			chacha20poly1305.NonceSize,
		)
	}

	nonce, ciphertext := data[:chacha20poly1305.NonceSize], data[chacha20poly1305.NonceSize:]
	return aead.Open(nil, nonce, ciphertext, nil)
}

func example_simple_diffiehellman_enc_dec() error {
	alice := newkp()
	bob := newkp()

	fmt.Println("alice", "\n", alice)
	fmt.Println("bob", "\n", bob)

	da, err := alice.dh(bob.P)
	if err != nil {
		return fmt.Errorf("alice key agreement: %w", err)
	}
	db, err := bob.dh(alice.P)
	if err != nil {
		return fmt.Errorf("bob key agreement: %w", err)
	}

	for _, v := range [][curve25519.PointSize]byte{da, db} {
		fmt.Printf("shared:\t\t%x\n", v)
	}

	ct, err := encrypt(da, []byte("foo"))
	if err != nil {
		return fmt.Errorf("encrypt message: %w", err)
	}
	t, err := decrypt(db, ct)
	if err != nil {
		return fmt.Errorf("decrypt message: %w", err)
	}

	fmt.Println(string(t))
	return nil
}

func main() {

	// sending from alice to bob
	bob_view := newkp()
	bob_spend := newkp()

	r := random_scalar()

	// D = rA
	var D [curve25519.PointSize]byte
	curve25519.ScalarMult(&D, &r, &bob_view.P)

	f := hs(D)

	fmt.Printf("bob view public:\t%x\n", bob_view.P)
	fmt.Printf("bob spend public:\t%x\n", bob_spend.P)
	fmt.Printf("shared scalar:\t\t%x\n", f)

	// P = Hs(rA)G + B
	// - P  	public stealth addr
	// - Hs  	keccack of `rA` mod l interpreted as a scalar
	// - G 		base point
	// - A		public view key
	// - B		public spend key

}
