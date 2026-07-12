package blind

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestRFC9474RandomizedVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "rfc9474-a1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector map[string]string
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	n := integerHex(t, vector["n"])
	e := integerHex(t, vector["e"])
	publicKey := &rsa.PublicKey{N: n, E: int(e.Int64())}
	message := bytesHex(t, vector["msg"])
	prefix := bytesHex(t, vector["msg_prefix"])
	prepared := append(append([]byte(nil), prefix...), message...)
	if !bytes.Equal(prepared, bytesHex(t, vector["prepared_msg"])) {
		t.Fatal("randomized preparation does not match RFC 9474")
	}
	encoded, err := encodePSS(prepared, publicKey.N.BitLen()-1, bytesHex(t, vector["salt"]))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, bytesHex(t, vector["encoded_msg"])) {
		t.Fatal("PSS encoding does not match RFC 9474")
	}
	inverse := integerHex(t, vector["inv"])
	factor := new(big.Int).ModInverse(inverse, publicKey.N)
	blinded, err := blindEncodedWithFactor(publicKey, encoded, factor)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blinded, bytesHex(t, vector["blinded_msg"])) {
		t.Fatal("blinded message does not match RFC 9474")
	}
	blindSignature := integerHex(t, vector["blind_sig"])
	unblinded := new(big.Int).Mul(blindSignature, inverse)
	unblinded.Mod(unblinded, publicKey.N)
	signature := leftPad(unblinded.Bytes(), publicKey.Size())
	if !bytes.Equal(signature, bytesHex(t, vector["sig"])) {
		t.Fatal("final signature does not match RFC 9474")
	}
	digest := sha512.Sum384(prepared)
	if err := rsa.VerifyPSS(publicKey, crypto.SHA384, digest[:], signature, &rsa.PSSOptions{SaltLength: SaltSize, Hash: crypto.SHA384}); err != nil {
		t.Fatalf("verify RFC signature: %v", err)
	}
}

func TestCredentialRoundTripAndBinding(t *testing.T) {
	privateKey := testPrivateKey(t)
	keyID := KeyID(&privateKey.PublicKey)
	serial := bytes.Repeat([]byte{0x42}, SerialSize)
	request, err := Prepare(&privateKey.PublicKey, "poll-one", keyID, serial, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blindSignature, err := BlindSign(privateKey, request.BlindedMessage, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := Finalize(&privateKey.PublicKey, request.State, blindSignature)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(&privateKey.PublicKey, "poll-one", credential); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		pollID     string
		credential Credential
	}{
		{name: "poll", pollID: "poll-two", credential: credential},
		{name: "key id", pollID: "poll-one", credential: mutateCredential(credential, func(value *Credential) { value.IssuerKeyID = "sha256:wrong" })},
		{name: "serial", pollID: "poll-one", credential: mutateCredential(credential, func(value *Credential) { value.Serial[0] ^= 1 })},
		{name: "signature", pollID: "poll-one", credential: mutateCredential(credential, func(value *Credential) { value.Signature[len(value.Signature)-1] ^= 1 })},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := Verify(&privateKey.PublicKey, test.pollID, test.credential); err == nil {
				t.Fatal("accepted changed credential")
			}
		})
	}
}

func TestFinalizeRejectsChangedResponseAndState(t *testing.T) {
	privateKey := testPrivateKey(t)
	keyID := KeyID(&privateKey.PublicKey)
	request, err := Prepare(&privateKey.PublicKey, "poll", keyID, bytes.Repeat([]byte{1}, SerialSize), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := BlindSign(privateKey, request.BlindedMessage, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 1
	if _, err := Finalize(&privateKey.PublicKey, request.State, signature); ErrorCode(err) != "invalid_blind_signature" {
		t.Fatalf("error = %v", err)
	}
	request.State.EncodedMessage[0] ^= 1
	if _, err := Finalize(&privateKey.PublicKey, request.State, make([]byte, privateKey.Size())); ErrorCode(err) != "invalid_blind_signature" {
		t.Fatalf("state error = %v", err)
	}
}

func TestKeyPersistenceAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "issuer.pem")
	first, created, err := LoadOrCreatePrivateKey(path)
	if err != nil || !created {
		t.Fatalf("create: created=%v err=%v", created, err)
	}
	second, created, err := LoadOrCreatePrivateKey(path)
	if err != nil || created || first.N.Cmp(second.N) != 0 {
		t.Fatalf("reload: created=%v err=%v", created, err)
	}
	encoded, err := EncodePublicKey(&first.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePublicKey(encoded)
	if err != nil || parsed.N.Cmp(first.N) != 0 {
		t.Fatalf("public key: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreatePrivateKey(path); ErrorCode(err) != "unsafe_issuer_key_permissions" {
		t.Fatalf("permission error = %v", err)
	}
}

func TestConcurrentKeyCreationKeepsOneKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "issuer.pem")
	keys := make([]*rsa.PrivateKey, 2)
	created := make([]bool, 2)
	errorsFound := make([]error, 2)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range keys {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			keys[index], created[index], errorsFound[index] = LoadOrCreatePrivateKey(path)
		}(index)
	}
	close(start)
	wait.Wait()
	if errorsFound[0] != nil || errorsFound[1] != nil {
		t.Fatalf("errors = %v", errorsFound)
	}
	if created[0] == created[1] {
		t.Fatalf("created = %v", created)
	}
	if keys[0].N.Cmp(keys[1].N) != 0 {
		t.Fatal("callers loaded different issuer keys")
	}
}

func FuzzVerify(f *testing.F) {
	privateKey := testPrivateKey(f)
	keyID := KeyID(&privateKey.PublicKey)
	request, err := Prepare(&privateKey.PublicKey, "poll", keyID, bytes.Repeat([]byte{2}, SerialSize), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	blindSignature, err := BlindSign(privateKey, request.BlindedMessage, rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	credential, err := Finalize(&privateKey.PublicKey, request.State, blindSignature)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(credential.Serial, credential.Signature)
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, serial, signature []byte) {
		_ = Verify(&privateKey.PublicKey, "poll", Credential{IssuerKeyID: keyID, Serial: serial, Signature: signature})
	})
}

func mutateCredential(input Credential, operation func(*Credential)) Credential {
	output := input
	output.Serial = append([]byte(nil), input.Serial...)
	output.Signature = append([]byte(nil), input.Signature...)
	operation(&output)
	return output
}

func testPrivateKey(tb testing.TB) *rsa.PrivateKey {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, MinRSAKeyBits)
	if err != nil {
		tb.Fatal(err)
	}
	return key
}

func bytesHex(tb testing.TB, value string) []byte {
	tb.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		tb.Fatal(err)
	}
	return decoded
}

func integerHex(tb testing.TB, value string) *big.Int {
	tb.Helper()
	integer := new(big.Int)
	if _, ok := integer.SetString(value, 16); !ok {
		tb.Fatal("invalid integer fixture")
	}
	return integer
}
