package sshsig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const testNamespace = "vota-test@vota.local"

func TestSignThroughAgentSocketAndVerify(t *testing.T) {
	privateKey, publicKey := testKey(t, 0x41)
	socketPath := serveAgent(t, privateKey)
	t.Setenv("SSH_AUTH_SOCK", socketPath)

	encoded, err := Sign(context.Background(), ssh.MarshalAuthorizedKey(publicKey), testNamespace, []byte("team vote"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(publicKey, testNamespace, []byte("team vote"), encoded); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !bytes.HasPrefix(encoded, []byte("-----BEGIN SSH SIGNATURE-----\n")) {
		t.Fatalf("signature header = %q", encoded)
	}
}

func TestOpenSSHVerifiesGeneratedSignature(t *testing.T) {
	sshKeygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	vector := loadVector(t)
	publicKey, err := ParsePublicKey([]byte(vector.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	message := decodeBase64(t, vector.Message)
	signature := decodeBase64(t, vector.Signature)
	directory := t.TempDir()
	allowedPath := filepath.Join(directory, "allowed_signers")
	signaturePath := filepath.Join(directory, "message.sig")
	allowed := append([]byte("tester "), ssh.MarshalAuthorizedKey(publicKey)...)
	if err := os.WriteFile(allowedPath, allowed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(sshKeygen, "-Y", "verify", "-f", allowedPath, "-I", "tester", "-n", vector.Namespace, "-s", signaturePath)
	command.Stdin = bytes.NewReader(message)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen verify: %v\n%s", err, output)
	}
}

func TestDeterministicVector(t *testing.T) {
	vector := loadVector(t)
	message := decodeBase64(t, vector.Message)
	signature := decodeBase64(t, vector.Signature)
	publicKey, err := ParsePublicKey([]byte(vector.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(publicKey, vector.Namespace, message, signature); err != nil {
		t.Fatalf("verify fixture: %v", err)
	}

	privateKey, generatedPublicKey := testKey(t, 0x42)
	if !bytes.Equal(publicKey.Marshal(), generatedPublicKey.Marshal()) {
		t.Fatal("fixture public key does not match deterministic key")
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		t.Fatal(err)
	}
	generated, err := signWithAgent(keyring, publicKey, vector.Namespace, message)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generated, signature) {
		t.Fatal("generated signature does not match fixture")
	}
}

func TestVerifyRejectsChangedInputs(t *testing.T) {
	privateKey, publicKey := testKey(t, 0x43)
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		t.Fatal(err)
	}
	signature, err := signWithAgent(keyring, publicKey, testNamespace, []byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	_, otherPublic := testKey(t, 0x44)
	tests := []struct {
		name      string
		key       ssh.PublicKey
		namespace string
		message   []byte
		signature []byte
		code      string
	}{
		{name: "namespace", key: publicKey, namespace: "other@vota.local", message: []byte("message"), signature: signature, code: "wrong_ssh_signature_namespace"},
		{name: "message", key: publicKey, namespace: testNamespace, message: []byte("changed"), signature: signature, code: "invalid_ssh_signature"},
		{name: "key", key: otherPublic, namespace: testNamespace, message: []byte("message"), signature: signature, code: "wrong_ssh_signature_key"},
		{name: "encoding", key: publicKey, namespace: testNamespace, message: []byte("message"), signature: []byte("not an sshsig"), code: "invalid_ssh_signature_encoding"},
		{name: "empty namespace", key: publicKey, namespace: "", message: []byte("message"), signature: signature, code: "invalid_ssh_signature_namespace"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := Verify(test.key, test.namespace, test.message, test.signature); ErrorCode(err) != test.code {
				t.Fatalf("error = %v, want %s", err, test.code)
			}
		})
	}

	block, _ := pem.Decode(signature)
	block.Bytes[len(block.Bytes)-1] ^= 1
	mutated := pem.EncodeToMemory(block)
	if err := Verify(publicKey, testNamespace, []byte("message"), mutated); ErrorCode(err) != "invalid_ssh_signature" {
		t.Fatalf("mutated signature error = %v", err)
	}
}

func TestPublicKeyParsingAndAgentSelection(t *testing.T) {
	privateKey, publicKey := testKey(t, 0x45)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey))) + " developer@example\n"
	parsed, err := ParsePublicKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalPublicKey(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, bytes.TrimSpace(ssh.MarshalAuthorizedKey(publicKey))) {
		t.Fatalf("canonical key = %q", canonical)
	}
	fingerprint, err := Fingerprint(parsed)
	if err != nil || !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Fatalf("fingerprint = %q, error = %v", fingerprint, err)
	}

	emptyAgent := agent.NewKeyring()
	if _, err := signWithAgent(emptyAgent, publicKey, testNamespace, nil); ErrorCode(err) != "ssh_key_not_in_agent" {
		t.Fatalf("missing key error = %v", err)
	}
	if err := emptyAgent.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		t.Fatal(err)
	}
	if _, err := signWithAgent(emptyAgent, publicKey, "contains space", nil); ErrorCode(err) != "invalid_ssh_signature_namespace" {
		t.Fatalf("namespace error = %v", err)
	}
}

func TestRejectsUnsupportedAndMalformedKeys(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaPublic, err := ssh.NewPublicKey(&ecdsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicKey(ssh.MarshalAuthorizedKey(ecdsaPublic)); ErrorCode(err) != "unsupported_ssh_key_type" {
		t.Fatalf("unsupported key error = %v", err)
	}
	if err := Verify(ecdsaPublic, testNamespace, nil, []byte("signature")); ErrorCode(err) != "unsupported_ssh_key_type" {
		t.Fatalf("unsupported verification key error = %v", err)
	}
	if _, err := ParsePublicKey([]byte("ssh-ed25519 invalid")); ErrorCode(err) != "invalid_ssh_public_key" {
		t.Fatalf("malformed key error = %v", err)
	}
	_, publicKey := testKey(t, 0x46)
	twoKeys := append(ssh.MarshalAuthorizedKey(publicKey), ssh.MarshalAuthorizedKey(publicKey)...)
	if _, err := ParsePublicKey(twoKeys); ErrorCode(err) != "invalid_ssh_public_key" {
		t.Fatalf("multiple key error = %v", err)
	}
}

func TestMissingAgentSocket(t *testing.T) {
	_, publicKey := testKey(t, 0x47)
	t.Setenv("SSH_AUTH_SOCK", "")
	if _, err := Sign(context.Background(), ssh.MarshalAuthorizedKey(publicKey), testNamespace, nil); ErrorCode(err) != "ssh_agent_unavailable" {
		t.Fatalf("missing agent error = %v", err)
	}
}

func testKey(tb testing.TB, fill byte) (ed25519.PrivateKey, ssh.PublicKey) {
	tb.Helper()
	seed := bytes.Repeat([]byte{fill}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		tb.Fatal(err)
	}
	return privateKey, publicKey
}

type testVector struct {
	PublicKey string `json:"public_key"`
	Namespace string `json:"namespace"`
	Message   string `json:"message_base64"`
	Signature string `json:"signature_base64"`
}

func loadVector(tb testing.TB) testVector {
	tb.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "openssh_ed25519.json"))
	if err != nil {
		tb.Fatal(err)
	}
	var vector testVector
	if err := json.Unmarshal(data, &vector); err != nil {
		tb.Fatal(err)
	}
	return vector
}

func decodeBase64(tb testing.TB, value string) []byte {
	tb.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		tb.Fatal(err)
	}
	return decoded
}

func serveAgent(tb testing.TB, privateKey ed25519.PrivateKey) string {
	tb.Helper()
	directory, err := os.MkdirTemp("", "vota-agent-")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "agent.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		tb.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		listener.Close()
		tb.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_ = agent.ServeAgent(keyring, connection)
	}()
	tb.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	return path
}
