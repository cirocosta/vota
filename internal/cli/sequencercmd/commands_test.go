package sequencercmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestMemberFileCanonicalizesAndRejectsDuplicates(t *testing.T) {
	keys := []string{testPublicKey(t, 2), testPublicKey(t, 1), testPublicKey(t, 3)}
	path := filepath.Join(t.TempDir(), "team.keys")
	body := "bob " + keys[0] + "\nalice " + keys[1] + "\ncarol " + keys[2] + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	members, err := readMembers(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.IsSorted(members) || len(members) != 3 {
		t.Fatalf("members = %v", members)
	}
	if err := os.WriteFile(path, []byte("alice "+keys[0]+"\nbob "+keys[0]+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readMembers(path); err == nil || !strings.Contains(err.Error(), "duplicate member") {
		t.Fatalf("duplicate error = %v", err)
	}
}

func TestMemberFileRejectsUnsupportedKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _ := ssh.NewPublicKey(&privateKey.PublicKey)
	path := filepath.Join(t.TempDir(), "team.keys")
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(publicKey), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readMembers(path); err == nil {
		t.Fatal("unsupported key accepted")
	}
}

func TestDraftValidationHappensBeforeAgentUse(t *testing.T) {
	members := []string{testPublicKey(t, 1), testPublicKey(t, 2)}
	if err := validateDraft("Lunch?", []string{"Pizza", "pizza"}, "2026-07-12T16:00:00Z", members); err == nil || err.Error() != "duplicate choice" {
		t.Fatalf("duplicate choice error = %v", err)
	}
	if err := validateDraft("Lunch?", []string{"Pizza", "Ramen"}, "not-a-time", members); err == nil || err.Error() != "invalid closing time" {
		t.Fatalf("time error = %v", err)
	}
}

func TestVoteHasNoChoiceValueFlag(t *testing.T) {
	var voteFound bool
	for _, command := range Commands(Options{}) {
		if command.Name() != "vote" {
			continue
		}
		voteFound = true
		if command.Flags().Lookup("choice") != nil {
			t.Fatal("vote exposes a choice value in process arguments")
		}
		if command.Flags().Lookup("choice-stdin") == nil {
			t.Fatal("vote omits choice-stdin")
		}
	}
	if !voteFound {
		t.Fatal("vote command missing")
	}
}

func testPublicKey(tb testing.TB, fill byte) string {
	tb.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
	publicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		tb.Fatal(err)
	}
	return string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(publicKey)))
}
