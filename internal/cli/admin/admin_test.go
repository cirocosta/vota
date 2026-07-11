package admin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cirocosta/vota/internal/crypto/election"
	"github.com/cirocosta/vota/internal/crypto/lrs"
	"github.com/cirocosta/vota/internal/keystore"
	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/spf13/cobra"
)

var cliTestKDF = keystore.KDFParams{Time: 1, MemoryKiB: 8 * 1024, Threads: 1, KeyLength: 32}

func TestFreezeMatchesCanonicalManifestFixture(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	draftPath := filepath.Join(directory, "poll.draft.json")
	keyPath := filepath.Join(directory, "admin.key")
	manifestPath := filepath.Join(directory, "manifest.json")
	writeFixtureAdminKey(t, keyPath)
	draft := fixtureDraft(t)
	draftBytes, _ := protocol.MarshalCanonical(draft)
	if err := os.WriteFile(draftPath, draftBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	command := commandRoot(testOptions(true))
	command.SetArgs([]string{"poll", "freeze", "--yes", "--draft", draftPath, "--admin-key", keyPath, "--out", manifestPath})
	if err := command.Execute(); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	got, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "manifest", "canonical.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.TrimSpace(want)) {
		t.Fatalf("manifest differs:\n%s", got)
	}
	var updated DraftFile
	if err := readStrict(draftPath, &updated); err != nil || !updated.Frozen {
		t.Fatalf("updated draft = %+v, error = %v", updated, err)
	}
}

func TestFreezeRequiresConfirmation(t *testing.T) {
	t.Parallel()

	options := testOptions(false)
	command := commandRoot(options)
	command.SetArgs([]string{"poll", "freeze", "--draft", "unused", "--admin-key", "unused", "--out", "unused"})
	if err := command.Execute(); err == nil || err.Error() != "freeze_cancelled" {
		t.Fatalf("error = %v", err)
	}
}

func TestAdminKeyCreateUsesOwnerOnlyFileAndNoValueSecretFlag(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission semantics are unavailable")
	}
	output := filepath.Join(t.TempDir(), "admin.key")
	options := testOptions(true)
	options.Rand = newHashReader("admin-create")
	command := commandRoot(options)
	command.SetArgs([]string{"admin", "key", "create", "--out", output})
	if err := command.Execute(); err != nil {
		t.Fatalf("create: %v", err)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions = %o", info.Mode().Perm())
	}
	for _, root := range command.Commands() {
		walkCommands(t, root)
	}
}

func TestPollHelpIncludesExperimentalWarning(t *testing.T) {
	t.Parallel()

	command := commandRoot(testOptions(true))
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"poll", "--help"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "not suitable for real elections") {
		t.Fatalf("help = %s", output.String())
	}
}

func commandRoot(options Options) *cobra.Command {
	root := &cobra.Command{Use: "vota", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(Commands(options)...)
	return root
}

func testOptions(confirm bool) Options {
	return Options{
		Rand: newHashReader("options"),
		Now:  func() time.Time { return time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC) },
		KDF:  cliTestKDF,
		ReadSecret: func(string, int) ([]byte, error) {
			return []byte("test-passphrase"), nil
		},
		Confirm: func(string) (bool, error) { return confirm, nil },
	}
}

func writeFixtureAdminKey(tb testing.TB, path string) {
	tb.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	material, _ := protocol.MarshalCanonical(adminKeyMaterial{PrivateKey: "ed25519priv:" + hex.EncodeToString(privateKey)})
	sealed, err := keystore.Seal(keystore.RoleAdmin, "fixture-admin", material, []byte("test-passphrase"), keystore.Options{
		KDF:  cliTestKDF,
		Rand: newHashReader("seal-admin"),
		Now:  func() time.Time { return time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(path, sealed, 0o600); err != nil {
		tb.Fatal(err)
	}
}

func fixtureDraft(tb testing.TB) DraftFile {
	tb.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	trustees := make([]TrusteeConfig, 3)
	manifestTrustees := make([]manifest.Trustee, 3)
	for index := range 3 {
		contribution, err := election.GenerateDealerContribution(index+1, 3, 2, newHashReader(fmt.Sprintf("dealer-%d", index)))
		if err != nil {
			tb.Fatal(err)
		}
		public := contribution.Public()
		commitment, _ := public.MarshalBinary()
		signingKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(0x51 + index)}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
		trustees[index] = TrusteeConfig{
			ID:         fmt.Sprintf("trustee-%d", index+1),
			SigningKey: "ed25519:" + hex.EncodeToString(signingKey),
			Commitment: "vota-ceremony-commitment-v1:" + hex.EncodeToString(commitment),
		}
		manifestTrustees[index] = manifest.Trustee{ID: trustees[index].ID, SigningKey: signingKey, Contribution: public}
	}
	draft := DraftFile{
		SchemaVersion: protocol.SchemaVersion,
		Protocol:      protocol.ProtocolVersion,
		Config: PollConfig{
			Question: "Which release color?",
			Choices:  []protocol.Choice{{ID: "green", Label: "Green"}, {ID: "blue", Label: "Blue"}},
			Trustees: trustees, TrusteeQuorum: 2, PrivacyThreshold: 2,
			OpensAt: "2026-08-01T12:00:00Z", ClosesAt: "2026-08-02T12:00:00Z",
		},
		AuthorityKey: "ed25519:" + hex.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
		Enrollments:  []protocol.Enrollment{},
	}
	manifestDraft := manifest.Draft{
		Question: draft.Config.Question, Choices: draft.Config.Choices, Trustees: manifestTrustees,
		TrusteeQuorum: 2, PrivacyThreshold: 2,
		OpensAt: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC), ClosesAt: time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC),
		AuthorityKey: privateKey.Public().(ed25519.PublicKey),
	}
	draftID, err := manifest.DraftID(manifestDraft)
	if err != nil {
		tb.Fatal(err)
	}
	for index := range 3 {
		voterKey, _, _ := lrs.GenerateKey(newHashReader(fmt.Sprintf("voter-%d", index)))
		enrollment, err := manifest.CreateEnrollment(draftID, voterKey, newHashReader(fmt.Sprintf("enrollment-%d", index)))
		if err != nil {
			tb.Fatal(err)
		}
		draft.Enrollments = append(draft.Enrollments, enrollment)
	}
	return draft
}

func walkCommands(tb testing.TB, command *cobra.Command) {
	tb.Helper()
	if command.Flags().Lookup("passphrase") != nil || command.Flags().Lookup("admin-token") != nil || command.Flags().Lookup("token") != nil {
		tb.Fatalf("command %s exposes a value secret flag", command.CommandPath())
	}
	for _, child := range command.Commands() {
		walkCommands(tb, child)
	}
}

type hashReader struct {
	seed    []byte
	counter uint64
	buffer  []byte
}

func newHashReader(seed string) io.Reader { return &hashReader{seed: []byte(seed)} }

func (reader *hashReader) Read(output []byte) (int, error) {
	written := 0
	for written < len(output) {
		if len(reader.buffer) == 0 {
			input := append([]byte(nil), reader.seed...)
			input = append(input, byte(reader.counter>>56), byte(reader.counter>>48), byte(reader.counter>>40), byte(reader.counter>>32), byte(reader.counter>>24), byte(reader.counter>>16), byte(reader.counter>>8), byte(reader.counter))
			digest := sha512.Sum512(input)
			reader.buffer = append(reader.buffer[:0], digest[:]...)
			reader.counter++
		}
		count := copy(output[written:], reader.buffer)
		reader.buffer = reader.buffer[count:]
		written += count
	}
	return written, nil
}
