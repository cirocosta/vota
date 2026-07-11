package voter

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cirocosta/vota/internal/app"
	"github.com/cirocosta/vota/internal/crypto/lrs"
	"github.com/cirocosta/vota/internal/keystore"
	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/creack/pty"
	"github.com/spf13/cobra"
)

var testKDF = keystore.KDFParams{Time: 1, MemoryKiB: 8 * 1024, Threads: 1, KeyLength: 32}

func TestIdentityCreateAndEnrollmentExport(t *testing.T) {
	directory := t.TempDir()
	identityPath := filepath.Join(directory, "voter.key")
	enrollmentPath := filepath.Join(directory, "enrollment.json")
	draftID := "sha256:" + strings.Repeat("42", 32)

	create := commandRoot(testOptions())
	create.SetArgs([]string{"identity", "create", "--poll", draftID, "--out", identityPath})
	if err := create.Execute(); err != nil {
		t.Fatalf("create identity: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(identityPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("identity permissions = %o", info.Mode().Perm())
		}
	}

	export := commandRoot(testOptions())
	export.SetArgs([]string{"identity", "enroll", "export", "--identity", identityPath, "--out", enrollmentPath})
	if err := export.Execute(); err != nil {
		t.Fatalf("export enrollment: %v", err)
	}
	var enrollment protocol.Enrollment
	encoded, err := os.ReadFile(enrollmentPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.DecodeStrict(encoded, &enrollment); err != nil {
		t.Fatal(err)
	}
	if enrollment.PollDraftID != draftID {
		t.Fatalf("draft ID = %s", enrollment.PollDraftID)
	}
	if err := manifest.VerifyEnrollment(enrollment); err != nil {
		t.Fatalf("verify enrollment: %v", err)
	}
}

func TestVoteCastCreatesPrivateBallotWithoutChoiceDisclosure(t *testing.T) {
	directory := t.TempDir()
	manifestPath := copyManifestFixture(t, directory)
	identityPath := filepath.Join(directory, "voter.key")
	ballotPath := filepath.Join(directory, "ballot.json")
	writeIdentity(t, identityPath, fixtureVoterKey(t), fixtureManifest(t).PollDraftID)

	options := testOptions()
	options.ReadChoice = func(value protocol.Manifest) (int, error) {
		for index, choice := range value.Choices {
			if choice.ID == "green" {
				return index, nil
			}
		}
		return 0, io.EOF
	}
	command := commandRoot(options)
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"vote", "cast", "--poll", manifestPath, "--identity", identityPath, "--out", ballotPath})
	if err := command.Execute(); err != nil {
		t.Fatalf("cast vote: %v", err)
	}
	encoded, err := os.ReadFile(ballotPath)
	if err != nil {
		t.Fatal(err)
	}
	ballot, err := app.ParseBallot(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.VerifyBallot(fixtureManifest(t), ballot); err != nil {
		t.Fatalf("verify ballot: %v", err)
	}
	for _, disclosed := range []string{"green", "Green"} {
		if strings.Contains(output.String(), disclosed) || bytes.Contains(encoded, []byte(disclosed)) {
			t.Fatalf("choice disclosed as %q", disclosed)
		}
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(ballotPath)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("ballot permissions = %o", info.Mode().Perm())
		}
	}
}

func TestVoteCastChoiceStdinAcceptsOneIDAndHasNoChoiceFlag(t *testing.T) {
	directory := t.TempDir()
	manifestPath := copyManifestFixture(t, directory)
	identityPath := filepath.Join(directory, "voter.key")
	writeIdentity(t, identityPath, fixtureVoterKey(t), fixtureManifest(t).PollDraftID)
	command := commandRoot(testOptions())
	command.SetIn(strings.NewReader("green\n"))
	command.SetArgs([]string{"vote", "cast", "--choice-stdin", "--poll", manifestPath, "--identity", identityPath, "--out", filepath.Join(directory, "ballot.json")})
	if err := command.Execute(); err != nil {
		t.Fatalf("cast from stdin: %v", err)
	}
	walkCommands(t, command)
}

func TestDefaultChoiceReaderUsesTerminalWithoutEcho(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PTY semantics are unavailable")
	}
	primary, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	defer terminal.Close()
	originalStdin := os.Stdin
	os.Stdin = terminal
	defer func() { os.Stdin = originalStdin }()

	type result struct {
		selected int
		err      error
	}
	readDone := make(chan result, 1)
	go func() {
		selected, readErr := defaultReadChoice(fixtureManifest(t))
		readDone <- result{selected: selected, err: readErr}
	}()
	time.Sleep(10 * time.Millisecond)
	if _, err := primary.Write([]byte("green\n")); err != nil {
		t.Fatal(err)
	}
	read := <-readDone
	if read.err != nil {
		t.Fatalf("read terminal choice: %v", read.err)
	}
	selected := read.selected
	if fixtureManifest(t).Choices[selected].ID != "green" {
		t.Fatalf("selected choice = %s", fixtureManifest(t).Choices[selected].ID)
	}
	_ = terminal.Close()
	buffer := make([]byte, 128)
	_ = primary.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	count, _ := primary.Read(buffer)
	if strings.Contains(string(buffer[:count]), "green") {
		t.Fatalf("terminal echoed private choice: %q", buffer[:count])
	}
}

func TestVoteCastRejectsTrailingChoiceInput(t *testing.T) {
	manifest := fixtureManifest(t)
	if _, err := readChoiceFrom(strings.NewReader("green blue\n"), manifest); err == nil || err.Error() != "invalid_choice" {
		t.Fatalf("error = %v", err)
	}
}

func TestVoteCastValidatesBeforeChoicePrompt(t *testing.T) {
	tests := []struct {
		name       string
		manifestOK bool
		eligible   bool
		now        time.Time
	}{
		{name: "invalid manifest", now: time.Date(2026, 8, 1, 13, 0, 0, 0, time.UTC)},
		{name: "not eligible", manifestOK: true, now: time.Date(2026, 8, 1, 13, 0, 0, 0, time.UTC)},
		{name: "expired", manifestOK: true, eligible: true, now: time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			manifestPath := filepath.Join(directory, "manifest.json")
			if test.manifestOK {
				fixture, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "manifest", "canonical.json"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(manifestPath, fixture, 0o644); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(manifestPath, []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
			key := fixtureVoterKey(t)
			if !test.eligible {
				key, _, _ = lrs.GenerateKey(newHashReader("outsider"))
			}
			identityPath := filepath.Join(directory, "voter.key")
			writeIdentity(t, identityPath, key, fixtureManifest(t).PollDraftID)
			calls := 0
			options := testOptions()
			options.Now = func() time.Time { return test.now }
			options.ReadChoice = func(protocol.Manifest) (int, error) { calls++; return 0, nil }
			command := commandRoot(options)
			command.SetArgs([]string{"vote", "cast", "--poll", manifestPath, "--identity", identityPath, "--out", filepath.Join(directory, "ballot.json")})
			if err := command.Execute(); err == nil {
				t.Fatal("expected cast failure")
			}
			if calls != 0 {
				t.Fatalf("choice reader calls = %d", calls)
			}
		})
	}
}

func commandRoot(options Options) *cobra.Command {
	root := &cobra.Command{Use: "vota", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(Commands(options)...)
	return root
}

func testOptions() Options {
	return Options{
		Rand:       newHashReader("voter-options"),
		Now:        func() time.Time { return time.Date(2026, 8, 1, 13, 0, 0, 0, time.UTC) },
		KDF:        testKDF,
		ReadSecret: func(string, int) ([]byte, error) { return []byte("test-passphrase"), nil },
	}
}

func fixtureManifest(tb testing.TB) protocol.Manifest {
	tb.Helper()
	encoded, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "manifest", "canonical.json"))
	if err != nil {
		tb.Fatal(err)
	}
	frozen, err := manifest.Parse(encoded)
	if err != nil {
		tb.Fatal(err)
	}
	return frozen.Manifest()
}

func copyManifestFixture(tb testing.TB, directory string) string {
	tb.Helper()
	path := filepath.Join(directory, "manifest.json")
	encoded, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "manifest", "canonical.json"))
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		tb.Fatal(err)
	}
	return path
}

func fixtureVoterKey(tb testing.TB) lrs.PrivateKey {
	tb.Helper()
	privateKey, _, err := lrs.GenerateKey(newHashReader("voter-0"))
	if err != nil {
		tb.Fatal(err)
	}
	return privateKey
}

func writeIdentity(tb testing.TB, path string, privateKey lrs.PrivateKey, draftID string) {
	tb.Helper()
	publicKey, err := lrs.Public(privateKey)
	if err != nil {
		tb.Fatal(err)
	}
	material, _ := protocol.MarshalCanonical(identityMaterial{
		PollDraftID: draftID,
		PrivateKey:  "ristretto255scalar:" + hex.EncodeToString(privateKey[:]),
		PublicKey:   "ristretto255:" + hex.EncodeToString(publicKey[:]),
	})
	sealed, err := keystore.Seal(keystore.RoleVoter, "fixture-voter", material, []byte("test-passphrase"), keystore.Options{
		KDF: testKDF, Rand: newHashReader("seal-voter"), Now: func() time.Time { return time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(path, sealed, 0o600); err != nil {
		tb.Fatal(err)
	}
}

func walkCommands(tb testing.TB, command *cobra.Command) {
	tb.Helper()
	for _, forbidden := range []string{"choice", "passphrase", "token"} {
		if command.Flags().Lookup(forbidden) != nil {
			tb.Fatalf("command %s exposes %s", command.CommandPath(), forbidden)
		}
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
