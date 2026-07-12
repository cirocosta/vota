package trustee

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cirocosta/vota/internal/app"
	"github.com/cirocosta/vota/internal/crypto/election"
	"github.com/cirocosta/vota/internal/httpapi"
	"github.com/cirocosta/vota/internal/keystore"
	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/store"
	"github.com/spf13/cobra"
)

var testKDF = keystore.KDFParams{Time: 1, MemoryKiB: 8 * 1024, Threads: 1, KeyLength: 32}

func TestCeremonyCommandsEncryptSharesAndReproduceManifestCommitments(t *testing.T) {
	directory := t.TempDir()
	contributionDir := filepath.Join(directory, "contributions")
	if err := os.Mkdir(contributionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	participants := make([]Participant, 3)
	keyPaths := make([]string, 3)
	for index := range 3 {
		keyPaths[index] = filepath.Join(directory, fmt.Sprintf("trustee-%d.key", index+1))
		publicPath := filepath.Join(directory, fmt.Sprintf("trustee-%d.public.json", index+1))
		command := commandRoot(options(fmt.Sprintf("key-%d", index)))
		command.SetArgs([]string{"trustee", "key", "create", "--id", fmt.Sprintf("trustee-%d", index+1), "--out", keyPaths[index], "--public-out", publicPath})
		if err := command.Execute(); err != nil {
			t.Fatalf("create key %d: %v", index, err)
		}
		if err := readStrict(publicPath, &participants[index]); err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" {
			info, _ := os.Stat(keyPaths[index])
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("key permissions = %o", info.Mode().Perm())
			}
		}
	}
	slices.SortFunc(participants, func(a, b Participant) int { return strings.Compare(a.ID, b.ID) })
	config := CeremonyConfig{SchemaVersion: protocol.SchemaVersion, Protocol: protocol.ProtocolVersion, Quorum: 2, Trustees: participants}
	configPath := filepath.Join(directory, "config.json")
	requestPath := filepath.Join(directory, "request.json")
	writeCanonical(t, configPath, config)
	initCommand := commandRoot(options("init"))
	initCommand.SetArgs([]string{"trustee", "ceremony", "init", "--config", configPath, "--out", requestPath})
	if err := initCommand.Execute(); err != nil {
		t.Fatalf("init ceremony: %v", err)
	}

	for index := range 3 {
		path := filepath.Join(contributionDir, fmt.Sprintf("trustee-%d.json", index+1))
		command := commandRoot(options(fmt.Sprintf("dealer-%d", index)))
		command.SetArgs([]string{"trustee", "ceremony", "contribute", "--input", requestPath, "--key", keyPaths[index], "--out", path})
		if err := command.Execute(); err != nil {
			t.Fatalf("contribute %d: %v", index, err)
		}
		encoded, _ := os.ReadFile(path)
		dealer, err := election.GenerateDealerContribution(index+1, 3, 2, newHashReader(fmt.Sprintf("dealer-%d", index)))
		if err != nil {
			t.Fatal(err)
		}
		for recipient := 1; recipient <= 3; recipient++ {
			share, _ := dealer.ShareFor(recipient)
			shareBytes, _ := share.MarshalBinary()
			if bytes.Contains(encoded, []byte(hex.EncodeToString(shareBytes))) {
				t.Fatalf("contribution %d exposes recipient %d share", index, recipient)
			}
		}
	}

	finalPath := filepath.Join(directory, "trustee-1.final.key")
	publicPath := filepath.Join(directory, "ceremony.public.json")
	finalize := commandRoot(options("finalize"))
	finalize.SetArgs([]string{"trustee", "ceremony", "finalize", "--input-dir", contributionDir, "--request", requestPath, "--key", keyPaths[0], "--out", finalPath, "--public-out", publicPath})
	if err := finalize.Execute(); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	var public PublicCeremony
	if err := readStrict(publicPath, &public); err != nil {
		t.Fatal(err)
	}
	fixture := fixtureManifest(t)
	if public.ElectionKey != fixture.Trustees.ElectionPublicKey {
		t.Fatalf("election key = %s", public.ElectionKey)
	}
	for index := range public.Trustees {
		if public.Trustees[index].Commitment != fixture.Trustees.Members[index].Commitment {
			t.Fatalf("commitment %d differs from manifest fixture", index)
		}
	}
	material, passphrase, err := unlockKey(options("unlock"), finalPath, -1)
	clear(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if material.TrusteeIndex != 1 || material.SecretShare == "" {
		t.Fatalf("finalized material = %+v", material)
	}
	walkCommands(t, commandRoot(options("flags")))
}

func TestTallyShareCommandAcceptsOnlyValidAggregateRecord(t *testing.T) {
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "manifest.json")
	fixtureManifestBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "manifest", "canonical.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, fixtureManifestBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	value := fixtureManifest(t)
	database, err := store.Open(context.Background(), filepath.Join(directory, "vota.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	checkpointKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	service, err := app.NewService(database, checkpointKey, app.ServiceOptions{Now: func() time.Time { return time.Date(2026, 8, 1, 13, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.PublishPoll(context.Background(), bytes.TrimSpace(fixtureManifestBytes)); err != nil {
		t.Fatal(err)
	}
	ballotBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "app", "ballot.json"))
	if err != nil {
		t.Fatal(err)
	}
	ballot, err := app.ParseBallot(bytes.TrimSpace(ballotBytes))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.AcceptBallot(context.Background(), ballot); err != nil {
		t.Fatal(err)
	}
	aggregate, _, err := service.ClosePoll(context.Background(), value.PollID)
	if err != nil {
		t.Fatal(err)
	}
	aggregatePath := filepath.Join(directory, "aggregate.json")
	writeCanonical(t, aggregatePath, aggregate)

	contributions := make([]election.DealerContribution, 3)
	public := make([]election.PublicContribution, 3)
	for index := range 3 {
		contributions[index], err = election.GenerateDealerContribution(index+1, 3, 2, newHashReader(fmt.Sprintf("dealer-%d", index)))
		if err != nil {
			t.Fatal(err)
		}
		public[index] = contributions[index].Public()
	}
	dealerShares := make([]election.DealerShare, 3)
	for index := range 3 {
		dealerShares[index], _ = contributions[index].ShareFor(1)
	}
	secret, err := election.FinalizeTrusteeShare(public, dealerShares, 1)
	if err != nil {
		t.Fatal(err)
	}
	signingPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	transportPrivate, err := ecdhPrivateForTest()
	if err != nil {
		t.Fatal(err)
	}
	material := keyMaterial{
		TrusteeID: "trustee-1", SigningPrivate: "ed25519priv:" + hex.EncodeToString(signingPrivate),
		TransportPrivate: "x25519priv:" + hex.EncodeToString(transportPrivate), TrusteeIndex: 1,
		SecretShare: "ristretto255scalar:" + hex.EncodeToString(secret.Value[:]),
	}
	keyPath := filepath.Join(directory, "trustee.key")
	writeTrusteeKey(t, keyPath, material)
	sharePath := filepath.Join(directory, "share.json")
	command := commandRoot(options("share"))
	command.SetArgs([]string{"trustee", "tally-share", "--poll", manifestPath, "--aggregate", aggregatePath, "--key", keyPath, "--out", sharePath})
	if err := command.Execute(); err != nil {
		t.Fatalf("create tally share: %v", err)
	}
	var share protocol.TrusteeShare
	if err := readStrict(sharePath, &share); err != nil {
		t.Fatal(err)
	}
	if err := app.VerifyTrusteeShare(value, aggregate, share); err != nil {
		t.Fatalf("verify tally share: %v", err)
	}

	prettyShare, err := json.MarshalIndent(share, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	prettySharePath := filepath.Join(directory, "pretty-share.json")
	if err := os.WriteFile(prettySharePath, prettyShare, 0o644); err != nil {
		t.Fatal(err)
	}
	api, err := httpapi.New(httpapi.Config{Service: service})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	submit := commandRoot(options("submit-share"))
	submit.SetOut(io.Discard)
	submit.SetArgs([]string{"tally", "submit-share", "--share", prettySharePath, "--server", server.URL})
	if err := submit.Execute(); err == nil || !strings.Contains(err.Error(), "noncanonical_json") {
		t.Fatalf("submit share error = %v", err)
	}

	invalidPath := filepath.Join(directory, "ballot-as-aggregate.json")
	if err := os.WriteFile(invalidPath, ballotBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	invalid := commandRoot(options("invalid"))
	invalid.SetArgs([]string{"trustee", "tally-share", "--poll", manifestPath, "--aggregate", invalidPath, "--key", keyPath, "--out", filepath.Join(directory, "invalid-share.json")})
	if err := invalid.Execute(); err == nil {
		t.Fatal("individual ballot accepted as aggregate")
	}
}

func commandRoot(options Options) *cobra.Command {
	root := &cobra.Command{Use: "vota", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(Commands(options)...)
	return root
}

func options(seed string) Options {
	return Options{Rand: newHashReader(seed), Now: func() time.Time { return time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC) }, KDF: testKDF, ReadSecret: func(string, int) ([]byte, error) { return []byte("test-passphrase"), nil }}
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

func writeCanonical(tb testing.TB, path string, value any) {
	tb.Helper()
	encoded, err := protocol.MarshalCanonical(value)
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		tb.Fatal(err)
	}
}

func writeTrusteeKey(tb testing.TB, path string, material keyMaterial) {
	tb.Helper()
	plaintext, _ := protocol.MarshalCanonical(material)
	sealed, err := keystore.Seal(keystore.RoleTrustee, material.TrusteeID, plaintext, []byte("test-passphrase"), keystore.Options{KDF: testKDF, Rand: newHashReader("seal"), Now: func() time.Time { return time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(path, sealed, 0o600); err != nil {
		tb.Fatal(err)
	}
}

func ecdhPrivateForTest() ([]byte, error) {
	key, err := ecdh.X25519().GenerateKey(newHashReader("transport"))
	if err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func walkCommands(tb testing.TB, command *cobra.Command) {
	tb.Helper()
	for _, forbidden := range []string{"passphrase", "secret", "private-key"} {
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
