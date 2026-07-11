// Package voter provides voter identity and ballot Cobra commands.
package voter

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cirocosta/vota/internal/app"
	"github.com/cirocosta/vota/internal/audit"
	"github.com/cirocosta/vota/internal/cli/admin"
	"github.com/cirocosta/vota/internal/crypto/lrs"
	"github.com/cirocosta/vota/internal/httpclient"
	"github.com/cirocosta/vota/internal/keystore"
	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type SecretReader func(prompt string, fd int) ([]byte, error)
type ChoiceReader func(protocol.Manifest) (int, error)

type Options struct {
	Rand       io.Reader
	Now        func() time.Time
	KDF        keystore.KDFParams
	ReadSecret SecretReader
	ReadChoice ChoiceReader
	HTTPClient func(string) (*httpclient.Client, error)
}

type identityMaterial struct {
	PollDraftID string `json:"poll_draft_id"`
	PrivateKey  string `json:"private_key"`
	PublicKey   string `json:"public_key"`
}

func Commands(options Options) []*cobra.Command {
	options = defaults(options)
	return []*cobra.Command{newIdentityCommand(options), newVoteCommand(options)}
}

func newIdentityCommand(options Options) *cobra.Command {
	command := &cobra.Command{Use: "identity", Short: "manage poll-local voter identities", Args: cobra.NoArgs}
	command.AddCommand(newIdentityCreateCommand(options), newEnrollCommand(options))
	return command
}

func newIdentityCreateCommand(options Options) *cobra.Command {
	var poll, output string
	var passphraseFD int
	command := &cobra.Command{
		Use: "create", Short: "create an encrypted poll-local voter identity", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			draftID, err := resolveDraftID(poll)
			if err != nil {
				return err
			}
			passphrase, err := options.ReadSecret("Voter identity passphrase: ", passphraseFD)
			if err != nil {
				return err
			}
			defer clear(passphrase)
			privateKey, publicKey, err := lrs.GenerateKey(options.Rand)
			if err != nil {
				return err
			}
			material, err := protocol.MarshalCanonical(identityMaterial{
				PollDraftID: draftID,
				PrivateKey:  "ristretto255scalar:" + hex.EncodeToString(privateKey[:]),
				PublicKey:   "ristretto255:" + hex.EncodeToString(publicKey[:]),
			})
			clear(privateKey[:])
			if err != nil {
				return err
			}
			sealed, err := keystore.Seal(keystore.RoleVoter, hex.EncodeToString(publicKey[:8]), material, passphrase, keystore.Options{KDF: options.KDF, Rand: options.Rand, Now: options.Now})
			clear(material)
			if err != nil {
				return err
			}
			if err := createFile(output, sealed, 0o600); err != nil {
				return err
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "voter identity created: %s\n", output)
			return err
		},
	}
	command.Flags().StringVar(&poll, "poll", "", "poll draft path or draft ID")
	command.Flags().StringVar(&output, "out", "", "encrypted identity output path")
	command.Flags().IntVar(&passphraseFD, "passphrase-fd", -1, "read passphrase from an open file descriptor")
	_ = command.MarkFlagRequired("poll")
	_ = command.MarkFlagRequired("out")
	return command
}

func newEnrollCommand(options Options) *cobra.Command {
	root := &cobra.Command{Use: "enroll", Short: "export eligibility enrollment proofs", Args: cobra.NoArgs}
	var identityPath, output string
	var passphraseFD int
	export := &cobra.Command{
		Use: "export", Short: "export a draft-bound proof of key possession", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			material, err := unlockIdentity(options, identityPath, passphraseFD)
			if err != nil {
				return err
			}
			privateKey, err := parsePrivateKey(material.PrivateKey)
			if err != nil {
				return err
			}
			defer clear(privateKey[:])
			enrollment, err := manifest.CreateEnrollment(material.PollDraftID, privateKey, options.Rand)
			if err != nil {
				return err
			}
			encoded, err := protocol.MarshalCanonical(enrollment)
			if err != nil {
				return err
			}
			if err := createFile(output, encoded, 0o644); err != nil {
				return err
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "enrollment exported: %s\n", output)
			return err
		},
	}
	export.Flags().StringVar(&identityPath, "identity", "", "encrypted voter identity path")
	export.Flags().StringVar(&output, "out", "", "enrollment output path")
	export.Flags().IntVar(&passphraseFD, "passphrase-fd", -1, "read passphrase from an open file descriptor")
	_ = export.MarkFlagRequired("identity")
	_ = export.MarkFlagRequired("out")
	root.AddCommand(export)
	return root
}

func newVoteCommand(options Options) *cobra.Command {
	command := &cobra.Command{Use: "vote", Short: "cast and submit anonymous ballots", Args: cobra.NoArgs}
	command.AddCommand(newCastCommand(options), newSubmitCommand(options))
	return command
}

func newCastCommand(options Options) *cobra.Command {
	var pollPath, identityPath, output string
	var passphraseFD int
	var choiceStdin bool
	command := &cobra.Command{
		Use: "cast", Short: "create an encrypted anonymous ballot", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			encodedManifest, err := os.ReadFile(pollPath)
			if err != nil {
				return err
			}
			frozen, err := manifest.Parse(encodedManifest)
			if err != nil {
				return err
			}
			value := frozen.Manifest()
			now := options.Now().UTC()
			opensAt, _ := time.Parse(time.RFC3339, value.OpensAt)
			closesAt, _ := time.Parse(time.RFC3339, value.ClosesAt)
			if now.Before(opensAt) {
				return fmt.Errorf("poll_not_open")
			}
			if !now.Before(closesAt) {
				return fmt.Errorf("poll_closed")
			}
			material, err := unlockIdentity(options, identityPath, passphraseFD)
			if err != nil {
				return err
			}
			if material.PollDraftID != value.PollDraftID {
				return fmt.Errorf("wrong_poll_identity")
			}
			privateKey, err := parsePrivateKey(material.PrivateKey)
			if err != nil {
				return err
			}
			defer clear(privateKey[:])
			publicKey, err := lrs.Public(privateKey)
			if err != nil {
				return err
			}
			public := "ristretto255:" + hex.EncodeToString(publicKey[:])
			signerIndex := -1
			for index, eligible := range value.EligibleKeys {
				if eligible == public {
					signerIndex = index
					break
				}
			}
			if signerIndex < 0 {
				return fmt.Errorf("identity_not_eligible")
			}
			var selected int
			if choiceStdin {
				selected, err = readChoiceFrom(command.InOrStdin(), value)
			} else {
				selected, err = options.ReadChoice(value)
			}
			if err != nil {
				return err
			}
			ballot, err := app.CastBallot(value, privateKey, signerIndex, selected, options.Rand)
			if err != nil {
				return err
			}
			encoded, err := app.MarshalBallot(ballot)
			if err != nil {
				return err
			}
			if err := createFile(output, encoded, 0o600); err != nil {
				return err
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "ballot created: %s (%s)\n", output, ballot.BallotHash)
			return err
		},
	}
	command.Flags().StringVar(&pollPath, "poll", "", "frozen manifest path")
	command.Flags().StringVar(&identityPath, "identity", "", "encrypted voter identity path")
	command.Flags().StringVar(&output, "out", "", "ballot output path")
	command.Flags().IntVar(&passphraseFD, "passphrase-fd", -1, "read passphrase from an open file descriptor")
	command.Flags().BoolVar(&choiceStdin, "choice-stdin", false, "read one choice ID or number from stdin")
	for _, name := range []string{"poll", "identity", "out"} {
		_ = command.MarkFlagRequired(name)
	}
	return command
}

func newSubmitCommand(options Options) *cobra.Command {
	var ballotPath, server, receiptPath string
	command := &cobra.Command{
		Use: "submit", Short: "submit a ballot and verify its receipt", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			encoded, err := os.ReadFile(ballotPath)
			if err != nil {
				return err
			}
			ballot, err := app.ParseBallot(encoded)
			if err != nil {
				return err
			}
			client, err := options.HTTPClient(server)
			if err != nil {
				return err
			}
			receipt, _, err := client.SubmitBallot(command.Context(), ballot)
			if err != nil {
				return err
			}
			status, err := client.Poll(command.Context(), ballot.PollID)
			if err != nil {
				return err
			}
			checkpointKey, err := decodeValue(status.CheckpointKey, "ed25519", ed25519.PublicKeySize)
			if err != nil {
				return err
			}
			bundleBytes, err := client.Audit(command.Context(), ballot.PollID)
			if err != nil {
				return err
			}
			bundle, err := audit.ParseBundle(bundleBytes, ed25519.PublicKey(checkpointKey))
			if err != nil {
				return err
			}
			var event protocol.AuditEvent
			var checkpoint protocol.Checkpoint
			for _, candidate := range bundle.Events {
				if candidate.Sequence == receipt.Sequence {
					event = candidate
					break
				}
			}
			for _, candidate := range bundle.Checkpoints {
				if candidate.Sequence == receipt.Sequence {
					checkpoint = candidate
					break
				}
			}
			if err := audit.VerifyReceipt(ed25519.PublicKey(checkpointKey), receipt, event, checkpoint); err != nil {
				return err
			}
			receiptBytes, err := protocol.MarshalCanonical(receipt)
			if err != nil {
				return err
			}
			if err := createFile(receiptPath, receiptBytes, 0o644); err != nil {
				return err
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "ballot accepted: %s\n", receipt.BallotHash)
			return err
		},
	}
	command.Flags().StringVar(&ballotPath, "ballot", "", "ballot artifact path")
	command.Flags().StringVar(&server, "server", "", "collector base URL")
	command.Flags().StringVar(&receiptPath, "receipt", "", "verified receipt output path")
	for _, name := range []string{"ballot", "server", "receipt"} {
		_ = command.MarkFlagRequired(name)
	}
	return command
}

func resolveDraftID(value string) (string, error) {
	if strings.HasPrefix(value, "sha256:") {
		_, err := decodeValue(value, "sha256", 32)
		return value, err
	}
	var draft admin.DraftFile
	encoded, err := os.ReadFile(value)
	if err != nil {
		return "", err
	}
	if err := protocol.DecodeStrict(encoded, &draft); err != nil {
		return "", err
	}
	return manifest.DraftID(admin.ManifestDraft(draft))
}

func unlockIdentity(options Options, path string, fd int) (identityMaterial, error) {
	passphrase, err := options.ReadSecret("Voter identity passphrase: ", fd)
	if err != nil {
		return identityMaterial{}, err
	}
	defer clear(passphrase)
	plaintext, _, err := keystore.Load(path, keystore.RoleVoter, passphrase)
	if err != nil {
		return identityMaterial{}, err
	}
	defer clear(plaintext)
	var material identityMaterial
	if err := protocol.DecodeStrict(plaintext, &material); err != nil {
		return identityMaterial{}, err
	}
	privateKey, err := parsePrivateKey(material.PrivateKey)
	if err != nil {
		return identityMaterial{}, err
	}
	publicKey, err := lrs.Public(privateKey)
	clear(privateKey[:])
	if err != nil || material.PublicKey != "ristretto255:"+hex.EncodeToString(publicKey[:]) {
		return identityMaterial{}, fmt.Errorf("voter_identity_key_mismatch")
	}
	if _, err := decodeValue(material.PollDraftID, "sha256", 32); err != nil {
		return identityMaterial{}, err
	}
	return material, nil
}

func parsePrivateKey(value string) (lrs.PrivateKey, error) {
	decoded, err := decodeValue(value, "ristretto255scalar", lrs.ScalarSize)
	if err != nil {
		return lrs.PrivateKey{}, err
	}
	var key lrs.PrivateKey
	copy(key[:], decoded)
	return key, nil
}

func readChoiceFrom(reader io.Reader, value protocol.Manifest) (int, error) {
	data, err := io.ReadAll(io.LimitReader(reader, 4097))
	if err != nil {
		return 0, err
	}
	input := strings.TrimSpace(string(data))
	if input == "" || strings.ContainsAny(input, " \t\r\n") {
		return 0, fmt.Errorf("invalid_choice")
	}
	if number, err := strconv.Atoi(input); err == nil && number >= 1 && number <= len(value.Choices) {
		return number - 1, nil
	}
	for index, choice := range value.Choices {
		if choice.ID == input {
			return index, nil
		}
	}
	return 0, fmt.Errorf("invalid_choice")
}

func defaultReadChoice(value protocol.Manifest) (int, error) {
	for index, choice := range value.Choices {
		_, _ = fmt.Fprintf(os.Stderr, "%d. %s\n", index+1, choice.Label)
	}
	_, _ = fmt.Fprint(os.Stderr, "Choice: ")
	data, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		return 0, err
	}
	return readChoiceFrom(strings.NewReader(string(data)), value)
}

func defaultReadSecret(prompt string, fd int) ([]byte, error) {
	if fd >= 0 {
		file := os.NewFile(uintptr(fd), "secret")
		if file == nil {
			return nil, fmt.Errorf("invalid file descriptor")
		}
		value, err := bufio.NewReader(io.LimitReader(file, 4097)).ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}
		return []byte(strings.TrimRight(value, "\r\n")), nil
	}
	_, _ = fmt.Fprint(os.Stderr, prompt)
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(os.Stderr)
	return value, err
}

func defaults(options Options) Options {
	if options.Rand == nil {
		options.Rand = rand.Reader
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.KDF == (keystore.KDFParams{}) {
		options.KDF = keystore.DefaultKDFParams
	}
	if options.ReadSecret == nil {
		options.ReadSecret = defaultReadSecret
	}
	if options.ReadChoice == nil {
		options.ReadChoice = defaultReadChoice
	}
	if options.HTTPClient == nil {
		options.HTTPClient = func(server string) (*httpclient.Client, error) { return httpclient.New(server, nil) }
	}
	return options
}

func createFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func decodeValue(value, prefix string, size int) ([]byte, error) {
	payload, ok := strings.CutPrefix(value, prefix+":")
	if !ok {
		return nil, fmt.Errorf("expected %s value", prefix)
	}
	decoded, err := hex.DecodeString(payload)
	if err != nil || len(decoded) != size {
		return nil, fmt.Errorf("invalid %s value", prefix)
	}
	return decoded, nil
}
