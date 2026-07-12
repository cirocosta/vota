// Package admin provides administrator Cobra command constructors.
package admin

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

	"github.com/cirocosta/vota/internal/crypto/election"
	"github.com/cirocosta/vota/internal/httpclient"
	"github.com/cirocosta/vota/internal/keystore"
	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type SecretReader func(prompt string, fd int) ([]byte, error)
type Confirmer func(prompt string) (bool, error)

type Options struct {
	Rand       io.Reader
	Now        func() time.Time
	KDF        keystore.KDFParams
	ReadSecret SecretReader
	Confirm    Confirmer
	HTTPClient func(string) (*httpclient.Client, error)
}

type PollConfig struct {
	Question         string            `json:"question"`
	Choices          []protocol.Choice `json:"choices"`
	Trustees         []TrusteeConfig   `json:"trustees"`
	TrusteeQuorum    int               `json:"trustee_quorum"`
	PrivacyThreshold int               `json:"privacy_threshold"`
	OpensAt          string            `json:"opens_at"`
	ClosesAt         string            `json:"closes_at"`
}

type TrusteeConfig struct {
	ID         string `json:"id"`
	SigningKey string `json:"signing_key"`
	Commitment string `json:"commitment"`
}

type DraftFile struct {
	SchemaVersion int                   `json:"schema_version"`
	Protocol      string                `json:"protocol"`
	Config        PollConfig            `json:"config"`
	AuthorityKey  string                `json:"authority_key"`
	Enrollments   []protocol.Enrollment `json:"enrollments"`
	Frozen        bool                  `json:"frozen"`
}

type adminKeyMaterial struct {
	PrivateKey string `json:"private_key"`
}

func Commands(options Options) []*cobra.Command {
	options = defaults(options)
	return []*cobra.Command{newAdminCommand(options), newPollCommand(options)}
}

func newAdminCommand(options Options) *cobra.Command {
	command := &cobra.Command{Use: "admin", Short: "manage administrator keys", Args: cobra.NoArgs}
	keyCommand := &cobra.Command{Use: "key", Short: "manage administrator keys", Args: cobra.NoArgs}
	keyCommand.AddCommand(newKeyCreateCommand(options))
	command.AddCommand(keyCommand)
	return command
}

func newKeyCreateCommand(options Options) *cobra.Command {
	var output string
	var passphraseFD int
	command := &cobra.Command{
		Use:   "create",
		Short: "create an encrypted administrator key",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			passphrase, err := options.ReadSecret("Administrator key passphrase: ", passphraseFD)
			if err != nil {
				return err
			}
			defer clear(passphrase)
			publicKey, privateKey, err := ed25519.GenerateKey(options.Rand)
			if err != nil {
				return fmt.Errorf("generate administrator key: %w", err)
			}
			material, err := protocol.MarshalCanonical(adminKeyMaterial{PrivateKey: "ed25519priv:" + hex.EncodeToString(privateKey)})
			if err != nil {
				return err
			}
			keyID := hex.EncodeToString(publicKey[:8])
			sealed, err := keystore.Seal(keystore.RoleAdmin, keyID, material, passphrase, keystore.Options{KDF: options.KDF, Rand: options.Rand, Now: options.Now})
			clear(privateKey)
			if err != nil {
				return err
			}
			if err := createPrivateFile(output, sealed); err != nil {
				return err
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "administrator key created: %s\n", output)
			return err
		},
	}
	command.Flags().StringVar(&output, "out", "", "encrypted key output path")
	command.Flags().IntVar(&passphraseFD, "passphrase-fd", -1, "read passphrase from an open file descriptor")
	_ = command.MarkFlagRequired("out")
	return command
}

func newPollCommand(options Options) *cobra.Command {
	command := &cobra.Command{Use: "poll", Short: "create and operate polls", Long: "Poll commands operate experimental educational polls that are not suitable for real elections.", Args: cobra.NoArgs}
	command.AddCommand(
		newPollCreateCommand(options),
		newEligibleCommand(options),
		newFreezeCommand(options),
		newPublishCommand(options),
		newGetCommand(options),
		newCloseCommand(options),
	)
	return command
}

func newPollCreateCommand(options Options) *cobra.Command {
	var configPath, adminKeyPath, output string
	var passphraseFD int
	command := &cobra.Command{
		Use:   "create",
		Short: "create a canonical poll draft",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			var config PollConfig
			if err := readStrict(configPath, &config); err != nil {
				return err
			}
			privateKey, err := unlockAdminKey(options, adminKeyPath, passphraseFD)
			if err != nil {
				return err
			}
			defer clear(privateKey)
			draft := DraftFile{
				SchemaVersion: protocol.SchemaVersion,
				Protocol:      protocol.ProtocolVersion,
				Config:        config,
				AuthorityKey:  "ed25519:" + hex.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
				Enrollments:   []protocol.Enrollment{},
			}
			if _, err := manifest.DraftID(ManifestDraft(draft)); err != nil {
				return err
			}
			encoded, err := protocol.MarshalCanonical(draft)
			if err != nil {
				return err
			}
			if err := createPublicFile(output, encoded); err != nil {
				return err
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "poll draft created: %s\n", output)
			return err
		},
	}
	command.Flags().StringVar(&configPath, "config", "", "poll configuration JSON")
	command.Flags().StringVar(&adminKeyPath, "admin-key", "", "administrator key path")
	command.Flags().StringVar(&output, "out", "", "draft output path")
	command.Flags().IntVar(&passphraseFD, "passphrase-fd", -1, "read passphrase from an open file descriptor")
	for _, flag := range []string{"config", "admin-key", "out"} {
		_ = command.MarkFlagRequired(flag)
	}
	return command
}

func newEligibleCommand(options Options) *cobra.Command {
	root := &cobra.Command{Use: "eligible", Short: "manage poll eligibility", Args: cobra.NoArgs}
	var draftPath, enrollmentPath string
	add := &cobra.Command{
		Use:   "add",
		Short: "add a verified enrollment to a draft",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			var draft DraftFile
			if err := readStrict(draftPath, &draft); err != nil {
				return err
			}
			if draft.Frozen {
				return fmt.Errorf("poll_frozen")
			}
			var enrollment protocol.Enrollment
			if err := readStrict(enrollmentPath, &enrollment); err != nil {
				return err
			}
			draftID, err := manifest.DraftID(ManifestDraft(draft))
			if err != nil {
				return err
			}
			if enrollment.PollDraftID != draftID {
				return fmt.Errorf("wrong_draft_enrollment")
			}
			if err := manifest.VerifyEnrollment(enrollment); err != nil {
				return err
			}
			for _, existing := range draft.Enrollments {
				if existing.EligibilityKey == enrollment.EligibilityKey {
					return fmt.Errorf("duplicate_eligibility_key")
				}
			}
			draft.Enrollments = append(draft.Enrollments, enrollment)
			encoded, _ := protocol.MarshalCanonical(draft)
			if err := replacePublicFile(draftPath, encoded); err != nil {
				return err
			}
			_, err = fmt.Fprintln(command.OutOrStdout(), "eligibility enrollment added")
			return err
		},
	}
	add.Flags().StringVar(&draftPath, "draft", "", "poll draft path")
	add.Flags().StringVar(&enrollmentPath, "enrollment", "", "enrollment artifact path")
	_ = add.MarkFlagRequired("draft")
	_ = add.MarkFlagRequired("enrollment")
	root.AddCommand(add)
	return root
}

func newFreezeCommand(options Options) *cobra.Command {
	var draftPath, adminKeyPath, output string
	var passphraseFD int
	var yes, outputJSON bool
	command := &cobra.Command{
		Use:   "freeze",
		Short: "freeze and sign a poll manifest",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if !yes {
				confirmed, err := options.Confirm("Freeze poll permanently? [y/N]: ")
				if err != nil {
					return err
				}
				if !confirmed {
					return fmt.Errorf("freeze_cancelled")
				}
			}
			var draft DraftFile
			if err := readStrict(draftPath, &draft); err != nil {
				return err
			}
			if draft.Frozen {
				return fmt.Errorf("poll_frozen")
			}
			privateKey, err := unlockAdminKey(options, adminKeyPath, passphraseFD)
			if err != nil {
				return err
			}
			defer clear(privateKey)
			frozen, err := manifest.Freeze(ManifestDraft(draft), privateKey)
			if err != nil {
				return err
			}
			encoded, err := frozen.MarshalCanonical()
			if err != nil {
				return err
			}
			if err := createPublicFile(output, encoded); err != nil {
				return err
			}
			draft.Frozen = true
			draftBytes, _ := protocol.MarshalCanonical(draft)
			if err := replacePublicFile(draftPath, draftBytes); err != nil {
				return err
			}
			if outputJSON {
				_, err = command.OutOrStdout().Write(encoded)
				return err
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "poll frozen: %s\n", frozen.Manifest().PollID)
			return err
		},
	}
	command.Flags().StringVar(&draftPath, "draft", "", "poll draft path")
	command.Flags().StringVar(&adminKeyPath, "admin-key", "", "administrator key path")
	command.Flags().StringVar(&output, "out", "", "manifest output path")
	command.Flags().IntVar(&passphraseFD, "passphrase-fd", -1, "read passphrase from an open file descriptor")
	command.Flags().BoolVar(&yes, "yes", false, "confirm irreversible freeze")
	command.Flags().BoolVar(&outputJSON, "json", false, "write the manifest to stdout")
	for _, flag := range []string{"draft", "admin-key", "out"} {
		_ = command.MarkFlagRequired(flag)
	}
	return command
}

func newPublishCommand(options Options) *cobra.Command {
	var manifestPath, server string
	var tokenFD int
	var outputJSON bool
	command := &cobra.Command{
		Use:   "publish",
		Short: "publish a frozen manifest",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			encoded, err := os.ReadFile(manifestPath)
			if err != nil {
				return err
			}
			var value protocol.Manifest
			if err := protocol.DecodeStrict(encoded, &value); err != nil {
				return err
			}
			token, err := options.ReadSecret("Administrator token: ", tokenFD)
			if err != nil {
				return err
			}
			defer clear(token)
			client, err := options.HTTPClient(server)
			if err != nil {
				return err
			}
			published, created, err := client.PublishPollArtifact(command.Context(), encoded, strings.TrimSpace(string(token)))
			if err != nil {
				return err
			}
			if outputJSON {
				return writeCanonical(command.OutOrStdout(), published)
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "poll published: %s (created=%t)\n", published.PollID, created)
			return err
		},
	}
	command.Flags().StringVar(&manifestPath, "manifest", "", "frozen manifest path")
	command.Flags().StringVar(&server, "server", "", "collector base URL")
	command.Flags().IntVar(&tokenFD, "admin-token-fd", -1, "read admin token from an open file descriptor")
	command.Flags().BoolVar(&outputJSON, "json", false, "write JSON output")
	_ = command.MarkFlagRequired("manifest")
	_ = command.MarkFlagRequired("server")
	return command
}

func newGetCommand(options Options) *cobra.Command {
	var pollID, server, output string
	command := &cobra.Command{
		Use:   "get",
		Short: "download a poll manifest",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			client, err := options.HTTPClient(server)
			if err != nil {
				return err
			}
			status, err := client.Poll(command.Context(), pollID)
			if err != nil {
				return err
			}
			encoded, _ := protocol.MarshalCanonical(status.Manifest)
			if err := createPublicFile(output, encoded); err != nil {
				return err
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "poll downloaded: %s\n", output)
			return err
		},
	}
	command.Flags().StringVar(&pollID, "poll", "", "poll ID")
	command.Flags().StringVar(&server, "server", "", "collector base URL")
	command.Flags().StringVar(&output, "out", "", "manifest output path")
	for _, flag := range []string{"poll", "server", "out"} {
		_ = command.MarkFlagRequired(flag)
	}
	return command
}

func newCloseCommand(options Options) *cobra.Command {
	var pollID, server string
	var tokenFD int
	var outputJSON bool
	command := &cobra.Command{
		Use:   "close",
		Short: "close a poll and publish its aggregate",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			token, err := options.ReadSecret("Administrator token: ", tokenFD)
			if err != nil {
				return err
			}
			defer clear(token)
			client, err := options.HTTPClient(server)
			if err != nil {
				return err
			}
			aggregate, err := client.ClosePoll(command.Context(), pollID, strings.TrimSpace(string(token)))
			if err != nil {
				return err
			}
			if outputJSON {
				return writeCanonical(command.OutOrStdout(), aggregate)
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "poll closed: %s\n", aggregate.AggregateHash)
			return err
		},
	}
	command.Flags().StringVar(&pollID, "poll", "", "poll ID")
	command.Flags().StringVar(&server, "server", "", "collector base URL")
	command.Flags().IntVar(&tokenFD, "admin-token-fd", -1, "read admin token from an open file descriptor")
	command.Flags().BoolVar(&outputJSON, "json", false, "write JSON output")
	_ = command.MarkFlagRequired("poll")
	_ = command.MarkFlagRequired("server")
	return command
}

// ManifestDraft converts a public draft file into the validated manifest input.
func ManifestDraft(draft DraftFile) manifest.Draft {
	trustees := make([]manifest.Trustee, len(draft.Config.Trustees))
	for index, trustee := range draft.Config.Trustees {
		signingKey, _ := decodeValue(trustee.SigningKey, "ed25519", ed25519.PublicKeySize)
		commitment, _ := decodeValue(trustee.Commitment, "vota-ceremony-commitment-v1", -1)
		contribution, _ := election.ParsePublicContribution(commitment)
		trustees[index] = manifest.Trustee{ID: trustee.ID, SigningKey: ed25519.PublicKey(signingKey), Contribution: contribution}
	}
	authorityKey, _ := decodeValue(draft.AuthorityKey, "ed25519", ed25519.PublicKeySize)
	opensAt, _ := time.Parse(time.RFC3339, draft.Config.OpensAt)
	closesAt, _ := time.Parse(time.RFC3339, draft.Config.ClosesAt)
	return manifest.Draft{
		Question:         draft.Config.Question,
		Choices:          draft.Config.Choices,
		Enrollments:      draft.Enrollments,
		Trustees:         trustees,
		TrusteeQuorum:    draft.Config.TrusteeQuorum,
		PrivacyThreshold: draft.Config.PrivacyThreshold,
		OpensAt:          opensAt,
		ClosesAt:         closesAt,
		AuthorityKey:     ed25519.PublicKey(authorityKey),
	}
}

func unlockAdminKey(options Options, path string, fd int) (ed25519.PrivateKey, error) {
	passphrase, err := options.ReadSecret("Administrator key passphrase: ", fd)
	if err != nil {
		return nil, err
	}
	defer clear(passphrase)
	plaintext, _, err := keystore.Load(path, keystore.RoleAdmin, passphrase)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	var material adminKeyMaterial
	if err := protocol.DecodeStrict(plaintext, &material); err != nil {
		return nil, err
	}
	privateKey, err := decodeValue(material.PrivateKey, "ed25519priv", ed25519.PrivateKeySize)
	if err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(privateKey), nil
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
	if options.Confirm == nil {
		options.Confirm = defaultConfirm
	}
	if options.HTTPClient == nil {
		options.HTTPClient = func(server string) (*httpclient.Client, error) { return httpclient.New(server, nil) }
	}
	return options
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

func defaultConfirm(prompt string) (bool, error) {
	_, _ = fmt.Fprint(os.Stderr, prompt)
	value, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "y" || value == "yes", nil
}

func readStrict(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return protocol.DecodeStrict(data, target)
}

func createPrivateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func createPublicFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func replacePublicFile(path string, data []byte) error {
	temporary := path + ".tmp-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := os.WriteFile(temporary, data, 0o644); err != nil {
		return err
	}
	defer os.Remove(temporary)
	return os.Rename(temporary, path)
}

func writeCanonical(writer io.Writer, value any) error {
	encoded, err := protocol.MarshalCanonical(value)
	if err != nil {
		return err
	}
	_, err = writer.Write(append(encoded, '\n'))
	return err
}

func decodeValue(value, prefix string, size int) ([]byte, error) {
	payload, ok := strings.CutPrefix(value, prefix+":")
	if !ok {
		return nil, fmt.Errorf("expected %s value", prefix)
	}
	decoded, err := hex.DecodeString(payload)
	if err != nil || (size >= 0 && len(decoded) != size) {
		return nil, fmt.Errorf("invalid %s value", prefix)
	}
	return decoded, nil
}
