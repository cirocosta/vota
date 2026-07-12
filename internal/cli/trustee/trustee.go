// Package trustee provides trustee ceremony and tally Cobra commands.
package trustee

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cirocosta/vota/internal/app"
	"github.com/cirocosta/vota/internal/crypto/election"
	"github.com/cirocosta/vota/internal/httpclient"
	"github.com/cirocosta/vota/internal/keystore"
	"github.com/cirocosta/vota/internal/manifest"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

type SecretReader func(prompt string, fd int) ([]byte, error)

type Options struct {
	Rand       io.Reader
	Now        func() time.Time
	KDF        keystore.KDFParams
	ReadSecret SecretReader
	HTTPClient func(string) (*httpclient.Client, error)
}

type Participant struct {
	ID           string `json:"id"`
	SigningKey   string `json:"signing_key"`
	TransportKey string `json:"transport_key"`
}

type CeremonyConfig struct {
	SchemaVersion int           `json:"schema_version"`
	Protocol      string        `json:"protocol"`
	Quorum        int           `json:"quorum"`
	Trustees      []Participant `json:"trustees"`
}

type Contribution struct {
	SchemaVersion      int              `json:"schema_version"`
	Protocol           string           `json:"protocol"`
	TrusteeID          string           `json:"trustee_id"`
	PublicContribution string           `json:"public_contribution"`
	EncryptedShares    []EncryptedShare `json:"encrypted_shares"`
	Signature          string           `json:"signature"`
}

type EncryptedShare struct {
	RecipientID string `json:"recipient_id"`
	Ephemeral   string `json:"ephemeral_key"`
	Nonce       string `json:"nonce"`
	Ciphertext  string `json:"ciphertext"`
}

type PublicCeremony struct {
	SchemaVersion int             `json:"schema_version"`
	Protocol      string          `json:"protocol"`
	Quorum        int             `json:"quorum"`
	Trustees      []PublicTrustee `json:"trustees"`
	ElectionKey   string          `json:"election_public_key"`
}

type PublicTrustee struct {
	ID         string `json:"id"`
	SigningKey string `json:"signing_key"`
	Commitment string `json:"commitment"`
}

type keyMaterial struct {
	TrusteeID        string `json:"trustee_id"`
	SigningPrivate   string `json:"signing_private_key"`
	TransportPrivate string `json:"transport_private_key"`
	TrusteeIndex     int    `json:"trustee_index,omitempty"`
	SecretShare      string `json:"secret_share,omitempty"`
}

func Commands(options Options) []*cobra.Command {
	options = defaults(options)
	return []*cobra.Command{newTrusteeCommand(options), newTallyCommand(options)}
}

func newTrusteeCommand(options Options) *cobra.Command {
	command := &cobra.Command{Use: "trustee", Short: "manage trustee keys and aggregate shares", Args: cobra.NoArgs}
	key := &cobra.Command{Use: "key", Short: "manage trustee keys", Args: cobra.NoArgs}
	key.AddCommand(newKeyCreateCommand(options))
	ceremony := &cobra.Command{Use: "ceremony", Short: "run the threshold key ceremony", Args: cobra.NoArgs}
	ceremony.AddCommand(newCeremonyInitCommand(), newContributeCommand(options), newFinalizeCommand(options))
	command.AddCommand(key, ceremony, newTallyShareCommand(options))
	return command
}

func newKeyCreateCommand(options Options) *cobra.Command {
	var trusteeID, output, publicOutput string
	var passphraseFD int
	command := &cobra.Command{Use: "create", Short: "create an encrypted trustee key", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		if strings.TrimSpace(trusteeID) != trusteeID || trusteeID == "" {
			return fmt.Errorf("invalid_trustee_id")
		}
		passphrase, err := options.ReadSecret("Trustee key passphrase: ", passphraseFD)
		if err != nil {
			return err
		}
		defer clear(passphrase)
		signingPublic, signingPrivate, err := ed25519.GenerateKey(options.Rand)
		if err != nil {
			return err
		}
		transportPrivate, err := ecdh.X25519().GenerateKey(options.Rand)
		if err != nil {
			return err
		}
		material, err := protocol.MarshalCanonical(keyMaterial{
			TrusteeID:        trusteeID,
			SigningPrivate:   "ed25519priv:" + hex.EncodeToString(signingPrivate),
			TransportPrivate: "x25519priv:" + hex.EncodeToString(transportPrivate.Bytes()),
		})
		clear(signingPrivate)
		if err != nil {
			return err
		}
		sealed, err := keystore.Seal(keystore.RoleTrustee, trusteeID, material, passphrase, keystore.Options{KDF: options.KDF, Rand: options.Rand, Now: options.Now})
		clear(material)
		if err != nil {
			return err
		}
		if err := createFile(output, sealed, 0o600); err != nil {
			return err
		}
		participant := Participant{ID: trusteeID, SigningKey: "ed25519:" + hex.EncodeToString(signingPublic), TransportKey: "x25519:" + hex.EncodeToString(transportPrivate.PublicKey().Bytes())}
		encoded, err := protocol.MarshalCanonical(participant)
		if err != nil {
			return err
		}
		if err := createFile(publicOutput, encoded, 0o644); err != nil {
			return err
		}
		_, err = fmt.Fprintf(command.OutOrStdout(), "trustee key created: %s\n", output)
		return err
	}}
	command.Flags().StringVar(&trusteeID, "id", "", "stable trustee ID")
	command.Flags().StringVar(&output, "out", "", "encrypted trustee key path")
	command.Flags().StringVar(&publicOutput, "public-out", "", "public participant descriptor path")
	command.Flags().IntVar(&passphraseFD, "passphrase-fd", -1, "read passphrase from an open file descriptor")
	for _, name := range []string{"id", "out", "public-out"} {
		_ = command.MarkFlagRequired(name)
	}
	return command
}

func newCeremonyInitCommand() *cobra.Command {
	var configPath, output string
	command := &cobra.Command{Use: "init", Short: "validate and freeze a ceremony request", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		var config CeremonyConfig
		if err := readStrict(configPath, &config); err != nil {
			return err
		}
		if err := validateConfig(config); err != nil {
			return err
		}
		encoded, err := protocol.MarshalCanonical(config)
		if err != nil {
			return err
		}
		if err := createFile(output, encoded, 0o644); err != nil {
			return err
		}
		_, err = fmt.Fprintf(command.OutOrStdout(), "ceremony initialized: %s\n", output)
		return err
	}}
	command.Flags().StringVar(&configPath, "config", "", "ceremony configuration path")
	command.Flags().StringVar(&output, "out", "", "ceremony request path")
	_ = command.MarkFlagRequired("config")
	_ = command.MarkFlagRequired("out")
	return command
}

func newContributeCommand(options Options) *cobra.Command {
	var input, keyPath, output string
	var passphraseFD int
	command := &cobra.Command{Use: "contribute", Short: "create a signed encrypted ceremony contribution", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		var config CeremonyConfig
		if err := readStrict(input, &config); err != nil {
			return err
		}
		if err := validateConfig(config); err != nil {
			return err
		}
		material, passphrase, err := unlockKey(options, keyPath, passphraseFD)
		if err != nil {
			return err
		}
		defer clear(passphrase)
		participant, dealerIndex, err := participantFor(config, material)
		if err != nil {
			return err
		}
		dealer, err := election.GenerateDealerContribution(dealerIndex, len(config.Trustees), config.Quorum, options.Rand)
		if err != nil {
			return err
		}
		publicBytes, _ := dealer.MarshalPublicCommitment()
		contribution := Contribution{SchemaVersion: protocol.SchemaVersion, Protocol: protocol.ProtocolVersion, TrusteeID: material.TrusteeID, PublicContribution: "vota-ceremony-commitment-v1:" + hex.EncodeToString(publicBytes), EncryptedShares: make([]EncryptedShare, len(config.Trustees))}
		for recipientIndex, recipient := range config.Trustees {
			share, err := dealer.ShareFor(recipientIndex + 1)
			if err != nil {
				return err
			}
			shareBytes, _ := share.MarshalBinary()
			contribution.EncryptedShares[recipientIndex], err = encryptShare(options.Rand, material.TrusteeID, recipient, shareBytes)
			if err != nil {
				return err
			}
		}
		signingPrivate, err := decodeValue(material.SigningPrivate, "ed25519priv", ed25519.PrivateKeySize)
		if err != nil {
			return err
		}
		if participant.SigningKey != "ed25519:"+hex.EncodeToString(ed25519.PrivateKey(signingPrivate).Public().(ed25519.PublicKey)) {
			return fmt.Errorf("trustee_key_mismatch")
		}
		message, err := contributionMessage(contribution)
		if err != nil {
			return err
		}
		contribution.Signature = "ed25519sig:" + hex.EncodeToString(ed25519.Sign(ed25519.PrivateKey(signingPrivate), message))
		clear(signingPrivate)
		encoded, err := protocol.MarshalCanonical(contribution)
		if err != nil {
			return err
		}
		if err := createFile(output, encoded, 0o600); err != nil {
			return err
		}
		_, err = fmt.Fprintf(command.OutOrStdout(), "ceremony contribution created: %s\n", output)
		return err
	}}
	command.Flags().StringVar(&input, "input", "", "ceremony request path")
	command.Flags().StringVar(&keyPath, "key", "", "encrypted trustee key path")
	command.Flags().StringVar(&output, "out", "", "private contribution artifact path")
	command.Flags().IntVar(&passphraseFD, "passphrase-fd", -1, "read passphrase from an open file descriptor")
	for _, name := range []string{"input", "key", "out"} {
		_ = command.MarkFlagRequired(name)
	}
	return command
}

func newFinalizeCommand(options Options) *cobra.Command {
	var inputDir, requestPath, keyPath, output, publicOutput string
	var passphraseFD int
	command := &cobra.Command{Use: "finalize", Short: "verify contributions and finalize one trustee share", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		var config CeremonyConfig
		if err := readStrict(requestPath, &config); err != nil {
			return err
		}
		if err := validateConfig(config); err != nil {
			return err
		}
		material, passphrase, err := unlockKey(options, keyPath, passphraseFD)
		if err != nil {
			return err
		}
		defer clear(passphrase)
		_, recipientIndex, err := participantFor(config, material)
		if err != nil {
			return err
		}
		contributions, public, shares, err := loadContributions(inputDir, config, material, recipientIndex)
		if err != nil {
			return err
		}
		secret, err := election.FinalizeTrusteeShare(contributions, shares, recipientIndex)
		if err != nil {
			return err
		}
		material.TrusteeIndex = int(secret.TrusteeIndex)
		material.SecretShare = "ristretto255scalar:" + hex.EncodeToString(secret.Value[:])
		plaintext, err := protocol.MarshalCanonical(material)
		if err != nil {
			return err
		}
		sealed, err := keystore.Seal(keystore.RoleTrustee, material.TrusteeID, plaintext, passphrase, keystore.Options{KDF: options.KDF, Rand: options.Rand, Now: options.Now})
		clear(plaintext)
		if err != nil {
			return err
		}
		if err := createFile(output, sealed, 0o600); err != nil {
			return err
		}
		encodedPublic, err := protocol.MarshalCanonical(public)
		if err != nil {
			return err
		}
		if err := createFile(publicOutput, encodedPublic, 0o644); err != nil {
			return err
		}
		_, err = fmt.Fprintf(command.OutOrStdout(), "trustee ceremony finalized: %s\n", output)
		return err
	}}
	command.Flags().StringVar(&inputDir, "input-dir", "", "directory containing contribution artifacts")
	command.Flags().StringVar(&requestPath, "request", "", "ceremony request path")
	command.Flags().StringVar(&keyPath, "key", "", "encrypted trustee key path")
	command.Flags().StringVar(&output, "out", "", "finalized encrypted trustee key path")
	command.Flags().StringVar(&publicOutput, "public-out", "", "verified public ceremony path")
	command.Flags().IntVar(&passphraseFD, "passphrase-fd", -1, "read passphrase from an open file descriptor")
	for _, name := range []string{"input-dir", "request", "key", "out", "public-out"} {
		_ = command.MarkFlagRequired(name)
	}
	return command
}

func newTallyShareCommand(options Options) *cobra.Command {
	var manifestPath, aggregatePath, keyPath, output string
	var passphraseFD int
	command := &cobra.Command{Use: "tally-share", Short: "create a signed aggregate-only decryption share", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		frozen, err := readManifest(manifestPath)
		if err != nil {
			return err
		}
		value := frozen.Manifest()
		aggregateBytes, err := os.ReadFile(aggregatePath)
		if err != nil {
			return err
		}
		aggregate, err := app.ParseAggregate(aggregateBytes)
		if err != nil {
			return err
		}
		if _, err := app.ParseAggregateMustMatch(value, aggregate); err != nil {
			return err
		}
		material, passphrase, err := unlockKey(options, keyPath, passphraseFD)
		if err != nil {
			return err
		}
		defer clear(passphrase)
		if material.SecretShare == "" || material.TrusteeIndex == 0 {
			return fmt.Errorf("trustee_ceremony_not_finalized")
		}
		secretBytes, err := decodeValue(material.SecretShare, "ristretto255scalar", election.ScalarSize)
		if err != nil {
			return err
		}
		var secret election.TrusteeSecretShare
		secret.TrusteeIndex = uint16(material.TrusteeIndex)
		copy(secret.Value[:], secretBytes)
		clear(secretBytes)
		signingBytes, err := decodeValue(material.SigningPrivate, "ed25519priv", ed25519.PrivateKeySize)
		if err != nil {
			return err
		}
		share, err := app.CreateTrusteeShare(value, aggregate, material.TrusteeID, secret, ed25519.PrivateKey(signingBytes), options.Rand)
		clear(signingBytes)
		if err != nil {
			return err
		}
		if err := app.VerifyTrusteeShare(value, aggregate, share); err != nil {
			return err
		}
		encoded, err := protocol.MarshalCanonical(share)
		if err != nil {
			return err
		}
		if err := createFile(output, encoded, 0o644); err != nil {
			return err
		}
		_, err = fmt.Fprintf(command.OutOrStdout(), "tally share created: %s\n", output)
		return err
	}}
	command.Flags().StringVar(&manifestPath, "poll", "", "frozen manifest path")
	command.Flags().StringVar(&aggregatePath, "aggregate", "", "closed poll aggregate path")
	command.Flags().StringVar(&keyPath, "key", "", "finalized encrypted trustee key path")
	command.Flags().StringVar(&output, "out", "", "trustee share output path")
	command.Flags().IntVar(&passphraseFD, "passphrase-fd", -1, "read passphrase from an open file descriptor")
	for _, name := range []string{"poll", "aggregate", "key", "out"} {
		_ = command.MarkFlagRequired(name)
	}
	return command
}

func newTallyCommand(options Options) *cobra.Command {
	command := &cobra.Command{Use: "tally", Short: "submit shares and retrieve aggregate tallies", Args: cobra.NoArgs}
	command.AddCommand(newSubmitShareCommand(options), newGetTallyCommand(options))
	return command
}

func newSubmitShareCommand(options Options) *cobra.Command {
	var sharePath, server string
	command := &cobra.Command{Use: "submit-share", Short: "submit a verified trustee share", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		encoded, err := os.ReadFile(sharePath)
		if err != nil {
			return err
		}
		var share protocol.TrusteeShare
		if err := protocol.DecodeStrict(encoded, &share); err != nil {
			return err
		}
		client, err := options.HTTPClient(server)
		if err != nil {
			return err
		}
		tally, created, err := client.SubmitTrusteeShareArtifact(command.Context(), share.PollID, encoded)
		if err != nil {
			return err
		}
		if tally == nil {
			_, err = fmt.Fprintf(command.OutOrStdout(), "tally share accepted: created=%t\n", created)
			return err
		}
		_, err = fmt.Fprintf(command.OutOrStdout(), "tally published: %s\n", tally.EvidenceHash)
		return err
	}}
	command.Flags().StringVar(&sharePath, "share", "", "trustee share path")
	command.Flags().StringVar(&server, "server", "", "collector base URL")
	_ = command.MarkFlagRequired("share")
	_ = command.MarkFlagRequired("server")
	return command
}

func newGetTallyCommand(options Options) *cobra.Command {
	var pollID, server, output string
	command := &cobra.Command{Use: "get", Short: "download and verify a published tally", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		client, err := options.HTTPClient(server)
		if err != nil {
			return err
		}
		status, err := client.Poll(command.Context(), pollID)
		if err != nil {
			return err
		}
		tally, err := client.Tally(command.Context(), pollID)
		if err != nil {
			return err
		}
		key, err := decodeValue(status.CheckpointKey, "ed25519", ed25519.PublicKeySize)
		if err != nil {
			return err
		}
		if err := app.VerifyTally(status.Manifest, tally, ed25519.PublicKey(key)); err != nil {
			return err
		}
		encoded, err := protocol.MarshalCanonical(tally)
		if err != nil {
			return err
		}
		if err := createFile(output, encoded, 0o644); err != nil {
			return err
		}
		_, err = fmt.Fprintf(command.OutOrStdout(), "tally downloaded: %s\n", output)
		return err
	}}
	command.Flags().StringVar(&pollID, "poll", "", "poll ID")
	command.Flags().StringVar(&server, "server", "", "collector base URL")
	command.Flags().StringVar(&output, "out", "", "verified tally output path")
	for _, name := range []string{"poll", "server", "out"} {
		_ = command.MarkFlagRequired(name)
	}
	return command
}

func validateConfig(config CeremonyConfig) error {
	if config.SchemaVersion != protocol.SchemaVersion || config.Protocol != protocol.ProtocolVersion {
		return fmt.Errorf("invalid_ceremony_config")
	}
	if len(config.Trustees) < election.MinTrustees || len(config.Trustees) > election.MaxTrustees || config.Quorum < election.MinTrustees || config.Quorum > len(config.Trustees) {
		return fmt.Errorf("invalid_ceremony_config")
	}
	if !slices.IsSortedFunc(config.Trustees, func(a, b Participant) int { return strings.Compare(a.ID, b.ID) }) {
		return fmt.Errorf("noncanonical_trustee_order")
	}
	seen := map[string]bool{}
	for _, participant := range config.Trustees {
		if participant.ID == "" || seen[participant.ID] {
			return fmt.Errorf("duplicate_trustee_id")
		}
		seen[participant.ID] = true
		if _, err := decodeValue(participant.SigningKey, "ed25519", ed25519.PublicKeySize); err != nil {
			return err
		}
		transport, err := decodeValue(participant.TransportKey, "x25519", 32)
		if err != nil {
			return err
		}
		if _, err := ecdh.X25519().NewPublicKey(transport); err != nil {
			return fmt.Errorf("invalid_transport_key")
		}
	}
	return nil
}

func participantFor(config CeremonyConfig, material keyMaterial) (Participant, int, error) {
	signing, err := decodeValue(material.SigningPrivate, "ed25519priv", ed25519.PrivateKeySize)
	if err != nil {
		return Participant{}, 0, err
	}
	transport, err := decodeValue(material.TransportPrivate, "x25519priv", 32)
	if err != nil {
		return Participant{}, 0, err
	}
	transportPrivate, err := ecdh.X25519().NewPrivateKey(transport)
	clear(transport)
	if err != nil {
		return Participant{}, 0, err
	}
	wantSigning := "ed25519:" + hex.EncodeToString(ed25519.PrivateKey(signing).Public().(ed25519.PublicKey))
	clear(signing)
	wantTransport := "x25519:" + hex.EncodeToString(transportPrivate.PublicKey().Bytes())
	for index, participant := range config.Trustees {
		if participant.ID == material.TrusteeID {
			if participant.SigningKey != wantSigning || participant.TransportKey != wantTransport {
				return Participant{}, 0, fmt.Errorf("trustee_key_mismatch")
			}
			return participant, index + 1, nil
		}
	}
	return Participant{}, 0, fmt.Errorf("unknown_trustee")
}

func encryptShare(random io.Reader, dealerID string, recipient Participant, plaintext []byte) (EncryptedShare, error) {
	recipientBytes, err := decodeValue(recipient.TransportKey, "x25519", 32)
	if err != nil {
		return EncryptedShare{}, err
	}
	recipientKey, err := ecdh.X25519().NewPublicKey(recipientBytes)
	if err != nil {
		return EncryptedShare{}, err
	}
	ephemeral, err := ecdh.X25519().GenerateKey(random)
	if err != nil {
		return EncryptedShare{}, err
	}
	shared, err := ephemeral.ECDH(recipientKey)
	if err != nil {
		return EncryptedShare{}, err
	}
	key, err := hkdf.Key(sha256.New, shared, nil, shareContext(dealerID, recipient.ID), chacha20poly1305.KeySize)
	clear(shared)
	if err != nil {
		return EncryptedShare{}, err
	}
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return EncryptedShare{}, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return EncryptedShare{}, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, []byte(shareContext(dealerID, recipient.ID)))
	return EncryptedShare{RecipientID: recipient.ID, Ephemeral: "x25519:" + hex.EncodeToString(ephemeral.PublicKey().Bytes()), Nonce: hex.EncodeToString(nonce), Ciphertext: hex.EncodeToString(ciphertext)}, nil
}

func decryptShare(material keyMaterial, dealerID string, encrypted EncryptedShare) ([]byte, error) {
	privateBytes, err := decodeValue(material.TransportPrivate, "x25519priv", 32)
	if err != nil {
		return nil, err
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	clear(privateBytes)
	if err != nil {
		return nil, err
	}
	ephemeralBytes, err := decodeValue(encrypted.Ephemeral, "x25519", 32)
	if err != nil {
		return nil, err
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(ephemeralBytes)
	if err != nil {
		return nil, err
	}
	shared, err := privateKey.ECDH(ephemeral)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, shared, nil, shareContext(dealerID, material.TrusteeID), chacha20poly1305.KeySize)
	clear(shared)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	nonce, err := protocol.DecodeRawHex(encrypted.Nonce, chacha20poly1305.NonceSizeX)
	if err != nil {
		return nil, fmt.Errorf("invalid_ceremony_ciphertext")
	}
	ciphertext, err := protocol.DecodeRawHex(encrypted.Ciphertext, -1)
	if err != nil {
		return nil, fmt.Errorf("invalid_ceremony_ciphertext")
	}
	aead, _ := chacha20poly1305.NewX(key)
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(shareContext(dealerID, material.TrusteeID)))
	if err != nil {
		return nil, fmt.Errorf("invalid_ceremony_ciphertext")
	}
	return plaintext, nil
}

func loadContributions(directory string, config CeremonyConfig, material keyMaterial, recipientIndex int) ([]election.PublicContribution, PublicCeremony, []election.DealerShare, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, PublicCeremony{}, nil, err
	}
	byID := map[string]Contribution{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		var contribution Contribution
		if err := readStrict(filepath.Join(directory, entry.Name()), &contribution); err != nil {
			return nil, PublicCeremony{}, nil, err
		}
		if _, exists := byID[contribution.TrusteeID]; exists {
			return nil, PublicCeremony{}, nil, fmt.Errorf("duplicate_ceremony_contribution")
		}
		byID[contribution.TrusteeID] = contribution
	}
	publicContributions := make([]election.PublicContribution, len(config.Trustees))
	shares := make([]election.DealerShare, len(config.Trustees))
	public := PublicCeremony{SchemaVersion: protocol.SchemaVersion, Protocol: protocol.ProtocolVersion, Quorum: config.Quorum, Trustees: make([]PublicTrustee, len(config.Trustees))}
	for index, participant := range config.Trustees {
		contribution, exists := byID[participant.ID]
		if !exists {
			return nil, PublicCeremony{}, nil, fmt.Errorf("missing_ceremony_contribution")
		}
		if err := verifyContribution(participant, contribution, len(config.Trustees)); err != nil {
			return nil, PublicCeremony{}, nil, err
		}
		commitment, _ := decodeValue(contribution.PublicContribution, "vota-ceremony-commitment-v1", -1)
		publicContributions[index], err = election.ParsePublicContribution(commitment)
		if err != nil || int(publicContributions[index].DealerIndex) != index+1 {
			return nil, PublicCeremony{}, nil, fmt.Errorf("wrong_ceremony_dealer")
		}
		encrypted := contribution.EncryptedShares[recipientIndex-1]
		plaintext, err := decryptShare(material, contribution.TrusteeID, encrypted)
		if err != nil {
			return nil, PublicCeremony{}, nil, err
		}
		shares[index], err = election.ParseDealerShare(plaintext)
		clear(plaintext)
		if err != nil {
			return nil, PublicCeremony{}, nil, err
		}
		public.Trustees[index] = PublicTrustee{ID: participant.ID, SigningKey: participant.SigningKey, Commitment: contribution.PublicContribution}
	}
	ceremony, err := election.FinalizePublicCeremony(publicContributions)
	if err != nil {
		return nil, PublicCeremony{}, nil, err
	}
	public.ElectionKey = "ristretto255:" + hex.EncodeToString(ceremony.ElectionKey[:])
	return publicContributions, public, shares, nil
}

func verifyContribution(participant Participant, contribution Contribution, trusteeCount int) error {
	if contribution.SchemaVersion != protocol.SchemaVersion || contribution.Protocol != protocol.ProtocolVersion || contribution.TrusteeID != participant.ID || len(contribution.EncryptedShares) != trusteeCount {
		return fmt.Errorf("invalid_ceremony_contribution")
	}
	for index, encrypted := range contribution.EncryptedShares {
		if encrypted.RecipientID == "" || (index > 0 && contribution.EncryptedShares[index-1].RecipientID >= encrypted.RecipientID) {
			return fmt.Errorf("invalid_ceremony_recipients")
		}
	}
	signature, err := decodeValue(contribution.Signature, "ed25519sig", ed25519.SignatureSize)
	if err != nil {
		return err
	}
	publicKey, _ := decodeValue(participant.SigningKey, "ed25519", ed25519.PublicKeySize)
	message, err := contributionMessage(contribution)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return fmt.Errorf("invalid_ceremony_signature")
	}
	return nil
}

func contributionMessage(contribution Contribution) ([]byte, error) {
	unsigned := contribution
	unsigned.Signature = ""
	encoded, err := protocol.MarshalCanonical(unsigned)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(protocol.DomainCeremonyContribution), 0), encoded...), nil
}

func shareContext(dealerID, recipientID string) string {
	return protocol.DomainCeremonyShare + ":" + dealerID + ":" + recipientID
}

func readManifest(path string) (manifest.Frozen, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return manifest.Frozen{}, err
	}
	return manifest.Parse(encoded)
}

func unlockKey(options Options, path string, fd int) (keyMaterial, []byte, error) {
	passphrase, err := options.ReadSecret("Trustee key passphrase: ", fd)
	if err != nil {
		return keyMaterial{}, nil, err
	}
	plaintext, _, err := keystore.Load(path, keystore.RoleTrustee, passphrase)
	if err != nil {
		clear(passphrase)
		return keyMaterial{}, nil, err
	}
	defer clear(plaintext)
	var material keyMaterial
	if err := protocol.DecodeStrict(plaintext, &material); err != nil {
		clear(passphrase)
		return keyMaterial{}, nil, err
	}
	return material, passphrase, nil
}

func readStrict(path string, target any) error {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return protocol.DecodeStrict(encoded, target)
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
	if _, ok := strings.CutPrefix(value, prefix+":"); !ok {
		return nil, fmt.Errorf("expected %s value", prefix)
	}
	var (
		decoded []byte
		err     error
	)
	if size >= 0 {
		decoded, err = protocol.DecodeFixedHex(prefix, value, size)
	} else {
		decoded, err = protocol.DecodeOpaqueHex(prefix, value)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid %s value", prefix)
	}
	return decoded, nil
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
	if options.HTTPClient == nil {
		options.HTTPClient = func(server string) (*httpclient.Client, error) { return httpclient.New(server, nil) }
	}
	return options
}
