// Package sequencercmd provides the SSH-credit poll workflow.
package sequencercmd

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/cirocosta/vota/internal/auditverify"
	"github.com/cirocosta/vota/internal/crypto/blind"
	"github.com/cirocosta/vota/internal/crypto/sshsig"
	"github.com/cirocosta/vota/internal/httpclient"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/sequencer"
	"github.com/spf13/cobra"
)

type Options struct {
	HTTPClient *http.Client
	Random     io.Reader
	StateDir   string
}

func Commands(options Options) []*cobra.Command {
	if options.Random == nil {
		options.Random = rand.Reader
	}
	poll := &cobra.Command{Use: "poll", Short: "create, close, and inspect team polls"}
	poll.AddCommand(createCommand(options), resultCommand(options), closeCommand(options))
	return []*cobra.Command{poll, voteCommand(options), auditCommand(options)}
}

func createCommand(options Options) *cobra.Command {
	var serverURL, identityPath, membersPath, question, closesAt, output string
	var choices []string
	command := &cobra.Command{
		Use: "create", Short: "create a poll from SSH public keys", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			members, err := readMembers(membersPath)
			if err != nil {
				return err
			}
			if err := validateDraft(question, choices, closesAt, members); err != nil {
				return err
			}
			adminKey, err := readPublicKey(identityPath)
			if err != nil {
				return err
			}
			requestID := make([]byte, 16)
			if _, err := io.ReadFull(options.Random, requestID); err != nil {
				return fmt.Errorf("generate request ID: %w", err)
			}
			request := sequencer.CreatePollRequest{RequestID: base64.RawURLEncoding.EncodeToString(requestID), Question: question, Choices: choices, ClosesAt: closesAt, Members: members, AdminPublicKey: adminKey}
			message, err := sequencer.CreatePollMessage(request)
			if err != nil {
				return err
			}
			signature, err := sshsig.Sign(command.Context(), []byte(adminKey), sequencer.AdminNamespace, message)
			if err != nil {
				return friendlyError(err)
			}
			request.SSHSIG = base64.RawURLEncoding.EncodeToString(signature)
			client, err := httpclient.New(serverURL, options.HTTPClient)
			if err != nil {
				return err
			}
			response, _, err := client.CreateSequencerPoll(command.Context(), request)
			if err != nil {
				return friendlyError(err)
			}
			if err := sequencer.VerifyPollArtifact(response.Poll); err != nil {
				return fmt.Errorf("verify poll: %w", err)
			}
			if output != "" {
				if err := writeArtifact(output, response.Poll, 0o644); err != nil {
					return err
				}
			}
			_, err = fmt.Fprintln(command.OutOrStdout(), response.PollURL)
			return err
		},
	}
	flags := command.Flags()
	flags.StringVar(&serverURL, "server", "", "Vota server base URL")
	flags.StringVar(&identityPath, "admin-identity", "", "administrator SSH public key path")
	flags.StringVar(&membersPath, "members", "", "team SSH public key file")
	flags.StringVar(&question, "question", "", "poll question")
	flags.StringSliceVar(&choices, "choice", nil, "choice label (repeat for each choice)")
	flags.StringVar(&closesAt, "closes-at", "", "UTC RFC3339 closing time")
	flags.StringVar(&output, "out", "", "optional signed poll artifact path")
	for _, name := range []string{"server", "admin-identity", "members", "question", "choice", "closes-at"} {
		_ = command.MarkFlagRequired(name)
	}
	return command
}

func resultCommand(options Options) *cobra.Command {
	return &cobra.Command{
		Use: "result POLL-URL", Short: "show a closed poll result", Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			client, pollID, err := clientForPollURL(args[0], options.HTTPClient)
			if err != nil {
				return err
			}
			result, err := client.SequencerResult(command.Context(), pollID)
			if err != nil {
				return friendlyError(err)
			}
			poll, err := client.SequencerPoll(command.Context(), pollID)
			if err != nil {
				return friendlyError(err)
			}
			if err := sequencer.VerifyPollArtifact(poll); err != nil {
				return fmt.Errorf("verify poll: %w", err)
			}
			if err := sequencer.VerifyTallyForPoll(poll, result); err != nil {
				return fmt.Errorf("verify result: %w", err)
			}
			labels := make(map[string]string, len(poll.Choices))
			for _, choice := range poll.Choices {
				labels[choice.ID] = choice.Label
			}
			if _, err := fmt.Fprintf(command.OutOrStdout(), "%s\n\n", poll.Question); err != nil {
				return err
			}
			for _, total := range result.Totals {
				if _, err := fmt.Fprintf(command.OutOrStdout(), "%s: %d\n", labels[total.ChoiceID], total.Total); err != nil {
					return err
				}
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "Total votes: %d\n", result.BallotCount)
			return err
		},
	}
}

func closeCommand(options Options) *cobra.Command {
	var identityPath string
	command := &cobra.Command{
		Use: "close POLL-URL", Short: "close a poll and publish its result", Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			client, pollID, err := clientForPollURL(args[0], options.HTTPClient)
			if err != nil {
				return err
			}
			adminKey, err := readPublicKey(identityPath)
			if err != nil {
				return err
			}
			poll, err := client.SequencerPoll(command.Context(), pollID)
			if err != nil {
				return friendlyError(err)
			}
			if err := sequencer.VerifyPollArtifact(poll); err != nil {
				return fmt.Errorf("verify poll: %w", err)
			}
			message, _ := sequencer.ClosePollMessage(pollID, adminKey)
			signature, err := sshsig.Sign(command.Context(), []byte(adminKey), sequencer.AdminNamespace, message)
			if err != nil {
				return friendlyError(err)
			}
			tally, err := client.CloseSequencerPoll(command.Context(), pollID, sequencer.ClosePollRequest{AdminPublicKey: adminKey, SSHSIG: base64.RawURLEncoding.EncodeToString(signature)})
			if err != nil {
				return friendlyError(err)
			}
			if err := sequencer.VerifyTallyForPoll(poll, tally); err != nil {
				return fmt.Errorf("verify result: %w", err)
			}
			_, err = fmt.Fprintln(command.OutOrStdout(), "Poll closed")
			return err
		},
	}
	command.Flags().StringVar(&identityPath, "admin-identity", "", "administrator SSH public key path")
	_ = command.MarkFlagRequired("admin-identity")
	return command
}

func voteCommand(options Options) *cobra.Command {
	var identityPath string
	var choiceStdin bool
	var receiptPath string
	command := &cobra.Command{
		Use: "vote POLL-URL", Short: "claim one anonymous credit and vote", Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			client, pollID, err := clientForPollURL(args[0], options.HTTPClient)
			if err != nil {
				return err
			}
			poll, err := client.SequencerPoll(command.Context(), pollID)
			if err != nil {
				return friendlyError(err)
			}
			if err := sequencer.VerifyPollArtifact(poll); err != nil {
				return fmt.Errorf("verify poll: %w", err)
			}
			choiceID, err := readChoice(command, poll, choiceStdin)
			if err != nil {
				return err
			}
			publicKey, err := readPublicKey(identityPath)
			if err != nil {
				return err
			}
			statePath, err := credentialStatePath(options.StateDir, pollID, publicKey)
			if err != nil {
				return err
			}
			state, err := loadOrCreateVoteState(statePath, poll, args[0], publicKey, options.Random)
			if err != nil {
				return err
			}
			claimMessage, _ := sequencer.ClaimMessage(pollID, state.IssuanceRequestID, state.BlindRequest.BlindedMessage)
			signature, err := sshsig.Sign(command.Context(), []byte(publicKey), sequencer.CreditClaimNamespace, claimMessage)
			if err != nil {
				return friendlyError(err)
			}
			claim := sequencer.ClaimRequest{SSHPublicKey: publicKey, IssuanceRequestID: state.IssuanceRequestID, BlindedMessage: base64.RawURLEncoding.EncodeToString(state.BlindRequest.BlindedMessage), SSHSIG: base64.RawURLEncoding.EncodeToString(signature)}
			issued, _, err := client.ClaimCredential(command.Context(), pollID, claim)
			if err != nil {
				return friendlyError(err)
			}
			blindSignature, err := base64.RawURLEncoding.DecodeString(issued.BlindSignature)
			if err != nil {
				return fmt.Errorf("server returned an invalid blind signature")
			}
			issuer, err := blind.ParsePublicKey(poll.IssuerPublicKey)
			if err != nil {
				return fmt.Errorf("poll has an invalid issuer key")
			}
			credential, err := blind.Finalize(issuer, state.BlindRequest.State, blindSignature)
			if err != nil {
				return fmt.Errorf("verify issued credential: %w", err)
			}
			ballot := sequencer.BallotRequest{Credential: sequencer.Credential{IssuerKeyID: credential.IssuerKeyID, Serial: base64.RawURLEncoding.EncodeToString(credential.Serial), Signature: base64.RawURLEncoding.EncodeToString(credential.Signature)}, ChoiceID: choiceID}
			receipt, _, err := client.VoteWithCredential(command.Context(), pollID, ballot)
			if err != nil {
				return friendlyError(err)
			}
			if err := sequencer.VerifyReceiptForBallot(poll, ballot, receipt); err != nil {
				return fmt.Errorf("verify receipt: %w", err)
			}
			if receiptPath == "" {
				receiptPath, err = defaultReceiptPath(options.StateDir, pollID, receipt.CredentialHash)
				if err != nil {
					return err
				}
			}
			if err := writeArtifact(receiptPath, receipt, 0o600); err != nil {
				return fmt.Errorf("write receipt: %w", err)
			}
			if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove credential recovery state: %w", err)
			}
			if _, err := fmt.Fprintln(command.OutOrStdout(), "Vote recorded"); err != nil {
				return err
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "Receipt: %s\n", receiptPath)
			return err
		},
	}
	command.Flags().StringVar(&identityPath, "identity", "", "SSH public key path")
	command.Flags().BoolVar(&choiceStdin, "choice-stdin", false, "read the choice from standard input without a prompt")
	command.Flags().StringVar(&receiptPath, "receipt-out", "", "receipt output path")
	_ = command.MarkFlagRequired("identity")
	return command
}

func auditCommand(options Options) *cobra.Command {
	audit := &cobra.Command{Use: "audit", Short: "export and verify closed poll logs"}
	var serverURL, pollID, output string
	export := &cobra.Command{
		Use: "export", Short: "export a closed anonymous ballot log", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			client, err := httpclient.New(serverURL, options.HTTPClient)
			if err != nil {
				return err
			}
			bundle, err := client.SequencerAudit(command.Context(), pollID)
			if err != nil {
				return friendlyError(err)
			}
			if filepath.Ext(output) == "" {
				output = filepath.Join(output, "audit.json")
			}
			return writeArtifact(output, bundle, 0o644)
		},
	}
	export.Flags().StringVar(&serverURL, "server", "", "Vota server base URL")
	export.Flags().StringVar(&pollID, "poll", "", "poll ID")
	export.Flags().StringVar(&output, "out", "", "audit file or directory")
	for _, name := range []string{"server", "poll", "out"} {
		_ = export.MarkFlagRequired(name)
	}
	var recordPath string
	verify := &cobra.Command{
		Use: "verify", Short: "verify an audit log offline", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if info, err := os.Stat(recordPath); err == nil && info.IsDir() {
				recordPath = filepath.Join(recordPath, "audit.json")
			}
			data, err := os.ReadFile(recordPath)
			if err != nil {
				return err
			}
			if _, err := auditverify.Verify(data); err != nil {
				return fmt.Errorf("verify audit: %w", err)
			}
			_, err = fmt.Fprintln(command.OutOrStdout(), "Audit verified")
			return err
		},
	}
	verify.Flags().StringVar(&recordPath, "record", "", "audit file or directory")
	_ = verify.MarkFlagRequired("record")
	audit.AddCommand(export, verify)
	return audit
}

type voteState struct {
	SchemaVersion     int           `json:"schema_version"`
	PollURL           string        `json:"poll_url"`
	IssuanceRequestID string        `json:"issuance_request_id"`
	BlindRequest      blind.Request `json:"blind_request"`
}

func loadOrCreateVoteState(path string, poll sequencer.Poll, pollURL, publicKey string, random io.Reader) (voteState, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		var state voteState
		if err := protocol.DecodeStrict(data, &state); err != nil {
			return voteState{}, fmt.Errorf("invalid local credential recovery state: %w", err)
		}
		if state.SchemaVersion != 1 || state.PollURL != pollURL || state.BlindRequest.State.PollID != poll.PollID {
			return voteState{}, fmt.Errorf("local credential recovery state does not match this poll")
		}
		return state, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return voteState{}, err
	}
	issuer, err := blind.ParsePublicKey(poll.IssuerPublicKey)
	if err != nil {
		return voteState{}, fmt.Errorf("poll has an invalid issuer key")
	}
	serial := make([]byte, blind.SerialSize)
	if _, err := io.ReadFull(random, serial); err != nil {
		return voteState{}, err
	}
	request, err := blind.Prepare(issuer, poll.PollID, poll.IssuerKeyID, serial, random)
	if err != nil {
		return voteState{}, err
	}
	requestID := make([]byte, 16)
	if _, err := io.ReadFull(random, requestID); err != nil {
		return voteState{}, err
	}
	state := voteState{SchemaVersion: 1, PollURL: pollURL, IssuanceRequestID: base64.RawURLEncoding.EncodeToString(requestID), BlindRequest: request}
	if err := writeArtifact(path, state, 0o600); err != nil {
		return voteState{}, fmt.Errorf("persist credential recovery state: %w", err)
	}
	_ = publicKey
	return state, nil
}

func readChoice(command *cobra.Command, poll sequencer.Poll, quiet bool) (string, error) {
	if !quiet {
		if _, err := fmt.Fprintln(command.ErrOrStderr(), poll.Question); err != nil {
			return "", err
		}
		for index, choice := range poll.Choices {
			if _, err := fmt.Fprintf(command.ErrOrStderr(), "%d. %s\n", index+1, choice.Label); err != nil {
				return "", err
			}
		}
		if _, err := fmt.Fprint(command.ErrOrStderr(), "Choice: "); err != nil {
			return "", err
		}
	}
	reader := bufio.NewReader(io.LimitReader(command.InOrStdin(), 1024))
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value = strings.TrimSpace(value)
	if number, err := strconv.Atoi(value); err == nil && number >= 1 && number <= len(poll.Choices) {
		return poll.Choices[number-1].ID, nil
	}
	for _, choice := range poll.Choices {
		if value == choice.ID {
			return choice.ID, nil
		}
	}
	return "", fmt.Errorf("invalid choice")
}

func readMembers(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var output []string
	seen := make(map[string]struct{})
	for lineNumber, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] != "ssh-ed25519" {
			line = strings.Join(fields[1:], " ")
		}
		key, err := sshsig.ParsePublicKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("invalid member on line %d: %w", lineNumber+1, err)
		}
		canonical, _ := sshsig.CanonicalPublicKey(key)
		fingerprint, _ := sshsig.Fingerprint(key)
		if _, duplicate := seen[fingerprint]; duplicate {
			return nil, fmt.Errorf("duplicate member on line %d", lineNumber+1)
		}
		seen[fingerprint] = struct{}{}
		output = append(output, string(canonical))
	}
	slices.Sort(output)
	return output, nil
}

func readPublicKey(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	key, err := sshsig.ParsePublicKey(data)
	if err != nil {
		return "", err
	}
	canonical, _ := sshsig.CanonicalPublicKey(key)
	return string(canonical), nil
}

func validateDraft(question string, choices []string, closesAt string, members []string) error {
	if question == "" || question != strings.TrimSpace(question) || len(question) > 500 {
		return fmt.Errorf("invalid question")
	}
	if len(choices) < 2 || len(choices) > 20 {
		return fmt.Errorf("provide between 2 and 20 choices")
	}
	seen := make(map[string]struct{}, len(choices))
	for _, choice := range choices {
		if choice == "" || strings.TrimSpace(choice) != choice || len(choice) > 100 {
			return fmt.Errorf("invalid choice")
		}
		folded := strings.ToLower(choice)
		if _, duplicate := seen[folded]; duplicate {
			return fmt.Errorf("duplicate choice")
		}
		seen[folded] = struct{}{}
	}
	if len(members) < 2 {
		return fmt.Errorf("provide at least two unique members")
	}
	if _, err := protocol.ParseCanonicalTime(closesAt); err != nil {
		return fmt.Errorf("invalid closing time")
	}
	return nil
}

func clientForPollURL(value string, httpClient *http.Client) (*httpclient.Client, string, error) {
	serverURL, pollID, err := httpclient.ParsePollURL(value)
	if err != nil {
		return nil, "", err
	}
	client, err := httpclient.New(serverURL, httpClient)
	return client, pollID, err
}

func credentialStatePath(configured, pollID, publicKey string) (string, error) {
	base, err := stateBase(configured)
	if err != nil {
		return "", err
	}
	pollHash := sha256.Sum256([]byte(pollID))
	keyHash := sha256.Sum256([]byte(publicKey))
	return filepath.Join(base, "credentials", hex.EncodeToString(pollHash[:16]), hex.EncodeToString(keyHash[:16])+".json"), nil
}

func defaultReceiptPath(configured, pollID, credentialHash string) (string, error) {
	base, err := stateBase(configured)
	if err != nil {
		return "", err
	}
	pollHash := sha256.Sum256([]byte(pollID))
	receiptHash := sha256.Sum256([]byte(credentialHash))
	return filepath.Join(base, "receipts", hex.EncodeToString(pollHash[:16]), hex.EncodeToString(receiptHash[:16])+".json"), nil
}

func stateBase(configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	if value := os.Getenv("XDG_STATE_HOME"); value != "" {
		return filepath.Join(value, "vota"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "vota"), nil
}

func writeArtifact(path string, value any, mode os.FileMode) error {
	encoded, err := protocol.MarshalCanonical(value)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".vota-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func friendlyError(err error) error {
	if sshsig.ErrorCode(err) == "ssh_agent_unavailable" {
		return fmt.Errorf("SSH agent is unavailable; start ssh-agent and load your key")
	}
	if sshsig.ErrorCode(err) == "ssh_key_not_in_agent" {
		return fmt.Errorf("the selected SSH key is not loaded in ssh-agent")
	}
	var httpError *httpclient.Error
	if errors.As(err, &httpError) {
		switch httpError.Code {
		case "credit_already_claimed":
			return fmt.Errorf("credit already claimed for this SSH key on this poll\nfinish voting from the computer that claimed it")
		case "credential_already_spent":
			return fmt.Errorf("this anonymous credential has already voted")
		case "not_eligible":
			return fmt.Errorf("this SSH key is not eligible for the poll")
		case "poll_not_open":
			return fmt.Errorf("the poll is not open")
		case "result_unavailable":
			return fmt.Errorf("the result is unavailable until the poll is closed")
		}
	}
	return err
}
