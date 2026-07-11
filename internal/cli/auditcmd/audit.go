// Package auditcmd provides public audit export and offline verification commands.
package auditcmd

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cirocosta/vota/internal/audit"
	"github.com/cirocosta/vota/internal/auditverify"
	"github.com/cirocosta/vota/internal/httpclient"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/spf13/cobra"
)

const maxRecordBytes = audit.MaxBundleBytes

type Options struct {
	HTTPClient func(string) (*httpclient.Client, error)
}

func Command(options Options) *cobra.Command {
	if options.HTTPClient == nil {
		options.HTTPClient = func(server string) (*httpclient.Client, error) { return httpclient.New(server, nil) }
	}
	command := &cobra.Command{Use: "audit", Short: "export and verify public election records", Args: cobra.NoArgs}
	command.AddCommand(newExportCommand(options), newVerifyCommand(), newCompareCommand())
	return command
}

func newExportCommand(options Options) *cobra.Command {
	var pollID, server, output string
	command := &cobra.Command{Use: "export", Short: "download and verify a public record", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		client, err := options.HTTPClient(server)
		if err != nil {
			return err
		}
		encoded, err := client.Audit(command.Context(), pollID)
		if err != nil {
			return err
		}
		report, err := auditverify.Verify(encoded)
		if err != nil {
			return err
		}
		if report.PollID != pollID {
			return fmt.Errorf("wrong_poll_record")
		}
		if err := os.Mkdir(output, 0o755); err != nil {
			return err
		}
		if err := createFile(filepath.Join(output, "record.json"), encoded); err != nil {
			return err
		}
		_, err = fmt.Fprintf(command.OutOrStdout(), "audit record exported: %s\n", output)
		return err
	}}
	command.Flags().StringVar(&pollID, "poll", "", "poll ID")
	command.Flags().StringVar(&server, "server", "", "collector base URL")
	command.Flags().StringVar(&output, "out", "", "new audit record directory")
	for _, name := range []string{"poll", "server", "out"} {
		_ = command.MarkFlagRequired(name)
	}
	return command
}

func newVerifyCommand() *cobra.Command {
	var record string
	var outputJSON bool
	command := &cobra.Command{Use: "verify", Short: "replay a public record offline", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		encoded, err := readRecord(record)
		if err != nil {
			return err
		}
		report, err := auditverify.Verify(encoded)
		if err != nil {
			return err
		}
		if outputJSON {
			encoded, err := protocol.MarshalCanonical(report)
			if err != nil {
				return err
			}
			_, err = command.OutOrStdout().Write(append(encoded, '\n'))
			return err
		}
		_, err = fmt.Fprintf(command.OutOrStdout(), "verified poll %s: events=%d ballots=%d checkpoint=%s\n", report.PollID, report.EventCount, report.AcceptedBallotCount, report.FinalCheckpoint)
		return err
	}}
	command.Flags().StringVar(&record, "record", "", "audit record directory or JSON file")
	command.Flags().BoolVar(&outputJSON, "json", false, "write canonical verification report JSON")
	_ = command.MarkFlagRequired("record")
	return command
}

func newCompareCommand() *cobra.Command {
	var firstPath, secondPath string
	command := &cobra.Command{Use: "compare", Short: "compare signed checkpoint histories", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		firstBytes, err := readRecord(firstPath)
		if err != nil {
			return err
		}
		secondBytes, err := readRecord(secondPath)
		if err != nil {
			return err
		}
		first, err := audit.ParseBundle(firstBytes)
		if err != nil {
			return err
		}
		second, err := audit.ParseBundle(secondBytes)
		if err != nil {
			return err
		}
		if first.Manifest.PollID != second.Manifest.PollID || first.CheckpointKey != second.CheckpointKey {
			return fmt.Errorf("incomparable_audit_records")
		}
		key, err := checkpointKey(first.CheckpointKey)
		if err != nil {
			return err
		}
		bySequence := make(map[uint64]protocol.Checkpoint, len(first.Checkpoints))
		for _, checkpoint := range first.Checkpoints {
			bySequence[checkpoint.Sequence] = checkpoint
		}
		for _, checkpoint := range second.Checkpoints {
			if previous, exists := bySequence[checkpoint.Sequence]; exists {
				if err := audit.CompareCheckpoints(key, previous, checkpoint); err != nil {
					return err
				}
			}
		}
		_, err = fmt.Fprintln(command.OutOrStdout(), "checkpoint histories are compatible")
		return err
	}}
	command.Flags().StringVar(&firstPath, "first", "", "first audit record")
	command.Flags().StringVar(&secondPath, "second", "", "second audit record")
	_ = command.MarkFlagRequired("first")
	_ = command.MarkFlagRequired("second")
	return command
}

func readRecord(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		path = filepath.Join(path, "record.json")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, maxRecordBytes+1))
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxRecordBytes {
		return nil, fmt.Errorf("audit record too large")
	}
	return encoded, nil
}

func createFile(path string, encoded []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func checkpointKey(value string) (ed25519.PublicKey, error) {
	payload, ok := strings.CutPrefix(value, "ed25519:")
	decoded, err := hex.DecodeString(payload)
	if !ok || err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid_checkpoint_key")
	}
	return ed25519.PublicKey(decoded), nil
}
