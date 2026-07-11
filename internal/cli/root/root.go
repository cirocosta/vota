package root

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/cirocosta/vota/internal/cli/admin"
	"github.com/cirocosta/vota/internal/cli/auditcmd"
	"github.com/cirocosta/vota/internal/cli/server"
	"github.com/cirocosta/vota/internal/cli/trustee"
	"github.com/cirocosta/vota/internal/cli/voter"
	"github.com/spf13/cobra"
)

const artifactSchemaVersion = 1

// BuildInfo describes the metadata injected into a Vota build.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

type versionOutput struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	BuildDate     string `json:"build_date"`
	SchemaVersion int    `json:"schema_version"`
}

// New constructs the root Vota command.
func New(info BuildInfo) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "vota",
		Short:         "experimental anonymous polling",
		Long:          "Vota is experimental educational software and is not suitable for real elections.",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(newVersionCommand(info))
	cmd.AddCommand(admin.Commands(admin.Options{})...)
	cmd.AddCommand(voter.Commands(voter.Options{})...)
	cmd.AddCommand(trustee.Commands(trustee.Options{})...)
	cmd.AddCommand(auditcmd.Command(auditcmd.Options{}))
	cmd.AddCommand(server.Command(server.Options{}))
	return cmd
}

func newVersionCommand(info BuildInfo) *cobra.Command {
	var outputJSON bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "print build and artifact metadata",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return writeVersion(cmd.OutOrStdout(), info, outputJSON)
		},
	}
	cmd.Flags().BoolVar(&outputJSON, "json", false, "write machine-readable JSON")
	return cmd
}

func writeVersion(w io.Writer, info BuildInfo, outputJSON bool) error {
	out := versionOutput{
		Name:          "vota",
		Version:       info.Version,
		Commit:        info.Commit,
		BuildDate:     info.Date,
		SchemaVersion: artifactSchemaVersion,
	}
	if outputJSON {
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(out); err != nil {
			return fmt.Errorf("encode version output: %w", err)
		}
		return nil
	}

	_, err := fmt.Fprintf(
		w,
		"vota %s (commit %s, built %s, schema %d)\n",
		out.Version,
		out.Commit,
		out.BuildDate,
		out.SchemaVersion,
	)
	if err != nil {
		return fmt.Errorf("write version output: %w", err)
	}
	return nil
}
