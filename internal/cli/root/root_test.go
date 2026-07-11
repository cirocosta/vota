package root

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestVersionJSON(t *testing.T) {
	t.Parallel()

	cmd := New(BuildInfo{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-07-11T00:00:00Z",
	})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"version", "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute version: %v", err)
	}

	var got versionOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode version JSON: %v", err)
	}
	if got.Name != "vota" {
		t.Errorf("name = %q, want vota", got.Name)
	}
	if got.SchemaVersion != 1 {
		t.Errorf("schema version = %d, want 1", got.SchemaVersion)
	}
	if got.Version != "v0.1.0" || got.Commit != "abc123" {
		t.Errorf("build metadata = %#v", got)
	}
}

func TestRootWiresRoleAndServerCommands(t *testing.T) {
	t.Parallel()

	cmd := New(BuildInfo{})
	names := make([]string, 0, len(cmd.Commands()))
	for _, child := range cmd.Commands() {
		names = append(names, child.Name())
	}
	slices.Sort(names)
	want := []string{"admin", "audit", "identity", "poll", "serve", "tally", "trustee", "version", "vote"}
	if !slices.Equal(names, want) {
		t.Fatalf("commands = %v, want %v", names, want)
	}
}

func TestSubcommandHelpAndExecutionWarn(t *testing.T) {
	t.Parallel()

	help := New(BuildInfo{})
	var helpOutput bytes.Buffer
	help.SetOut(&helpOutput)
	help.SetArgs([]string{"admin", "--help"})
	if err := help.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(helpOutput.String(), experimentalWarning) {
		t.Fatalf("subcommand help omits warning:\n%s", helpOutput.String())
	}

	command := New(BuildInfo{})
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs([]string{"version", "--json"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), experimentalWarning) {
		t.Fatalf("JSON stdout contains warning: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), experimentalWarning) {
		t.Fatalf("execution stderr omits warning: %s", stderr.String())
	}
}

func TestRootHelpWarnsAboutExperimentalUse(t *testing.T) {
	t.Parallel()

	cmd := New(BuildInfo{})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute help: %v", err)
	}
	if !strings.Contains(stdout.String(), "not suitable for real elections") {
		t.Fatalf("help does not include experimental warning:\n%s", stdout.String())
	}
}
