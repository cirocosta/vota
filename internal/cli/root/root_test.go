package root

import (
	"bytes"
	"encoding/json"
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
