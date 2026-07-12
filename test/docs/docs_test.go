package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/cirocosta/vota/internal/cli/root"
)

func TestMarkdownLinksResolve(t *testing.T) {
	repository := repositoryRoot(t)
	files := []string{filepath.Join(repository, "README.md")}
	err := filepath.WalkDir(filepath.Join(repository, "docs"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".md") && !strings.Contains(path, string(filepath.Separator)+"prds"+string(filepath.Separator)) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	linkPattern := regexp.MustCompile(`\]\(([^)#]+)(?:#[^)]+)?\)`)
	for _, path := range files {
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range linkPattern.FindAllSubmatch(encoded, -1) {
			target := string(match[1])
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			resolved := filepath.Join(filepath.Dir(path), filepath.FromSlash(target))
			if _, err := os.Stat(resolved); err != nil {
				t.Errorf("%s links to missing %s", path, target)
			}
		}
	}
}

func TestGettingStartedCommandInventoryMatchesCobra(t *testing.T) {
	repository := repositoryRoot(t)
	encoded, err := os.ReadFile(filepath.Join(repository, "docs", "getting-started.md"))
	if err != nil {
		t.Fatal(err)
	}
	command := root.New(root.BuildInfo{})
	count := 0
	for _, line := range strings.Split(string(encoded), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "vota ") || strings.Contains(line, "<") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "vota "))
		found, _, err := command.Find(fields)
		if err != nil || found == command {
			t.Errorf("documented command does not resolve: %s", line)
		}
		count++
	}
	if count != 4 {
		t.Fatalf("documented command count = %d, want 4", count)
	}
}

func TestPublishedDocsDescribeOnlySSHCreditArchitecture(t *testing.T) {
	repository := repositoryRoot(t)
	files := []string{"README.md", "docs/getting-started.md", "docs/operations.md", "docs/security.md", "docs/ssh-credit-quickstart.md"}
	for _, relative := range files {
		encoded, err := os.ReadFile(filepath.Join(repository, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		for _, obsolete := range []string{"vota-v1-experimental", "trustee ceremony", "ring-v1", "/v1/polls"} {
			if bytesContainsFold(encoded, []byte(obsolete)) {
				t.Errorf("%s contains obsolete architecture term %q", relative, obsolete)
			}
		}
	}
}

func TestTeamExampleIsExecutable(t *testing.T) {
	path := filepath.Join(repositoryRoot(t), "examples", "ssh-credit-team", "demo.sh")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("example is not executable: mode %o", info.Mode().Perm())
	}
}

func bytesContainsFold(value, fragment []byte) bool {
	return strings.Contains(strings.ToLower(string(value)), strings.ToLower(string(fragment)))
}

func repositoryRoot(tb testing.TB) string {
	tb.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		tb.Fatal("resolve source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}
