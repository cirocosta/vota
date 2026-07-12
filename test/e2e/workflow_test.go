package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestSSHCreditTeamWorkflow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ssh-agent socket required")
	}
	directory := t.TempDir()
	binary := filepath.Join(directory, "vota")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/vota")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}

	privateKeys := make([]ed25519.PrivateKey, 3)
	publicKeys := make([]string, 3)
	identityPaths := make([]string, 3)
	for index := range privateKeys {
		_, privateKeys[index], _ = ed25519.GenerateKey(rand.Reader)
		public, _ := ssh.NewPublicKey(privateKeys[index].Public())
		publicKeys[index] = string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(public)))
		identityPaths[index] = filepath.Join(directory, fmt.Sprintf("developer-%d.pub", index+1))
		if err := os.WriteFile(identityPaths[index], append([]byte(publicKeys[index]), '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	agentSocket := serveAgent(t, privateKeys)
	teamPath := filepath.Join(directory, "team.keys")
	teamFile := fmt.Sprintf("alice %s\nbob %s\ncarol %s\n", publicKeys[0], publicKeys[1], publicKeys[2])
	if err := os.WriteFile(teamPath, []byte(teamFile), 0o644); err != nil {
		t.Fatal(err)
	}
	adminPath := filepath.Join(directory, "admin.keys")
	if err := os.WriteFile(adminPath, append([]byte(publicKeys[0]), '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	address := freeAddress(t)
	configPath := filepath.Join(directory, "server.json")
	databasePath := filepath.Join(directory, "vota.sqlite")
	checkpointPath := filepath.Join(directory, "checkpoint.key")
	issuerPath := filepath.Join(directory, "issuer.key")
	writeConfig(t, configPath, address, databasePath, checkpointPath, issuerPath, adminPath)
	server := startServer(t, binary, configPath, address)
	stateDir := filepath.Join(directory, "state")
	environment := append(os.Environ(), "SSH_AUTH_SOCK="+agentSocket, "XDG_STATE_HOME="+stateDir)

	closesAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)
	stdout, _ := run(t, binary, environment, "", "poll", "create",
		"--server", "http://"+address,
		"--admin-identity", identityPaths[0],
		"--members", teamPath,
		"--question", "Where should we have lunch?",
		"--choice", "Pizza", "--choice", "Ramen", "--choice", "Salad",
		"--closes-at", closesAt,
	)
	pollURL := strings.TrimSpace(stdout)
	if !strings.HasPrefix(pollURL, "http://"+address+"/polls/sha256:") {
		t.Fatalf("poll URL = %q", pollURL)
	}
	pollID := strings.TrimPrefix(pollURL, "http://"+address+"/polls/")

	for index := range privateKeys {
		receipt := filepath.Join(directory, fmt.Sprintf("receipt-%d.json", index+1))
		stdout, _ := run(t, binary, environment, fmt.Sprintf("%d\n", index+1), "vote", pollURL, "--identity", identityPaths[index], "--choice-stdin", "--receipt-out", receipt)
		if !strings.Contains(stdout, "Vote recorded") {
			t.Fatalf("vote output = %s", stdout)
		}
		if info, err := os.Stat(receipt); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("receipt %d: info=%v err=%v", index, info, err)
		}
	}

	_, stderr := runExpectError(t, binary, environment, "1\n", "vote", pollURL, "--identity", identityPaths[0], "--choice-stdin")
	if !strings.Contains(stderr, "credit already claimed") {
		t.Fatalf("duplicate claim error = %s", stderr)
	}

	run(t, binary, environment, "", "poll", "close", pollURL, "--admin-identity", identityPaths[0])
	result, _ := run(t, binary, environment, "", "poll", "result", pollURL)
	for _, expected := range []string{"Pizza: 1", "Ramen: 1", "Salad: 1", "Total votes: 3"} {
		if !strings.Contains(result, expected) {
			t.Fatalf("result omits %q:\n%s", expected, result)
		}
	}
	auditDirectory := filepath.Join(directory, "audit")
	run(t, binary, environment, "", "audit", "export", "--poll", pollID, "--server", "http://"+address, "--out", auditDirectory)
	verified, _ := run(t, binary, environment, "", "audit", "verify", "--record", auditDirectory)
	if !strings.Contains(verified, "Audit verified") {
		t.Fatalf("audit output = %s", verified)
	}

	logs := stopServer(t, server)
	for _, prohibited := range []string{pollID, publicKeys[0], "Pizza", "Ramen", "Salad"} {
		if strings.Contains(logs, prohibited) {
			t.Fatalf("server logs contain prohibited value %q: %s", prohibited, logs)
		}
	}

	server = startServer(t, binary, configPath, address)
	result, _ = run(t, binary, environment, "", "poll", "result", pollURL)
	if !strings.Contains(result, "Total votes: 3") {
		t.Fatalf("restart lost result: %s", result)
	}
	_ = stopServer(t, server)

	restoreDirectory := filepath.Join(directory, "restore")
	if err := os.MkdirAll(restoreDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	restoredDatabase := copyFile(t, databasePath, filepath.Join(restoreDirectory, "vota.sqlite"), 0o600)
	restoredCheckpoint := copyFile(t, checkpointPath, filepath.Join(restoreDirectory, "checkpoint.key"), 0o600)
	restoredIssuer := copyFile(t, issuerPath, filepath.Join(restoreDirectory, "issuer.key"), 0o600)
	restoredAdmin := copyFile(t, adminPath, filepath.Join(restoreDirectory, "admin.keys"), 0o644)
	restoredConfig := filepath.Join(restoreDirectory, "server.json")
	writeConfig(t, restoredConfig, address, restoredDatabase, restoredCheckpoint, restoredIssuer, restoredAdmin)
	server = startServer(t, binary, restoredConfig, address)
	result, _ = run(t, binary, environment, "", "poll", "result", pollURL)
	if !strings.Contains(result, "Total votes: 3") {
		t.Fatalf("restore lost result: %s", result)
	}
	_ = stopServer(t, server)
}

type runningServer struct {
	command *exec.Cmd
	logs    bytes.Buffer
}

func startServer(tb testing.TB, binary, configPath, address string) *runningServer {
	tb.Helper()
	server := &runningServer{}
	server.command = exec.Command(binary, "serve", "--config", configPath)
	server.command.Stdout = &server.logs
	server.command.Stderr = &server.logs
	if err := server.command.Start(); err != nil {
		tb.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, err := http.Get("http://" + address + "/readyz")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return server
			}
		}
		if time.Now().After(deadline) {
			_ = server.command.Process.Kill()
			_ = server.command.Wait()
			tb.Fatalf("server did not become ready: %s", server.logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func stopServer(tb testing.TB, server *runningServer) string {
	tb.Helper()
	if err := server.command.Process.Signal(syscall.SIGTERM); err != nil {
		tb.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.command.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			tb.Fatalf("server stop: %v\n%s", err, server.logs.String())
		}
	case <-time.After(10 * time.Second):
		_ = server.command.Process.Kill()
		tb.Fatal("server did not stop")
	}
	return server.logs.String()
}

func run(tb testing.TB, binary string, environment []string, stdin string, args ...string) (string, string) {
	tb.Helper()
	stdout, stderr, err := execute(binary, environment, stdin, args...)
	if err != nil {
		tb.Fatalf("vota %s: %v\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), err, stdout, stderr)
	}
	return stdout, stderr
}

func runExpectError(tb testing.TB, binary string, environment []string, stdin string, args ...string) (string, string) {
	tb.Helper()
	stdout, stderr, err := execute(binary, environment, stdin, args...)
	if err == nil {
		tb.Fatalf("vota %s unexpectedly succeeded", strings.Join(args, " "))
	}
	return stdout, stderr
}

func execute(binary string, environment []string, stdin string, args ...string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = environment
	command.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.String(), stderr.String(), err
}

func serveAgent(tb testing.TB, keys []ed25519.PrivateKey) string {
	tb.Helper()
	directory, err := os.MkdirTemp("", "vota-e2e-agent-")
	if err != nil {
		tb.Fatal(err)
	}
	path := filepath.Join(directory, "agent.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		tb.Fatal(err)
	}
	keyring := agent.NewKeyring()
	for _, key := range keys {
		if err := keyring.Add(agent.AddedKey{PrivateKey: key}); err != nil {
			tb.Fatal(err)
		}
	}
	done := make(chan struct{})
	var connections sync.WaitGroup
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer connection.Close()
				_ = agent.ServeAgent(keyring, connection)
			}()
		}
	}()
	tb.Cleanup(func() {
		_ = listener.Close()
		<-done
		connections.Wait()
		_ = os.RemoveAll(directory)
	})
	return path
}

func freeAddress(tb testing.TB) string {
	tb.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func writeConfig(tb testing.TB, path, address, database, checkpoint, issuer, admins string) {
	tb.Helper()
	body := fmt.Sprintf(`{"listen_address":%q,"database_path":%q,"public_base_url":%q,"checkpoint_key_path":%q,"issuer_key_path":%q,"admin_keys_path":%q,"shutdown_timeout":"2s"}`, address, database, "http://"+address, checkpoint, issuer, admins)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		tb.Fatal(err)
	}
}

func copyFile(tb testing.TB, source, target string, mode os.FileMode) string {
	tb.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(target, data, mode); err != nil {
		tb.Fatal(err)
	}
	return target
}
