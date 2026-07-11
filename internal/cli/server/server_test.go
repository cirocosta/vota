package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigSupportsStrictJSONAndYAML(t *testing.T) {
	hash := sha256.Sum256([]byte("admin-token"))
	directory := t.TempDir()
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "json", body: `{"database_path":"vota.sqlite","checkpoint_key_path":"checkpoint.key","admin_token_hashes":["sha256:` + hex.EncodeToString(hash[:]) + `"]}`},
		{name: "yaml", body: "database_path: vota.sqlite\ncheckpoint_key_path: checkpoint.key\nadmin_token_hashes:\n  - sha256:" + hex.EncodeToString(hash[:]) + "\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(directory, test.name)
			if err := os.WriteFile(path, []byte(test.body), 0o600); err != nil {
				t.Fatal(err)
			}
			config, err := LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if config.ListenAddress != "127.0.0.1:8080" {
				t.Fatalf("listen address = %s", config.ListenAddress)
			}
		})
	}
	unknownPath := filepath.Join(directory, "unknown.yaml")
	if err := os.WriteFile(unknownPath, []byte("unknown: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(unknownPath); err == nil || !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestConfigRejectsNonLoopbackWithoutAcknowledgement(t *testing.T) {
	hash := sha256.Sum256([]byte("admin-token"))
	config := Config{ListenAddress: "0.0.0.0:8080", DatabasePath: "vota.sqlite", CheckpointKeyPath: "checkpoint.key", AdminTokenHashes: []string{"sha256:" + hex.EncodeToString(hash[:])}}
	if err := validateConfig(config); err == nil || err.Error() != "non_loopback_requires_experimental_acknowledgement" {
		t.Fatalf("error = %v", err)
	}
	config.AcknowledgeExperimental = true
	if err := validateConfig(config); err != nil {
		t.Fatalf("acknowledged config: %v", err)
	}
}

func TestCheckpointKeyCreatedOwnerOnlyAndReloaded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint.key")
	first, err := loadOrCreateCheckpointKey(path, bytes.NewReader(bytes.Repeat([]byte{0x42}, 128)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateCheckpointKey(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("checkpoint key changed after reload")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("permissions = %o", info.Mode().Perm())
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadOrCreateCheckpointKey(path, nil); err == nil || err.Error() != "checkpoint key permissions must be 0600" {
			t.Fatalf("permission error = %v", err)
		}
	}
}

func TestServeCommandLoadsConfigAndWarns(t *testing.T) {
	hash := sha256.Sum256([]byte("admin-token"))
	path := filepath.Join(t.TempDir(), "server.json")
	body := `{"database_path":"vota.sqlite","checkpoint_key_path":"checkpoint.key","admin_token_hashes":["sha256:` + hex.EncodeToString(hash[:]) + `"]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	command := Command(Options{Run: func(_ context.Context, config Config, _ io.Writer) error {
		called = true
		if config.ListenAddress != "127.0.0.1:8080" {
			t.Fatalf("listen address = %s", config.ListenAddress)
		}
		return nil
	}})
	command.SetArgs([]string{"--config", path})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("server runner was not called")
	}
	if !strings.Contains(command.Long, "not suitable for real elections") {
		t.Fatalf("help warning = %s", command.Long)
	}
}

func TestRunShutsDownOnContextCancellation(t *testing.T) {
	directory := t.TempDir()
	hash := sha256.Sum256([]byte("admin-token"))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	config := Config{
		ListenAddress: address, DatabasePath: filepath.Join(directory, "vota.sqlite"),
		CheckpointKeyPath: filepath.Join(directory, "checkpoint.key"), AdminTokenHashes: []string{"sha256:" + hex.EncodeToString(hash[:])}, ShutdownTimeout: "1s",
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, config, &bytes.Buffer{}, bytes.NewReader(bytes.Repeat([]byte{0x31}, 256)))
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		response, requestErr := http.Get("http://" + address + "/healthz")
		if requestErr == nil {
			_ = response.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not initialize")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
}
