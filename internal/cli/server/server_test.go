package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestLoadConfigSupportsStrictJSONAndYAML(t *testing.T) {
	directory := t.TempDir()
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "json", body: `{"database_path":"vota.sqlite","checkpoint_key_path":"checkpoint.key","issuer_key_path":"issuer.key","admin_keys_path":"admin.keys","public_base_url":"http://127.0.0.1:8080"}`},
		{name: "yaml", body: "database_path: vota.sqlite\ncheckpoint_key_path: checkpoint.key\nissuer_key_path: issuer.key\nadmin_keys_path: admin.keys\npublic_base_url: http://127.0.0.1:8080\n"},
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

func TestConfigRejectsUnsafeNonLoopback(t *testing.T) {
	config := Config{ListenAddress: "0.0.0.0:8080", DatabasePath: "vota.sqlite", CheckpointKeyPath: "checkpoint.key", IssuerKeyPath: "issuer.key", AdminKeysPath: "admin.keys", PublicBaseURL: "https://vota.example"}
	if err := validateConfig(config); err == nil || err.Error() != "non_loopback_requires_tls_or_experimental_acknowledgement" {
		t.Fatalf("error = %v", err)
	}
	config.AcknowledgeExperimental = true
	if err := validateConfig(config); err != nil {
		t.Fatalf("acknowledged config: %v", err)
	}
	for _, value := range []string{
		"ftp://vota.example", "https://user:pass@vota.example",
		"https://vota.example?token=secret", "https://vota.example#fragment",
	} {
		config.PublicBaseURL = value
		if err := validateConfig(config); err == nil || err.Error() != "invalid public_base_url" {
			t.Fatalf("public URL %q error = %v", value, err)
		}
	}
}

func TestCheckpointKeyCreatedOwnerOnlyAndReloaded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "checkpoint.key")
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

func TestRunCreatesKeysAndShutsDown(t *testing.T) {
	directory := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	_, adminPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	adminPublic, _ := ssh.NewPublicKey(adminPrivate.Public())
	adminPath := filepath.Join(directory, "admin.keys")
	if err := os.WriteFile(adminPath, ssh.MarshalAuthorizedKey(adminPublic), 0o644); err != nil {
		t.Fatal(err)
	}
	config := Config{ListenAddress: address, DatabasePath: filepath.Join(directory, "vota.sqlite"), CheckpointKeyPath: filepath.Join(directory, "checkpoint.key"), IssuerKeyPath: filepath.Join(directory, "issuer.key"), AdminKeysPath: adminPath, PublicBaseURL: "http://" + address, ShutdownTimeout: "1s"}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, config, io.Discard, bytes.NewReader(bytes.Repeat([]byte{0x31}, 128))) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, requestErr := http.Get("http://" + address + "/readyz")
		if requestErr == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not initialize")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, path := range []string{config.CheckpointKeyPath, config.IssuerKeyPath, config.DatabasePath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing %s: %v", path, err)
		}
	}
	for _, path := range []string{config.CheckpointKeyPath, config.IssuerKeyPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("private key mode for %s = %v", path, info.Mode().Perm())
		}
	}
}
