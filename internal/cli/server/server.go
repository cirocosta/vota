// Package server provides the single-process Vota sequencer command.
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cirocosta/vota/internal/crypto/blind"
	"github.com/cirocosta/vota/internal/crypto/sshsig"
	"github.com/cirocosta/vota/internal/httpapi"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/sequencer"
	"github.com/cirocosta/vota/internal/sequencerstore"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddress           string `json:"listen_address" yaml:"listen_address"`
	DatabasePath            string `json:"database_path" yaml:"database_path"`
	PublicBaseURL           string `json:"public_base_url" yaml:"public_base_url"`
	CheckpointKeyPath       string `json:"checkpoint_key_path" yaml:"checkpoint_key_path"`
	IssuerKeyPath           string `json:"issuer_key_path" yaml:"issuer_key_path"`
	AdminKeysPath           string `json:"admin_keys_path" yaml:"admin_keys_path"`
	TLSCertificatePath      string `json:"tls_certificate_path,omitempty" yaml:"tls_certificate_path,omitempty"`
	TLSPrivateKeyPath       string `json:"tls_private_key_path,omitempty" yaml:"tls_private_key_path,omitempty"`
	MaxBodyBytes            int64  `json:"max_body_bytes,omitempty" yaml:"max_body_bytes,omitempty"`
	RequestTimeout          string `json:"request_timeout,omitempty" yaml:"request_timeout,omitempty"`
	ShutdownTimeout         string `json:"shutdown_timeout,omitempty" yaml:"shutdown_timeout,omitempty"`
	ReadHeaderTimeout       string `json:"read_header_timeout,omitempty" yaml:"read_header_timeout,omitempty"`
	ReadTimeout             string `json:"read_timeout,omitempty" yaml:"read_timeout,omitempty"`
	WriteTimeout            string `json:"write_timeout,omitempty" yaml:"write_timeout,omitempty"`
	IdleTimeout             string `json:"idle_timeout,omitempty" yaml:"idle_timeout,omitempty"`
	MaxHeaderBytes          int    `json:"max_header_bytes,omitempty" yaml:"max_header_bytes,omitempty"`
	LogLevel                string `json:"log_level,omitempty" yaml:"log_level,omitempty"`
	AcknowledgeExperimental bool   `json:"acknowledge_experimental,omitempty" yaml:"acknowledge_experimental,omitempty"`
}

type Options struct {
	Rand io.Reader
	Run  func(context.Context, Config, io.Writer) error
}

type checkpointMaterial struct {
	PrivateKey string `json:"private_key"`
}

func Command(options Options) *cobra.Command {
	if options.Rand == nil {
		options.Rand = rand.Reader
	}
	if options.Run == nil {
		options.Run = func(ctx context.Context, config Config, stderr io.Writer) error {
			return Run(ctx, config, stderr, options.Rand)
		}
	}
	var configPath string
	command := &cobra.Command{
		Use: "serve", Short: "run the SSH-credit poll sequencer", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			config, err := LoadConfig(configPath)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(command.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return options.Run(ctx, config, command.ErrOrStderr())
		},
	}
	command.Flags().StringVar(&configPath, "config", "", "JSON or YAML server configuration path")
	_ = command.MarkFlagRequired("config")
	return command
}

func DiagnoseCommand() *cobra.Command {
	var configPath string
	command := &cobra.Command{
		Use: "diagnose", Short: "report aggregate sequencer health", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			config, err := LoadConfig(configPath)
			if err != nil {
				return err
			}
			for _, path := range []string{config.CheckpointKeyPath, config.IssuerKeyPath} {
				if _, err := os.Stat(path); err != nil {
					return fmt.Errorf("sequencer key unavailable: %w", err)
				}
			}
			checkpointKey, err := loadOrCreateCheckpointKey(config.CheckpointKeyPath, rand.Reader)
			if err != nil {
				return err
			}
			issuerData, err := os.ReadFile(config.IssuerKeyPath)
			if err != nil {
				return err
			}
			issuerKey, err := blind.ParsePrivateKey(issuerData)
			if err != nil {
				return err
			}
			adminKeys, err := loadAdminKeys(config.AdminKeysPath)
			if err != nil {
				return err
			}
			database, err := sequencerstore.Open(command.Context(), config.DatabasePath)
			if err != nil {
				return err
			}
			defer database.Close()
			service, err := sequencer.New(sequencer.Config{Store: database, IssuerPrivateKey: issuerKey, CheckpointPrivateKey: checkpointKey, AdminPublicKeys: adminKeys})
			if err != nil {
				return err
			}
			if err := service.Ready(command.Context()); err != nil {
				return err
			}
			stats, err := database.Stats(command.Context())
			if err != nil {
				return err
			}
			output := struct {
				Status string `json:"status"`
				sequencerstore.Stats
			}{Status: "ready", Stats: stats}
			encoded, err := protocol.MarshalCanonical(output)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(command.OutOrStdout(), string(encoded))
			return err
		},
	}
	command.Flags().StringVar(&configPath, "config", "", "server configuration path")
	_ = command.MarkFlagRequired("config")
	return command
}

func LoadConfig(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	decoder := yaml.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.KnownFields(true)
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode server config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Config{}, fmt.Errorf("trailing server config document")
	}
	config = withDefaults(config)
	if err := validateConfig(config); err != nil {
		return Config{}, err
	}
	return config, nil
}

func Run(ctx context.Context, config Config, stderr io.Writer, random io.Reader) error {
	config = withDefaults(config)
	if err := validateConfig(config); err != nil {
		return err
	}
	if random == nil {
		random = rand.Reader
	}
	checkpointKey, err := loadOrCreateCheckpointKey(config.CheckpointKeyPath, random)
	if err != nil {
		return err
	}
	issuerKey, _, err := blind.LoadOrCreatePrivateKey(config.IssuerKeyPath)
	if err != nil {
		return err
	}
	adminKeys, err := loadAdminKeys(config.AdminKeysPath)
	if err != nil {
		return err
	}
	database, err := sequencerstore.Open(ctx, config.DatabasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	service, err := sequencer.New(sequencer.Config{Store: database, IssuerPrivateKey: issuerKey, CheckpointPrivateKey: checkpointKey, AdminPublicKeys: adminKeys})
	if err != nil {
		return err
	}
	if err := service.Ready(ctx); err != nil {
		return err
	}
	level, err := parseLogLevel(config.LogLevel)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: level}))
	requestTimeout, _ := duration(config.RequestTimeout, 15*time.Second)
	api, err := httpapi.NewSequencer(httpapi.SequencerConfig{Service: service, PublicBaseURL: config.PublicBaseURL, MaxBodyBytes: config.MaxBodyBytes, RequestTimeout: requestTimeout, Logger: logger})
	if err != nil {
		return err
	}
	readHeaderTimeout, _ := duration(config.ReadHeaderTimeout, 5*time.Second)
	readTimeout, _ := duration(config.ReadTimeout, 15*time.Second)
	writeTimeout, _ := duration(config.WriteTimeout, 30*time.Second)
	idleTimeout, _ := duration(config.IdleTimeout, 60*time.Second)
	httpServer := httpapi.NewServer(httpapi.ServerConfig{Address: config.ListenAddress, Handler: api, ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: readTimeout, WriteTimeout: writeTimeout, IdleTimeout: idleTimeout, MaxHeaderBytes: config.MaxHeaderBytes})
	done := make(chan error, 1)
	go func() {
		if config.TLSCertificatePath != "" {
			done <- httpServer.ListenAndServeTLS(config.TLSCertificatePath, config.TLSPrivateKeyPath)
			return
		}
		done <- httpServer.ListenAndServe()
	}()
	logger.Warn("experimental sequencer started", "address", config.ListenAddress, "suitable_for_real_elections", false)
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownTimeout, _ := duration(config.ShutdownTimeout, 10*time.Second)
		shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := httpapi.Shutdown(shutdownContext, httpServer); err != nil {
			return err
		}
		err := <-done
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func validateConfig(config Config) error {
	host, _, err := net.SplitHostPort(config.ListenAddress)
	if err != nil {
		return fmt.Errorf("invalid listen address")
	}
	hasTLS := config.TLSCertificatePath != "" && config.TLSPrivateKeyPath != ""
	if !isLoopback(host) && !hasTLS && !config.AcknowledgeExperimental {
		return fmt.Errorf("non_loopback_requires_tls_or_experimental_acknowledgement")
	}
	if (config.TLSCertificatePath == "") != (config.TLSPrivateKeyPath == "") {
		return fmt.Errorf("TLS certificate and private key must be configured together")
	}
	for name, value := range map[string]string{"database_path": config.DatabasePath, "checkpoint_key_path": config.CheckpointKeyPath, "issuer_key_path": config.IssuerKeyPath, "admin_keys_path": config.AdminKeysPath, "public_base_url": config.PublicBaseURL} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	parsedURL, err := url.Parse(config.PublicBaseURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return fmt.Errorf("invalid public_base_url")
	}
	for name, value := range map[string]string{"request_timeout": config.RequestTimeout, "shutdown_timeout": config.ShutdownTimeout, "read_header_timeout": config.ReadHeaderTimeout, "read_timeout": config.ReadTimeout, "write_timeout": config.WriteTimeout, "idle_timeout": config.IdleTimeout} {
		if value != "" {
			parsed, err := time.ParseDuration(value)
			if err != nil || parsed <= 0 {
				return fmt.Errorf("invalid %s", name)
			}
		}
	}
	_, err = parseLogLevel(config.LogLevel)
	return err
}

func withDefaults(config Config) Config {
	if config.ListenAddress == "" {
		config.ListenAddress = "127.0.0.1:8080"
	}
	return config
}

func loadAdminKeys(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read admin keys: %w", err)
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
			return nil, fmt.Errorf("invalid admin key on line %d: %w", lineNumber+1, err)
		}
		canonical, _ := sshsig.CanonicalPublicKey(key)
		fingerprint, _ := sshsig.Fingerprint(key)
		if _, duplicate := seen[fingerprint]; duplicate {
			return nil, fmt.Errorf("duplicate admin key on line %d", lineNumber+1)
		}
		seen[fingerprint] = struct{}{}
		output = append(output, string(canonical))
	}
	if len(output) == 0 {
		return nil, fmt.Errorf("admin_keys_path contains no keys")
	}
	return output, nil
}

func loadOrCreateCheckpointKey(path string, random io.Reader) (ed25519.PrivateKey, error) {
	encoded, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		_, privateKey, err := ed25519.GenerateKey(random)
		if err != nil {
			return nil, err
		}
		material, err := protocol.MarshalCanonical(checkpointMaterial{PrivateKey: "ed25519priv:" + hex.EncodeToString(privateKey)})
		if err != nil {
			return nil, err
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		if _, err := file.Write(material); err != nil {
			_ = file.Close()
			return nil, err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
		return privateKey, nil
	}
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("checkpoint key permissions must be 0600")
	}
	var material checkpointMaterial
	if err := protocol.DecodeStrict(encoded, &material); err != nil {
		return nil, err
	}
	privateKey, err := protocol.DecodeFixedHex("ed25519priv", material.PrivateKey, ed25519.PrivateKeySize)
	if err != nil {
		return nil, fmt.Errorf("invalid checkpoint key")
	}
	return ed25519.PrivateKey(privateKey), nil
}

func duration(value string, fallback time.Duration) (time.Duration, error) {
	if value == "" {
		return fallback, nil
	}
	return time.ParseDuration(value)
}

func parseLogLevel(value string) (slog.Level, error) {
	switch strings.ToLower(value) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log_level %s", strconv.Quote(value))
	}
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}
