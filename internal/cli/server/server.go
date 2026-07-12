// Package server provides the collector server Cobra command.
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cirocosta/vota/internal/app"
	"github.com/cirocosta/vota/internal/httpapi"
	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/store"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddress           string   `json:"listen_address" yaml:"listen_address"`
	DatabasePath            string   `json:"database_path" yaml:"database_path"`
	PublicBaseURL           string   `json:"public_base_url" yaml:"public_base_url"`
	AdminTokenHashes        []string `json:"admin_token_hashes" yaml:"admin_token_hashes"`
	CheckpointKeyPath       string   `json:"checkpoint_key_path" yaml:"checkpoint_key_path"`
	TLSCertificatePath      string   `json:"tls_certificate_path,omitempty" yaml:"tls_certificate_path,omitempty"`
	TLSPrivateKeyPath       string   `json:"tls_private_key_path,omitempty" yaml:"tls_private_key_path,omitempty"`
	MaxBodyBytes            int64    `json:"max_body_bytes,omitempty" yaml:"max_body_bytes,omitempty"`
	VerificationConcurrency int      `json:"verification_concurrency,omitempty" yaml:"verification_concurrency,omitempty"`
	RequestTimeout          string   `json:"request_timeout,omitempty" yaml:"request_timeout,omitempty"`
	ShutdownTimeout         string   `json:"shutdown_timeout,omitempty" yaml:"shutdown_timeout,omitempty"`
	ReadHeaderTimeout       string   `json:"read_header_timeout,omitempty" yaml:"read_header_timeout,omitempty"`
	ReadTimeout             string   `json:"read_timeout,omitempty" yaml:"read_timeout,omitempty"`
	WriteTimeout            string   `json:"write_timeout,omitempty" yaml:"write_timeout,omitempty"`
	IdleTimeout             string   `json:"idle_timeout,omitempty" yaml:"idle_timeout,omitempty"`
	MaxHeaderBytes          int      `json:"max_header_bytes,omitempty" yaml:"max_header_bytes,omitempty"`
	LogLevel                string   `json:"log_level,omitempty" yaml:"log_level,omitempty"`
	AcknowledgeExperimental bool     `json:"acknowledge_experimental,omitempty" yaml:"acknowledge_experimental,omitempty"`
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
		Use:   "serve",
		Short: "run the experimental collector",
		Long:  "Run the experimental Vota collector. It is not suitable for real elections.",
		Args:  cobra.NoArgs,
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
	database, err := store.Open(ctx, config.DatabasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	service, err := app.NewService(database, checkpointKey, app.ServiceOptions{})
	if err != nil {
		return err
	}
	level, err := parseLogLevel(config.LogLevel)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: level}))
	hashes, err := adminHashes(config.AdminTokenHashes)
	if err != nil {
		return err
	}
	requestTimeout, _ := duration(config.RequestTimeout, 15*time.Second)
	api, err := httpapi.New(httpapi.Config{
		Service: service, AdminTokenHashes: hashes, MaxBodyBytes: config.MaxBodyBytes,
		VerificationConcurrency: config.VerificationConcurrency, RequestTimeout: requestTimeout, Logger: logger,
	})
	if err != nil {
		return err
	}
	readHeaderTimeout, _ := duration(config.ReadHeaderTimeout, 5*time.Second)
	readTimeout, _ := duration(config.ReadTimeout, 15*time.Second)
	writeTimeout, _ := duration(config.WriteTimeout, 30*time.Second)
	idleTimeout, _ := duration(config.IdleTimeout, 60*time.Second)
	server := httpapi.NewServer(httpapi.ServerConfig{
		Address: config.ListenAddress, Handler: api, ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout: readTimeout, WriteTimeout: writeTimeout, IdleTimeout: idleTimeout, MaxHeaderBytes: config.MaxHeaderBytes,
	})
	done := make(chan error, 1)
	go func() {
		if config.TLSCertificatePath != "" {
			done <- server.ListenAndServeTLS(config.TLSCertificatePath, config.TLSPrivateKeyPath)
			return
		}
		done <- server.ListenAndServe()
	}()
	logger.Warn("experimental collector started", "address", config.ListenAddress, "suitable_for_real_elections", false)
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
		if err := httpapi.Shutdown(shutdownContext, server); err != nil {
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
	if !isLoopback(host) && !config.AcknowledgeExperimental {
		return fmt.Errorf("non_loopback_requires_experimental_acknowledgement")
	}
	if strings.TrimSpace(config.DatabasePath) == "" || strings.TrimSpace(config.CheckpointKeyPath) == "" {
		return fmt.Errorf("database_path and checkpoint_key_path are required")
	}
	if config.PublicBaseURL != "" {
		parsed, err := url.Parse(config.PublicBaseURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("invalid public_base_url")
		}
	}
	if len(config.AdminTokenHashes) == 0 {
		return fmt.Errorf("admin_token_hashes are required")
	}
	if _, err := adminHashes(config.AdminTokenHashes); err != nil {
		return err
	}
	if (config.TLSCertificatePath == "") != (config.TLSPrivateKeyPath == "") {
		return fmt.Errorf("TLS certificate and private key must be configured together")
	}
	for name, value := range map[string]string{
		"request_timeout": config.RequestTimeout, "shutdown_timeout": config.ShutdownTimeout,
		"read_header_timeout": config.ReadHeaderTimeout, "read_timeout": config.ReadTimeout,
		"write_timeout": config.WriteTimeout, "idle_timeout": config.IdleTimeout,
	} {
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

func adminHashes(values []string) ([][sha256.Size]byte, error) {
	hashes := make([][sha256.Size]byte, len(values))
	for index, value := range values {
		decoded, err := protocol.DecodeFixedHex("sha256", value, sha256.Size)
		if err != nil {
			return nil, fmt.Errorf("invalid admin token hash at index %d", index)
		}
		copy(hashes[index][:], decoded)
	}
	return hashes, nil
}

func loadOrCreateCheckpointKey(path string, random io.Reader) (ed25519.PrivateKey, error) {
	encoded, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
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
	if info.Mode().Perm()&0o077 != 0 {
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
