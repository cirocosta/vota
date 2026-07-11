// Package store provides transactional SQLite persistence without protocol validation.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cirocosta/vota/migrations"
	"modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type Tx struct {
	tx *sql.Tx
}

type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return e.Code
	}
	return fmt.Sprintf("%s: %v", e.Code, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

func ErrorCode(err error) string {
	var target *Error
	if errors.As(err, &target) {
		return target.Code
	}
	return "internal_error"
}

type Poll struct {
	PollID        string
	ManifestHash  string
	Manifest      []byte
	State         string
	CreatedAt     string
	ClosedAt      string
	AggregateHash string
	Aggregate     []byte
}

type Ballot struct {
	PollID     string
	BallotHash string
	Nullifier  string
	Artifact   []byte
	Sequence   uint64
	AcceptedAt string
	Receipt    []byte
}

type Event struct {
	PollID     string
	Sequence   uint64
	EventHash  string
	Artifact   []byte
	AcceptedAt string
}

type Checkpoint struct {
	PollID         string
	Sequence       uint64
	CheckpointHash string
	Artifact       []byte
}

type TrusteeShare struct {
	PollID        string
	TrusteeID     string
	AggregateHash string
	ArtifactHash  string
	Artifact      []byte
	SubmittedAt   string
}

type Tally struct {
	PollID        string
	AggregateHash string
	EvidenceHash  string
	Artifact      []byte
	CreatedAt     string
}

// Open opens a database, configures every connection, and applies migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, &Error{Code: "invalid_database_path"}
	}
	db, err := sql.Open("sqlite", dataSourceName(path))
	if err != nil {
		return nil, &Error{Code: "database_open_failed", Err: err}
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, &Error{Code: "database_open_failed", Err: err}
	}
	store := &Store{db: db}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (store *Store) Close() error {
	if err := store.db.Close(); err != nil {
		return &Error{Code: "database_close_failed", Err: err}
	}
	return nil
}

// Transaction commits all writes together or rolls them all back.
func (store *Store) Transaction(ctx context.Context, operation func(*Tx) error) error {
	return store.transaction(ctx, operation, nil)
}

func (store *Store) transaction(ctx context.Context, operation func(*Tx) error, beforeCommit func() error) error {
	databaseTx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return &Error{Code: "transaction_begin_failed", Err: err}
	}
	tx := &Tx{tx: databaseTx}
	if err := operation(tx); err != nil {
		_ = databaseTx.Rollback()
		return err
	}
	if beforeCommit != nil {
		if err := beforeCommit(); err != nil {
			_ = databaseTx.Rollback()
			return err
		}
	}
	if err := databaseTx.Commit(); err != nil {
		return &Error{Code: "transaction_commit_failed", Err: err}
	}
	return nil
}

func (store *Store) migrate(ctx context.Context) error {
	if _, err := store.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP) STRICT`); err != nil {
		return &Error{Code: "migration_failed", Err: err}
	}
	entries, err := migrations.Files.ReadDir(".")
	if err != nil {
		return &Error{Code: "migration_failed", Err: err}
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		var version int
		if _, err := fmt.Sscanf(name, "%03d_", &version); err != nil || version < 1 {
			return &Error{Code: "migration_failed", Err: fmt.Errorf("invalid migration name %q", name)}
		}
		var exists int
		err := store.db.QueryRowContext(ctx, `SELECT 1 FROM schema_migrations WHERE version = ?`, version).Scan(&exists)
		if err == nil {
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return &Error{Code: "migration_failed", Err: err}
		}
		contents, err := migrations.Files.ReadFile(name)
		if err != nil {
			return &Error{Code: "migration_failed", Err: err}
		}
		if err := store.transaction(ctx, func(tx *Tx) error {
			if _, err := tx.tx.ExecContext(ctx, string(contents)); err != nil {
				return &Error{Code: "migration_failed", Err: err}
			}
			if _, err := tx.tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, name) VALUES (?, ?)`, version, name); err != nil {
				return &Error{Code: "migration_failed", Err: err}
			}
			return nil
		}, nil); err != nil {
			return err
		}
	}
	return nil
}

func dataSourceName(path string) string {
	if path == ":memory:" {
		path = "file:vota-memory"
	} else if !strings.HasPrefix(path, "file:") {
		path = "file:" + filepath.ToSlash(path)
	}
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	parameters := url.Values{}
	parameters.Add("_pragma", "busy_timeout(5000)")
	parameters.Add("_pragma", "foreign_keys(1)")
	parameters.Add("_pragma", "journal_mode(WAL)")
	parameters.Set("_txlock", "immediate")
	if strings.Contains(path, "vota-memory") {
		parameters.Set("cache", "shared")
		parameters.Set("mode", "memory")
	}
	return path + separator + parameters.Encode()
}

func isConstraint(err error) bool {
	var sqliteError *sqlite.Error
	return errors.As(err, &sqliteError) && sqliteError.Code()&0xff == 19
}
