// Package sequencerstore persists independent credit and ballot streams.
package sequencerstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cirocosta/vota/migrations"
	"modernc.org/sqlite"
)

const emptyHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

type Store struct{ db *sql.DB }
type Tx struct{ tx *sql.Tx }

var memoryStoreID atomic.Uint64

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
	PollID                string
	ArtifactHash          string
	Artifact              []byte
	State                 string
	CreatedAt             string
	ClosesAt              string
	ClosedAt              string
	IssuerKeyID           string
	EligibilityCommitment string
}

type Choice struct {
	PollID   string
	ChoiceID string
	Label    string
	Position int
}

type Credit struct {
	PollID             string
	SSHFingerprint     string
	SSHPublicKey       string
	IssuanceRequestID  string
	BlindedMessageHash string
	BlindSignature     []byte
	ClaimedAt          string
}

type CreditEvent struct {
	PollID       string
	Sequence     uint64
	PreviousHash string
	EventHash    string
	Artifact     []byte
	Signature    []byte
	RecordedAt   string
}

type BallotEvent struct {
	PollID       string
	Sequence     uint64
	Type         string
	PreviousHash string
	EventHash    string
	Artifact     []byte
	Receipt      []byte
	RecordedAt   string
}

type Tally struct {
	PollID    string
	Artifact  []byte
	CreatedAt string
}

type Checkpoint struct {
	PollID         string
	BallotSequence uint64
	EventHash      string
	Artifact       []byte
}

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

func (store *Store) Close() error { return store.db.Close() }

func (store *Store) Ping(ctx context.Context) error {
	if err := store.db.PingContext(ctx); err != nil {
		return &Error{Code: "database_unavailable", Err: err}
	}
	return nil
}

func (store *Store) Transaction(ctx context.Context, operation func(*Tx) error) error {
	databaseTx, err := store.begin(ctx)
	if err != nil {
		return &Error{Code: "transaction_begin_failed", Err: err}
	}
	tx := &Tx{tx: databaseTx}
	if err := operation(tx); err != nil {
		_ = databaseTx.Rollback()
		return err
	}
	if err := databaseTx.Commit(); err != nil {
		return &Error{Code: "transaction_commit_failed", Err: err}
	}
	return nil
}

func (store *Store) begin(ctx context.Context) (*sql.Tx, error) {
	for attempts := 0; ; attempts++ {
		tx, err := store.db.BeginTx(ctx, nil)
		if err == nil {
			return tx, nil
		}
		if !isBusy(err) || attempts >= 100 {
			return nil, err
		}
		timer := time.NewTimer(time.Duration(attempts+1) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (store *Store) migrate(ctx context.Context) error {
	if _, err := store.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP) STRICT`); err != nil {
		return &Error{Code: "migration_failed", Err: err}
	}
	entries, err := migrations.Files.ReadDir(".")
	if err != nil {
		return &Error{Code: "migration_failed", Err: err}
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		var version int
		if _, err := fmt.Sscanf(name, "%03d_", &version); err != nil || version < 1 {
			return &Error{Code: "migration_failed", Err: fmt.Errorf("invalid migration %q", name)}
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
		if err := store.Transaction(ctx, func(tx *Tx) error {
			if _, err := tx.tx.ExecContext(ctx, string(contents)); err != nil {
				return &Error{Code: "migration_failed", Err: err}
			}
			_, err := tx.tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, name) VALUES (?, ?)`, version, name)
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}

func dataSourceName(path string) string {
	memory := path == ":memory:"
	if memory {
		path = fmt.Sprintf("file:vota-sequencer-memory-%d", memoryStoreID.Add(1))
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
	if memory {
		parameters.Set("cache", "shared")
		parameters.Set("mode", "memory")
	}
	return path + separator + parameters.Encode()
}

func EventHash(stream string, pollID string, sequence uint64, previousHash string, artifact []byte) string {
	hash := sha256.New()
	hash.Write([]byte("vota:" + stream + ":event:v1"))
	hash.Write([]byte{0})
	hash.Write([]byte(pollID))
	var encodedSequence [8]byte
	binary.BigEndian.PutUint64(encodedSequence[:], sequence)
	hash.Write(encodedSequence[:])
	hash.Write([]byte(previousHash))
	hash.Write(artifact)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func EmptyHash() string { return emptyHash }

func isConstraint(err error) bool {
	var sqliteError *sqlite.Error
	return errors.As(err, &sqliteError) && sqliteError.Code()&0xff == 19
}

func isBusy(err error) bool {
	var sqliteError *sqlite.Error
	if !errors.As(err, &sqliteError) {
		return false
	}
	code := sqliteError.Code() & 0xff
	return code == 5 || code == 6
}
