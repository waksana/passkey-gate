package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/webauthn"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrUnauthorized   = errors.New("unauthorized")
	ErrLastCredential = errors.New("cannot delete the last credential")
	ErrBootstrap      = errors.New("bootstrap token is invalid, expired, or consumed")
)

type Owner struct {
	ID          []byte
	Credentials []Credential
}

func (o Owner) WebAuthnID() []byte        { return bytes.Clone(o.ID) }
func (Owner) WebAuthnName() string        { return "owner" }
func (Owner) WebAuthnDisplayName() string { return "owner" }
func (o Owner) WebAuthnCredentials() []webauthn.Credential {
	result := make([]webauthn.Credential, len(o.Credentials))
	for i := range o.Credentials {
		result[i] = o.Credentials[i].Value
	}
	return result
}

type Credential struct {
	ID         int64
	Value      webauthn.Credential
	Label      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

type Session struct {
	TokenHash       [32]byte
	Host            string
	CredentialID    int64
	CreatedAt       time.Time
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
}

type Store struct {
	db  *sql.DB
	now func() time.Time
}

func Open(ctx context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("database path must not be a symbolic link")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect database: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open database file: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close database file: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("secure database permissions: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	s := &Store{db: db, now: time.Now}
	if err := s.initialize(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) initialize(ctx context.Context) error {
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := s.db.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("configure sqlite (%s): %w", pragma, err)
		}
	}

	const schema = `
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);
INSERT INTO schema_version(version)
SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version);

CREATE TABLE IF NOT EXISTS owner (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    webauthn_user_id BLOB NOT NULL UNIQUE CHECK (length(webauthn_user_id) = 32),
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id BLOB NOT NULL UNIQUE,
    credential_data BLOB NOT NULL,
    label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 80),
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB PRIMARY KEY CHECK (length(token_hash) = 32),
    host TEXT NOT NULL,
    credential_id INTEGER REFERENCES credentials(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    authenticated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS sessions_host_idx ON sessions(host);

CREATE TABLE IF NOT EXISTS bootstrap_tokens (
    token_hash BLOB PRIMARY KEY CHECK (length(token_hash) = 32),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
);
CREATE INDEX IF NOT EXISTS bootstrap_expiry_idx ON bootstrap_tokens(expires_at);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("apply database schema: %w", err)
	}

	var version int
	if err := s.db.QueryRowContext(ctx, "SELECT version FROM schema_version LIMIT 1").Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version != 1 {
		return fmt.Errorf("unsupported database schema version %d", version)
	}

	ownerID := make([]byte, 32)
	if _, err := rand.Read(ownerID); err != nil {
		return fmt.Errorf("generate owner ID: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		"INSERT OR IGNORE INTO owner(id, webauthn_user_id, created_at) VALUES(1, ?, ?)",
		ownerID, s.now().Unix()); err != nil {
		return fmt.Errorf("initialize owner: %w", err)
	}
	return s.initializeDevices(ctx)
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Health(ctx context.Context) error {
	var one int
	return s.db.QueryRowContext(ctx, "SELECT 1").Scan(&one)
}

func (s *Store) Owner(ctx context.Context) (Owner, error) {
	var owner Owner
	if err := s.db.QueryRowContext(ctx, "SELECT webauthn_user_id FROM owner WHERE id = 1").Scan(&owner.ID); err != nil {
		return Owner{}, fmt.Errorf("load owner: %w", err)
	}
	credentials, err := s.ListCredentials(ctx)
	if err != nil {
		return Owner{}, err
	}
	owner.Credentials = credentials
	return owner, nil
}

func (s *Store) ListCredentials(ctx context.Context) ([]Credential, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, credential_data, label, created_at, last_used_at FROM credentials ORDER BY created_at, id")
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	defer rows.Close()

	var result []Credential
	for rows.Next() {
		var item Credential
		var encoded []byte
		var created int64
		var used sql.NullInt64
		if err := rows.Scan(&item.ID, &encoded, &item.Label, &created, &used); err != nil {
			return nil, fmt.Errorf("scan credential: %w", err)
		}
		if rest, err := item.Value.UnmarshalMsg(encoded); err != nil || len(rest) != 0 {
			if err == nil {
				err = errors.New("trailing credential data")
			}
			return nil, fmt.Errorf("decode credential %d: %w", item.ID, err)
		}
		item.CreatedAt = time.Unix(created, 0).UTC()
		if used.Valid {
			value := time.Unix(used.Int64, 0).UTC()
			item.LastUsedAt = &value
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credentials: %w", err)
	}
	return result, nil
}

func (s *Store) CredentialCount(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM credentials").Scan(&count); err != nil {
		return 0, fmt.Errorf("count credentials: %w", err)
	}
	return count, nil
}

func (s *Store) AddCredential(ctx context.Context, value webauthn.Credential, label string, bootstrapHash *[32]byte) error {
	label = normalizeLabel(label)
	if label == "" {
		return errors.New("credential label is required")
	}
	encoded, err := value.MarshalMsg(nil)
	if err != nil {
		return fmt.Errorf("encode credential: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin credential transaction: %w", err)
	}
	defer tx.Rollback()

	now := s.now().Unix()
	if bootstrapHash != nil {
		result, err := tx.ExecContext(ctx, `
UPDATE bootstrap_tokens
SET consumed_at = ?
WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?`, now, bootstrapHash[:], now)
		if err != nil {
			return fmt.Errorf("consume bootstrap token: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil || affected != 1 {
			return ErrBootstrap
		}
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO credentials(credential_id, credential_data, label, created_at)
VALUES(?, ?, ?, ?)`, value.ID, encoded, label, now); err != nil {
		return fmt.Errorf("store credential: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit credential: %w", err)
	}
	return nil
}

func (s *Store) RenameCredential(ctx context.Context, id int64, label string) error {
	label = normalizeLabel(label)
	if label == "" {
		return errors.New("credential label is required")
	}
	result, err := s.db.ExecContext(ctx, "UPDATE credentials SET label = ? WHERE id = ?", label, id)
	if err != nil {
		return fmt.Errorf("rename credential: %w", err)
	}
	return requireAffected(result)
}

func (s *Store) DeleteCredential(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin deletion: %w", err)
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM credentials").Scan(&count); err != nil {
		return fmt.Errorf("count credentials: %w", err)
	}
	if count <= 1 {
		return ErrLastCredential
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM credentials WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
		return fmt.Errorf("revoke sessions after credential deletion: %w", err)
	}
	if err := revokeDevices(ctx, tx); err != nil {
		return fmt.Errorf("revoke devices after credential deletion: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit deletion: %w", err)
	}
	return nil
}

func (s *Store) IssueBootstrap(ctx context.Context, lifetime time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate bootstrap token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256(raw)
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin bootstrap transaction: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM bootstrap_tokens WHERE consumed_at IS NOT NULL OR expires_at <= ?", now.Unix()); err != nil {
		return "", fmt.Errorf("clean bootstrap tokens: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO bootstrap_tokens(token_hash, created_at, expires_at)
VALUES(?, ?, ?)`, hash[:], now.Unix(), now.Add(lifetime).Unix()); err != nil {
		return "", fmt.Errorf("store bootstrap token: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit bootstrap token: %w", err)
	}
	return token, nil
}

func (s *Store) ValidBootstrap(ctx context.Context, hash [32]byte) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `
SELECT 1 FROM bootstrap_tokens
WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?`, hash[:], s.now().Unix()).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("validate bootstrap token: %w", err)
	}
	return true, nil
}

func (s *Store) CreateSession(ctx context.Context, host string, credential webauthn.Credential, lifetime time.Duration) (string, Session, error) {
	token, hash, err := newSessionToken()
	if err != nil {
		return "", Session{}, err
	}
	encoded, err := credential.MarshalMsg(nil)
	if err != nil {
		return "", Session{}, fmt.Errorf("encode updated credential: %w", err)
	}
	now := s.now().UTC()
	session := Session{
		TokenHash:       hash,
		Host:            host,
		CreatedAt:       now,
		AuthenticatedAt: now,
		ExpiresAt:       now.Add(lifetime),
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", Session{}, fmt.Errorf("begin session transaction: %w", err)
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `
UPDATE credentials SET credential_data = ?, last_used_at = ? WHERE credential_id = ?
RETURNING id`, encoded, now.Unix(), credential.ID).Scan(&session.CredentialID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", Session{}, ErrUnauthorized
		}
		return "", Session{}, fmt.Errorf("update credential usage: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO sessions(token_hash, host, credential_id, created_at, authenticated_at, expires_at)
VALUES(?, ?, ?, ?, ?, ?)`,
		hash[:], host, session.CredentialID, now.Unix(), now.Unix(), session.ExpiresAt.Unix()); err != nil {
		return "", Session{}, fmt.Errorf("store session: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at <= ?", now.Unix()); err != nil {
		return "", Session{}, fmt.Errorf("clean expired sessions: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", Session{}, fmt.Errorf("commit session: %w", err)
	}
	return token, session, nil
}

func (s *Store) Session(ctx context.Context, token, host string) (Session, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return Session{}, ErrUnauthorized
	}
	hash := sha256.Sum256(raw)
	var value Session
	var storedHash []byte
	var created, authenticated, expires int64
	var credentialID sql.NullInt64
	err = s.db.QueryRowContext(ctx, `
SELECT token_hash, host, credential_id, created_at, authenticated_at, expires_at
FROM sessions WHERE token_hash = ?`, hash[:]).Scan(
		&storedHash, &value.Host, &credentialID, &created, &authenticated, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrUnauthorized
	}
	if err != nil {
		return Session{}, fmt.Errorf("load session: %w", err)
	}
	if len(storedHash) != len(value.TokenHash) || subtle.ConstantTimeCompare(storedHash, hash[:]) != 1 ||
		value.Host != host || expires <= s.now().Unix() {
		return Session{}, ErrUnauthorized
	}
	copy(value.TokenHash[:], storedHash)
	if credentialID.Valid {
		value.CredentialID = credentialID.Int64
	}
	value.CreatedAt = time.Unix(created, 0).UTC()
	value.AuthenticatedAt = time.Unix(authenticated, 0).UTC()
	value.ExpiresAt = time.Unix(expires, 0).UTC()
	return value, nil
}

func (s *Store) MarkFresh(ctx context.Context, hash [32]byte, credential webauthn.Credential) error {
	encoded, err := credential.MarshalMsg(nil)
	if err != nil {
		return fmt.Errorf("encode credential: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin fresh-auth transaction: %w", err)
	}
	defer tx.Rollback()
	now := s.now().Unix()
	result, err := tx.ExecContext(ctx, `
UPDATE credentials SET credential_data = ?, last_used_at = ? WHERE credential_id = ?`,
		encoded, now, credential.ID)
	if err != nil {
		return fmt.Errorf("update credential usage: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return ErrUnauthorized
	}
	result, err = tx.ExecContext(ctx, `
UPDATE sessions SET authenticated_at = ?
WHERE token_hash = ? AND expires_at > ?`, now, hash[:], now)
	if err != nil {
		return fmt.Errorf("update fresh authentication: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return ErrUnauthorized
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit fresh authentication: %w", err)
	}
	return nil
}

func (s *Store) RevokeAllSessions(ctx context.Context) error {
	tx, err := s.deviceTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
		return err
	}
	if err := revokeDevices(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RevokeSession(ctx context.Context, hash [32]byte) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash = ?", hash[:])
	return err
}

func normalizeLabel(label string) string {
	value := strings.TrimSpace(label)
	if !utf8.ValidString(value) || len([]rune(value)) > 80 {
		return ""
	}
	return value
}

func newSessionToken() (string, [32]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", [32]byte{}, fmt.Errorf("generate session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), sha256.Sum256(raw), nil
}

func requireAffected(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrNotFound
	}
	return nil
}
