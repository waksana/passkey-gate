package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	DeviceClient      = "cockpit-dashboard"
	DeviceScope       = "host-access"
	DeviceLifetime    = 300
	DeviceInterval    = 5
	AccessLifetime    = 900
	FamilyLifetime    = 30 * 24 * 60 * 60
	maxDeviceGrants   = 1024
	maxDeviceFamilies = 1024
	maxFamilyTokens   = 4096
)

type OAuthError string

func (e OAuthError) Error() string { return string(e) }

const (
	InvalidGrant OAuthError = "invalid_grant"
	Pending      OAuthError = "authorization_pending"
	SlowDown     OAuthError = "slow_down"
	Denied       OAuthError = "access_denied"
	Expired      OAuthError = "expired_token"
	Unavailable  OAuthError = "temporarily_unavailable"
)

type DeviceAuthorization struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
	ExpiresIn  int    `json:"expires_in"`
	Interval   int    `json:"interval"`
}

type DeviceTokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

type DeviceFamily struct {
	ID        int64
	Host      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (s *Store) initializeDevices(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS device_grants (
 device_hash BLOB PRIMARY KEY CHECK(length(device_hash)=32),
 user_hash BLOB NOT NULL UNIQUE CHECK(length(user_hash)=32),
 host TEXT NOT NULL, client TEXT NOT NULL, scope TEXT NOT NULL,
 expires_at INTEGER NOT NULL, poll_at INTEGER NOT NULL,
 interval INTEGER NOT NULL, state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS device_families (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 host TEXT NOT NULL, client TEXT NOT NULL, scope TEXT NOT NULL,
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS device_tokens (
 token_hash BLOB PRIMARY KEY CHECK(length(token_hash)=32),
 family_id INTEGER NOT NULL REFERENCES device_families(id) ON DELETE CASCADE,
 kind TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS device_tokens_family ON device_tokens(family_id);
CREATE TABLE IF NOT EXISTS device_rates (
 action TEXT PRIMARY KEY, resets_at INTEGER NOT NULL, count INTEGER NOT NULL
);`)
	return err
}

// Acquire the SQLite writer before reading state, including across Store handles.
func (s *Store) deviceTx(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE schema_version SET version = version"); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func (s *Store) cleanDevices(ctx context.Context, tx *sql.Tx) error {
	now := s.now().Unix()
	for _, q := range []struct {
		sql string
		at  int64
	}{
		{"DELETE FROM device_grants WHERE expires_at <= ?", now - 86400},
		{"DELETE FROM device_families WHERE expires_at <= ?", now},
		{"DELETE FROM device_tokens WHERE kind = 'access' AND expires_at <= ?", now},
	} {
		if _, err := tx.ExecContext(ctx, q.sql, q.at); err != nil {
			return err
		}
	}
	return nil
}

// Fixed, server-selected actions keep the rate table bounded. Limits survive restart.
func (s *Store) DeviceRate(ctx context.Context, action string, maximum int) (bool, error) {
	tx, err := s.deviceTx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	now := s.now().Unix()
	var count int
	err = tx.QueryRowContext(ctx, `
INSERT INTO device_rates(action, resets_at, count) VALUES(?, ?, 1)
ON CONFLICT(action) DO UPDATE SET
 count = CASE WHEN resets_at <= ? THEN 1 ELSE min(count + 1, ?) END,
 resets_at = CASE WHEN resets_at <= ? THEN excluded.resets_at ELSE resets_at END
RETURNING count`, action, now+60, now, maximum+1, now).Scan(&count)
	if err != nil {
		return false, err
	}
	return count <= maximum, tx.Commit()
}

func deviceHash(token string) ([32]byte, bool) {
	if len(token) != 43 {
		return [32]byte{}, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != 32 {
		return [32]byte{}, false
	}
	return sha256.Sum256(raw), true
}

const userAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func NormalizeUserCode(code string) (string, bool) {
	if len(code) > 16 {
		return "", false
	}
	code = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	if len(code) != 8 {
		return "", false
	}
	for _, ch := range code {
		if !strings.ContainsRune(userAlphabet, ch) {
			return "", false
		}
	}
	return code[:4] + "-" + code[4:], true
}

func newUserCode() (string, error) {
	var raw [8]byte
	// Rejection sampling avoids alphabet bias.
	for i := range raw {
		for {
			var b [1]byte
			if _, err := rand.Read(b[:]); err != nil {
				return "", err
			}
			if int(b[0]) < 256-256%len(userAlphabet) {
				raw[i] = userAlphabet[int(b[0])%len(userAlphabet)]
				break
			}
		}
	}
	return string(raw[:4]) + "-" + string(raw[4:]), nil
}

func (s *Store) CreateDevice(ctx context.Context, host string) (DeviceAuthorization, error) {
	code, hash, err := newSessionToken()
	if err != nil {
		return DeviceAuthorization{}, err
	}
	user, err := newUserCode()
	if err != nil {
		return DeviceAuthorization{}, err
	}
	userHash := sha256.Sum256([]byte(user))
	tx, err := s.deviceTx(ctx)
	if err != nil {
		return DeviceAuthorization{}, err
	}
	defer tx.Rollback()
	if err := s.cleanDevices(ctx, tx); err != nil {
		return DeviceAuthorization{}, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM device_grants").Scan(&count); err != nil {
		return DeviceAuthorization{}, err
	}
	if count >= maxDeviceGrants {
		// Expired tombstones are best-effort; they must not block live authorization.
		if _, err := tx.ExecContext(ctx, "DELETE FROM device_grants WHERE expires_at <= ?", s.now().Unix()); err != nil {
			return DeviceAuthorization{}, err
		}
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM device_grants").Scan(&count); err != nil {
			return DeviceAuthorization{}, err
		}
		if count >= maxDeviceGrants {
			return DeviceAuthorization{}, Unavailable
		}
	}
	now := s.now().Unix()
	_, err = tx.ExecContext(ctx, `INSERT INTO device_grants
(device_hash,user_hash,host,client,scope,expires_at,poll_at,interval,state)
VALUES(?,?,?,?,?,?,?,?, 'pending')`, hash[:], userHash[:], host, DeviceClient, DeviceScope,
		now+DeviceLifetime, now+DeviceInterval, DeviceInterval)
	if err != nil {
		return DeviceAuthorization{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeviceAuthorization{}, err
	}
	return DeviceAuthorization{code, user, DeviceLifetime, DeviceInterval}, nil
}

func (s *Store) DeviceHost(ctx context.Context, code string) (string, error) {
	code, ok := NormalizeUserCode(code)
	if !ok {
		return "", InvalidGrant
	}
	hash := sha256.Sum256([]byte(code))
	var host string
	err := s.db.QueryRowContext(ctx, `SELECT host FROM device_grants
WHERE user_hash=? AND state='pending' AND expires_at>?`, hash[:], s.now().Unix()).Scan(&host)
	if errors.Is(err, sql.ErrNoRows) {
		return "", InvalidGrant
	}
	return host, err
}

// Approval always supplies a freshly verified credential, not just a fresh cookie.
func (s *Store) DecideDevice(ctx context.Context, code string, session Session, credential *webauthn.Credential) error {
	code, ok := NormalizeUserCode(code)
	if !ok {
		return InvalidGrant
	}
	hash := sha256.Sum256([]byte(code))
	tx, err := s.deviceTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now().Unix()
	var one int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM sessions WHERE token_hash=? AND host=? AND expires_at>?`,
		session.TokenHash[:], session.Host, now).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnauthorized
	}
	if err != nil {
		return err
	}
	state := "denied"
	if credential != nil {
		data, err := credential.MarshalMsg(nil)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE credentials SET credential_data=?, last_used_at=? WHERE credential_id=?`,
			data, now, credential.ID)
		if err != nil {
			return err
		}
		if err := requireAffected(result); err != nil {
			return ErrUnauthorized
		}
		state = "approved"
	}
	result, err := tx.ExecContext(ctx, `UPDATE device_grants SET state=?
WHERE user_hash=? AND state='pending' AND expires_at>?`, state, hash[:], now)
	if err != nil {
		return err
	}
	if err := requireAffected(result); err != nil {
		return InvalidGrant
	}
	return tx.Commit()
}

func (s *Store) PollDevice(ctx context.Context, code, host string) (DeviceTokens, error) {
	hash, ok := deviceHash(code)
	if !ok {
		return DeviceTokens{}, InvalidGrant
	}
	tx, err := s.deviceTx(ctx)
	if err != nil {
		return DeviceTokens{}, err
	}
	defer tx.Rollback()
	var state string
	var expires, poll, interval int64
	err = tx.QueryRowContext(ctx, `SELECT state,expires_at,poll_at,interval FROM device_grants
WHERE device_hash=? AND host=? AND client=? AND scope=?`, hash[:], host, DeviceClient, DeviceScope).
		Scan(&state, &expires, &poll, &interval)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceTokens{}, InvalidGrant
	}
	if err != nil {
		return DeviceTokens{}, err
	}
	now := s.now().Unix()
	if state == "consumed" {
		return DeviceTokens{}, InvalidGrant
	}
	if expires <= now {
		return DeviceTokens{}, Expired
	}
	if state == "denied" {
		return DeviceTokens{}, Denied
	}
	pollError := Pending
	if poll > now {
		interval += 5
		pollError = SlowDown
	}
	if _, err := tx.ExecContext(ctx, `UPDATE device_grants SET poll_at=?,interval=? WHERE device_hash=?`,
		now+interval, interval, hash[:]); err != nil {
		return DeviceTokens{}, err
	}
	if pollError == SlowDown || state == "pending" {
		if err := tx.Commit(); err != nil {
			return DeviceTokens{}, err
		}
		return DeviceTokens{}, pollError
	}
	if err := s.cleanDevices(ctx, tx); err != nil {
		return DeviceTokens{}, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM device_families").Scan(&count); err != nil {
		return DeviceTokens{}, err
	}
	if count >= maxDeviceFamilies {
		return DeviceTokens{}, Unavailable
	}
	var family int64
	err = tx.QueryRowContext(ctx, `INSERT INTO device_families(host,client,scope,created_at,expires_at)
VALUES(?,?,?,?,?) RETURNING id`, host, DeviceClient, DeviceScope, now, now+FamilyLifetime).Scan(&family)
	if err != nil {
		return DeviceTokens{}, err
	}
	tokens, err := s.issueDeviceTokens(ctx, tx, family, now+FamilyLifetime)
	if err != nil {
		return DeviceTokens{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE device_grants SET state='consumed' WHERE device_hash=?`, hash[:]); err != nil {
		return DeviceTokens{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeviceTokens{}, err
	}
	return tokens, nil
}

func (s *Store) issueDeviceTokens(ctx context.Context, tx *sql.Tx, family, expires int64) (DeviceTokens, error) {
	access, ah, err := newSessionToken()
	if err != nil {
		return DeviceTokens{}, err
	}
	refresh, rh, err := newSessionToken()
	if err != nil {
		return DeviceTokens{}, err
	}
	accessExpiry := min(expires, s.now().Unix()+AccessLifetime)
	_, err = tx.ExecContext(ctx, `INSERT INTO device_tokens(token_hash,family_id,kind,expires_at)
VALUES(?,?,'access',?),(?,?,'refresh',?)`, ah[:], family, accessExpiry, rh[:], family, expires)
	if err != nil {
		return DeviceTokens{}, err
	}
	return DeviceTokens{access, "Bearer", accessExpiry - s.now().Unix(), refresh, DeviceScope}, nil
}

func (s *Store) RefreshDevice(ctx context.Context, token, host string) (DeviceTokens, error) {
	hash, ok := deviceHash(token)
	if !ok {
		return DeviceTokens{}, InvalidGrant
	}
	tx, err := s.deviceTx(ctx)
	if err != nil {
		return DeviceTokens{}, err
	}
	defer tx.Rollback()
	var family, expires int64
	var used int
	err = tx.QueryRowContext(ctx, `SELECT f.id,f.expires_at,t.used FROM device_tokens t
JOIN device_families f ON f.id=t.family_id
WHERE t.token_hash=? AND t.kind='refresh' AND f.host=? AND f.client=? AND f.scope=?
AND f.revoked=0 AND f.expires_at>?`, hash[:], host, DeviceClient, DeviceScope, s.now().Unix()).
		Scan(&family, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceTokens{}, InvalidGrant
	}
	if err != nil {
		return DeviceTokens{}, err
	}
	if used != 0 {
		if _, err := tx.ExecContext(ctx, "UPDATE device_families SET revoked=1 WHERE id=?", family); err != nil {
			return DeviceTokens{}, err
		}
		if err := tx.Commit(); err != nil {
			return DeviceTokens{}, err
		}
		return DeviceTokens{}, InvalidGrant
	}
	if err := s.cleanDevices(ctx, tx); err != nil {
		return DeviceTokens{}, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM device_tokens WHERE family_id=?", family).Scan(&count); err != nil {
		return DeviceTokens{}, err
	}
	if count+2 > maxFamilyTokens {
		return DeviceTokens{}, Unavailable
	}
	if _, err := tx.ExecContext(ctx, "UPDATE device_tokens SET used=1 WHERE token_hash=?", hash[:]); err != nil {
		return DeviceTokens{}, err
	}
	tokens, err := s.issueDeviceTokens(ctx, tx, family, expires)
	if err != nil {
		return DeviceTokens{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeviceTokens{}, err
	}
	return tokens, nil
}

func (s *Store) CheckDevice(ctx context.Context, token, host string) error {
	hash, ok := deviceHash(token)
	if !ok {
		return ErrUnauthorized
	}
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM device_tokens t JOIN device_families f ON f.id=t.family_id
WHERE t.token_hash=? AND t.kind='access' AND t.expires_at>? AND f.expires_at>?
AND f.host=? AND f.client=? AND f.scope=? AND f.revoked=0`,
		hash[:], s.now().Unix(), s.now().Unix(), host, DeviceClient, DeviceScope).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnauthorized
	}
	return err
}

func (s *Store) RevokeDeviceToken(ctx context.Context, token, host string) error {
	hash, ok := deviceHash(token)
	if !ok {
		return nil
	} // RFC 7009: unknown tokens also succeed.
	_, err := s.db.ExecContext(ctx, `UPDATE device_families SET revoked=1 WHERE host=? AND client=?
AND id IN (SELECT family_id FROM device_tokens WHERE token_hash=?)`, host, DeviceClient, hash[:])
	return err
}

func (s *Store) ListDevices(ctx context.Context) ([]DeviceFamily, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,host,created_at,expires_at FROM device_families
WHERE revoked=0 AND expires_at>? ORDER BY id DESC`, s.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []DeviceFamily{}
	for rows.Next() {
		var f DeviceFamily
		var created, expires int64
		if err := rows.Scan(&f.ID, &f.Host, &created, &expires); err != nil {
			return nil, err
		}
		f.CreatedAt, f.ExpiresAt = time.Unix(created, 0).UTC(), time.Unix(expires, 0).UTC()
		result = append(result, f)
	}
	return result, rows.Err()
}

func (s *Store) RevokeDevice(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, "UPDATE device_families SET revoked=1 WHERE id=?", id)
	if err != nil {
		return err
	}
	return requireAffected(result)
}

func revokeDevices(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, "UPDATE device_families SET revoked=1"); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "UPDATE device_grants SET state='denied' WHERE state IN ('pending','approved')")
	return err
}
