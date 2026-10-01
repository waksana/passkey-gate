package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func deviceOwner(t *testing.T, s *Store) Session {
	t.Helper()
	ctx := context.Background()
	if err := s.AddCredential(ctx, credential(1), "Synthetic", nil); err != nil {
		t.Fatal(err)
	}
	_, session, err := s.CreateSession(ctx, "auth.example.com", credential(1), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func approvedDevice(t *testing.T, s *Store, session Session) DeviceAuthorization {
	t.Helper()
	d, err := s.CreateDevice(context.Background(), "app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	c := credential(1)
	if err := s.DecideDevice(context.Background(), d.UserCode, session, &c); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDevicePollingStateAndCleanup(t *testing.T) {
	s := testStore(t)
	now := time.Unix(1700000000, 0)
	s.now = func() time.Time { return now }
	ctx := context.Background()
	session := deviceOwner(t, s)
	d, err := s.CreateDevice(ctx, "app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.DeviceCode) != 43 || len(d.UserCode) != 9 || d.Interval != 5 || d.ExpiresIn != 300 {
		t.Fatalf("wrong contract: %+v", d)
	}
	// Polling too soon permanently increases the interval, even while pending.
	if _, err := s.PollDevice(ctx, d.DeviceCode, "app.example.com"); err != SlowDown {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Second)
	if _, err := s.PollDevice(ctx, d.DeviceCode, "app.example.com"); err != Pending {
		t.Fatal(err)
	}
	now = now.Add(5 * time.Second)
	if _, err := s.PollDevice(ctx, d.DeviceCode, "app.example.com"); err != SlowDown {
		t.Fatal(err)
	}
	var interval int
	if err := s.db.QueryRow("SELECT interval FROM device_grants").Scan(&interval); err != nil || interval != 15 {
		t.Fatalf("interval=%d err=%v", interval, err)
	}
	if _, err := s.PollDevice(ctx, d.DeviceCode, "other.example.com"); err != InvalidGrant {
		t.Fatal(err)
	}
	if err := s.DecideDevice(ctx, d.UserCode, session, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PollDevice(ctx, d.DeviceCode, "app.example.com"); err != Denied {
		t.Fatal(err)
	}
	c := credential(1)
	if err := s.DecideDevice(ctx, d.UserCode, session, &c); err != InvalidGrant {
		t.Fatal(err)
	}
	now = now.Add(300 * time.Second)
	if _, err := s.PollDevice(ctx, d.DeviceCode, "app.example.com"); err != Expired {
		t.Fatal(err)
	}
	if _, err := s.DeviceHost(ctx, d.UserCode); err != InvalidGrant {
		t.Fatal(err)
	}
	now = now.Add(24 * time.Hour)
	if _, err := s.CreateDevice(ctx, "app.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PollDevice(ctx, d.DeviceCode, "app.example.com"); err != InvalidGrant {
		t.Fatal(err)
	}
}

func TestDeviceConcurrentConsumptionAndRefreshReplayAcrossConnections(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "devices.sqlite3")
	first, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	now := time.Unix(1700000000, 0)
	first.now = func() time.Time { return now }
	second.now = first.now
	session := deviceOwner(t, first)
	d := approvedDevice(t, first, session)
	now = now.Add(5 * time.Second)
	var wg sync.WaitGroup
	results := make(chan DeviceTokens, 2)
	failures := make(chan error, 2)
	for _, s := range []*Store{first, second} {
		wg.Add(1)
		go func(s *Store) {
			defer wg.Done()
			tokens, err := s.PollDevice(ctx, d.DeviceCode, "app.example.com")
			if err != nil {
				failures <- err
			} else {
				results <- tokens
			}
		}(s)
	}
	wg.Wait()
	if len(results) != 1 || len(failures) != 1 {
		t.Fatal("device code not consumed exactly once")
	}
	if err := <-failures; err != InvalidGrant {
		t.Fatal(err)
	}
	tokens := <-results
	if tokens.ExpiresIn != 900 || tokens.TokenType != "Bearer" || tokens.Scope != DeviceScope {
		t.Fatalf("wrong token contract: %+v", tokens)
	}
	for _, s := range []*Store{first, second} {
		wg.Add(1)
		go func(s *Store) {
			defer wg.Done()
			next, err := s.RefreshDevice(ctx, tokens.RefreshToken, "app.example.com")
			if err != nil {
				failures <- err
			} else {
				results <- next
			}
		}(s)
	}
	wg.Wait()
	if len(results) != 1 || len(failures) != 1 {
		t.Fatal("refresh not consumed exactly once")
	}
	if err := <-failures; err != InvalidGrant {
		t.Fatal(err)
	}
	next := <-results
	for _, access := range []string{tokens.AccessToken, next.AccessToken} {
		if err := first.CheckDevice(ctx, access, "app.example.com"); err != ErrUnauthorized {
			t.Fatalf("refresh replay did not revoke family: %v", err)
		}
	}
	if _, err := first.RefreshDevice(ctx, next.RefreshToken, "app.example.com"); err != InvalidGrant {
		t.Fatal(err)
	}
}

func TestDeviceExpiryIsolationRevocationAndHashes(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Unix(1700000000, 0)
	s.now = func() time.Time { return now }
	session := deviceOwner(t, s)
	d := approvedDevice(t, s, session)
	now = now.Add(5 * time.Second)
	tokens, err := s.PollDevice(ctx, d.DeviceCode, "app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	families, err := s.ListDevices(ctx)
	if err != nil || len(families) != 1 {
		t.Fatalf("families=%v err=%v", families, err)
	}
	expires := families[0].ExpiresAt
	for _, value := range []string{tokens.AccessToken, tokens.RefreshToken} {
		hash, valid := deviceHash(value)
		if !valid {
			t.Fatal("bad token encoding")
		}
		var length int
		if err := s.db.QueryRow("SELECT length(token_hash) FROM device_tokens WHERE token_hash=?", hash[:]).Scan(&length); err != nil || length != 32 {
			t.Fatalf("token not hashed: %d %v", length, err)
		}
	}
	userHash := sha256.Sum256([]byte(d.UserCode))
	var hashLength int
	if err := s.db.QueryRow("SELECT length(device_hash) FROM device_grants WHERE user_hash=?", userHash[:]).Scan(&hashLength); err != nil || hashLength != 32 {
		t.Fatal("codes not independently hashed", err)
	}
	if err := s.CheckDevice(ctx, tokens.RefreshToken, "app.example.com"); err != ErrUnauthorized {
		t.Fatal(err)
	}
	if err := s.CheckDevice(ctx, tokens.AccessToken, "auth.example.com"); err != ErrUnauthorized {
		t.Fatal(err)
	}
	if _, err := s.RefreshDevice(ctx, tokens.RefreshToken, "auth.example.com"); err != InvalidGrant {
		t.Fatal(err)
	}
	if err := s.RevokeDeviceToken(ctx, tokens.RefreshToken, "other.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckDevice(ctx, tokens.AccessToken, "app.example.com"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(900 * time.Second)
	if err := s.CheckDevice(ctx, tokens.AccessToken, "app.example.com"); err != ErrUnauthorized {
		t.Fatal(err)
	}
	next, err := s.RefreshDevice(ctx, tokens.RefreshToken, "app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	families, err = s.ListDevices(ctx)
	if err != nil || !families[0].ExpiresAt.Equal(expires) {
		t.Fatal("refresh extended family", err)
	}
	now = expires.Add(-10 * time.Second)
	last, err := s.RefreshDevice(ctx, next.RefreshToken, "app.example.com")
	if err != nil || last.ExpiresIn != 10 {
		t.Fatalf("last=%+v err=%v", last, err)
	}
	now = expires
	if _, err := s.RefreshDevice(ctx, last.RefreshToken, "app.example.com"); err != InvalidGrant {
		t.Fatal(err)
	}
	if err := s.CheckDevice(ctx, last.AccessToken, "app.example.com"); err != ErrUnauthorized {
		t.Fatal(err)
	}
}

func TestDeviceDurabilityAndRateLimits(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "device.sqlite3")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	s.now = func() time.Time { return now }
	session := deviceOwner(t, s)
	d := approvedDevice(t, s, session)
	for i := 0; i < 3; i++ {
		ok, err := s.DeviceRate(ctx, "create", 2)
		if err != nil || ok != (i < 2) {
			t.Fatalf("rate %d %v %v", i, ok, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.now = func() time.Time { return now }
	if ok, err := s.DeviceRate(ctx, "create", 2); err != nil || ok {
		t.Fatal("rate lost after restart", err)
	}
	now = now.Add(60 * time.Second)
	if ok, err := s.DeviceRate(ctx, "create", 2); err != nil || !ok {
		t.Fatal("rate not reset", err)
	}
	tokens, err := s.PollDevice(ctx, d.DeviceCode, "app.example.com")
	if err != nil {
		t.Fatal("grant lost after restart", err)
	}
	if err := s.RevokeDeviceToken(ctx, tokens.RefreshToken, "app.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckDevice(ctx, tokens.AccessToken, "app.example.com"); err != ErrUnauthorized {
		t.Fatal(err)
	}
	if err := s.RevokeDeviceToken(ctx, strings.Repeat("?", 10000), "app.example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceApprovalAndGlobalRevocation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Unix(1700000000, 0)
	s.now = func() time.Time { return now }
	session := deviceOwner(t, s)
	d := approvedDevice(t, s, session)
	pending, err := s.CreateDevice(ctx, "app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(5 * time.Second)
	tokens, err := s.PollDevice(ctx, d.DeviceCode, "app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAllSessions(ctx); err != nil {
		t.Fatal(err)
	}
	c := credential(1)
	if err := s.DecideDevice(ctx, pending.UserCode, session, &c); !errors.Is(err, ErrUnauthorized) {
		t.Fatal(err)
	}
	if err := s.CheckDevice(ctx, tokens.AccessToken, "app.example.com"); err != ErrUnauthorized {
		t.Fatal(err)
	}
	if _, err := s.PollDevice(ctx, pending.DeviceCode, "app.example.com"); err != Denied {
		t.Fatal(err)
	}
}

func TestDeviceCapacity(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	_, err := s.db.Exec(`WITH RECURSIVE numbers(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM numbers WHERE n<1024)
INSERT INTO device_grants(device_hash,user_hash,host,client,scope,expires_at,poll_at,interval,state)
SELECT randomblob(32),randomblob(32),'app.example.com','cockpit-dashboard','host-access',?,0,5,'pending' FROM numbers`, time.Now().Unix()+300)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateDevice(ctx, "app.example.com"); err != Unavailable {
		t.Fatal(err)
	}
	// Rate-compliant creation bursts cannot leave a day-long outage after expiry.
	if _, err := s.db.Exec("UPDATE device_grants SET expires_at=?", s.now().Unix()-1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateDevice(ctx, "app.example.com"); err != nil {
		t.Fatal("expired tombstones blocked new authorization", err)
	}
	var count int
	if err := s.db.QueryRow("SELECT count(*) FROM device_grants").Scan(&count); err != nil || count > maxDeviceGrants {
		t.Fatalf("retained capacity unbounded: %d %v", count, err)
	}
}
