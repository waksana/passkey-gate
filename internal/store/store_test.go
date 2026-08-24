package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	value, err := Open(context.Background(), filepath.Join(t.TempDir(), "gate.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = value.Close() })
	return value
}

func credential(id byte) webauthn.Credential {
	return webauthn.Credential{ID: []byte{id}, PublicKey: []byte{1, 2, 3}}
}

func TestDatabasePermissionsAndStableOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "gate.sqlite3")
	first, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	owner1, err := first.Owner(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode is %o", info.Mode().Perm())
	}

	second, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	owner2, err := second.Owner(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(owner1.ID) != string(owner2.ID) || len(owner2.ID) != 32 {
		t.Fatal("owner ID was not stable")
	}
}

func TestSessionIsHostBoundAndExpiresAbsolutely(t *testing.T) {
	database := testStore(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	database.now = func() time.Time { return now }
	if err := database.AddCredential(context.Background(), credential(1), "Primary", nil); err != nil {
		t.Fatal(err)
	}
	token, session, err := database.CreateSession(
		context.Background(), "app.example.com", credential(1), 36*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if session.ExpiresAt.Sub(session.CreatedAt) != 36*time.Hour {
		t.Fatal("session does not have fixed lifetime")
	}
	if _, err := database.Session(context.Background(), token, "other.example.com"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-host session accepted: %v", err)
	}
	now = now.Add(35 * time.Hour)
	if _, err := database.Session(context.Background(), token, "app.example.com"); err != nil {
		t.Fatalf("valid session rejected: %v", err)
	}
	now = now.Add(2 * time.Hour)
	if _, err := database.Session(context.Background(), token, "app.example.com"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired session accepted: %v", err)
	}
}

func TestBootstrapIsSingleUseAndLastCredentialCannotBeDeleted(t *testing.T) {
	database := testStore(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	database.now = func() time.Time { return now }
	token, err := database.IssueBootstrap(context.Background(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	hash, ok := testTokenHash(token)
	if !ok {
		t.Fatal("invalid generated token")
	}
	if err := database.AddCredential(context.Background(), credential(1), "Primary", &hash); err != nil {
		t.Fatal(err)
	}
	if err := database.AddCredential(context.Background(), credential(2), "Backup", &hash); !errors.Is(err, ErrBootstrap) {
		t.Fatalf("bootstrap token was reusable: %v", err)
	}
	credentials, err := database.ListCredentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 1 {
		t.Fatalf("unexpected credentials: %d", len(credentials))
	}
	if err := database.DeleteCredential(context.Background(), credentials[0].ID); !errors.Is(err, ErrLastCredential) {
		t.Fatalf("last credential deletion accepted: %v", err)
	}
}

func TestCredentialDeletionRevokesEverySession(t *testing.T) {
	database := testStore(t)
	if err := database.AddCredential(context.Background(), credential(1), "Primary", nil); err != nil {
		t.Fatal(err)
	}
	if err := database.AddCredential(context.Background(), credential(2), "Backup", nil); err != nil {
		t.Fatal(err)
	}
	token, _, err := database.CreateSession(
		context.Background(), "app.example.com", credential(1), 36*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := database.ListCredentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := database.DeleteCredential(context.Background(), credentials[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Session(context.Background(), token, "app.example.com"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("session survived credential deletion: %v", err)
	}
}

func testTokenHash(token string) ([32]byte, bool) {
	return tokenHashForTest(token)
}
