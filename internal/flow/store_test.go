package flow

import (
	"errors"
	"testing"
	"time"
)

func TestFlowIsBoundAndConsumedOnce(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := New(4)
	store.now = func() time.Time { return now }
	token, err := store.Create(Flow{
		Kind:      Login,
		Host:      "app.example.com",
		ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(token, "other.example.com", Login); !errors.Is(err, ErrBound) {
		t.Fatalf("expected binding error, got %v", err)
	}
	if _, err := store.Consume(token, "app.example.com", Login); !errors.Is(err, ErrMissing) {
		t.Fatalf("wrong-host attempt must consume flow, got %v", err)
	}
}

func TestExpiredFlowIsRejected(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := New(4)
	store.now = func() time.Time { return now }
	token, err := store.Create(Flow{Kind: Login, Host: "a.example.com", ExpiresAt: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if _, err := store.Consume(token, "a.example.com", Login); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expired flow, got %v", err)
	}
}
