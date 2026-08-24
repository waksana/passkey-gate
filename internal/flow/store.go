package flow

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	ErrMissing = errors.New("flow is missing or already consumed")
	ErrExpired = errors.New("flow has expired")
	ErrBound   = errors.New("flow binding does not match")
	ErrFull    = errors.New("too many active flows")
)

type Kind string

const (
	Login        Kind = "login"
	Fresh        Kind = "fresh"
	Registration Kind = "registration"
	Bootstrap    Kind = "bootstrap"
)

type Flow struct {
	Kind          Kind
	Host          string
	ReturnPath    string
	Label         string
	Session       webauthn.SessionData
	SessionHash   [32]byte
	BootstrapHash [32]byte
	ExpiresAt     time.Time
}

type Store struct {
	mu      sync.Mutex
	entries map[[32]byte]Flow
	limit   int
	now     func() time.Time
}

func New(limit int) *Store {
	return &Store{
		entries: make(map[[32]byte]Flow),
		limit:   limit,
		now:     time.Now,
	}
}

func (s *Store) Create(value Flow) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	key := sha256.Sum256(tokenBytes)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	if len(s.entries) >= s.limit {
		return "", ErrFull
	}
	s.entries[key] = value
	return token, nil
}

func (s *Store) Consume(token, host string, kinds ...Kind) (Flow, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return Flow{}, ErrMissing
	}
	key := sha256.Sum256(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.entries[key]
	delete(s.entries, key)
	if !ok {
		return Flow{}, ErrMissing
	}
	if !value.ExpiresAt.After(s.now()) {
		return Flow{}, ErrExpired
	}
	kindAllowed := false
	for _, kind := range kinds {
		if value.Kind == kind {
			kindAllowed = true
			break
		}
	}
	if value.Host != host || !kindAllowed {
		return Flow{}, ErrBound
	}
	return value, nil
}

func (s *Store) cleanupLocked() {
	now := s.now()
	for key, value := range s.entries {
		if !value.ExpiresAt.After(now) {
			delete(s.entries, key)
		}
	}
}
