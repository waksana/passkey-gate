package config

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAndroidOriginsAreOptInHostBoundAndLoginOnly(t *testing.T) {
	cfg := validConfig(t)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.LoginOriginsForHost("app.example.com"); len(got) != 1 {
		t.Fatal(got)
	}
	origin := "android:apk-key-hash:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	cfg.AndroidOrigins = map[string][]string{"app.example.com": {origin}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.LoginOriginsForHost("app.example.com"); len(got) != 2 || got[1] != origin {
		t.Fatal(got)
	}
	if got := cfg.LoginOriginsForHost("auth.example.com"); len(got) != 1 {
		t.Fatal(got)
	}
	if got := cfg.OriginsForHost("app.example.com"); len(got) != 1 {
		t.Fatal(got)
	}
	copy := cfg.LoginOriginsForHost("app.example.com")
	copy[0] = "changed"
	if cfg.OriginsForHost("app.example.com")[0] != "https://app.example.com" {
		t.Fatal("mutated config")
	}
}

func TestAndroidOriginsRejectMalformedConfiguration(t *testing.T) {
	good := "android:apk-key-hash:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for name, origins := range map[string]map[string][]string{
		"unknown host":      {"other.example.com": {good}},
		"wildcard":          {"*.example.com": {good}},
		"noncanonical host": {"APP.example.com": {good}},
		"empty":             {"app.example.com": {}},
		"duplicate":         {"app.example.com": {good, good}},
		"web":               {"app.example.com": {"https://app.example.com"}},
		"padded":            {"app.example.com": {good + "="}},
		"newline":           {"app.example.com": {good + "\n"}},
		"short":             {"app.example.com": {"android:apk-key-hash:AA"}},
		"hex":               {"app.example.com": {"android:apk-key-hash:" + strings.Repeat("a", 64)}},
		"noncanonical bits": {"app.example.com": {good[:len(good)-1] + "B"}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.AndroidOrigins = origins
			if err := cfg.Validate(); err == nil {
				t.Fatal("accepted unsafe Android origin configuration")
			}
		})
	}
}

func validConfig(t *testing.T) Config {
	t.Helper()
	cfg := Config{
		Listen:            "127.0.0.1:8081",
		RPID:              "example.com",
		RPName:            "Personal Services",
		ManagementOrigin:  "https://auth.example.com",
		SessionDuration:   Duration{Duration: 36 * time.Hour},
		ChallengeDuration: Duration{Duration: 5 * time.Minute},
		FreshAuthDuration: Duration{Duration: 5 * time.Minute},
		BootstrapDuration: Duration{Duration: 10 * time.Minute},
		AllowedOrigins: []string{
			"https://auth.example.com",
			"https://app.example.com",
		},
		AllowedHosts: []string{
			"auth.example.com",
			"app.example.com",
		},
		Database: filepath.Join(t.TempDir(), "gate.sqlite3"),
	}
	return cfg
}

func TestValidateAcceptsExactConfiguration(t *testing.T) {
	cfg := validConfig(t)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if !cfg.HostAllowed("app.example.com") {
		t.Fatal("expected exact host to be allowed")
	}
	if cfg.HostAllowed("evil.app.example.com") {
		t.Fatal("unexpected suffix host match")
	}
	origins := cfg.OriginsForHost("app.example.com")
	if len(origins) != 1 || origins[0] != "https://app.example.com" {
		t.Fatalf("unexpected host origins: %v", origins)
	}
}

func TestValidateRejectsUnsafeValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		match  string
	}{
		{"public listener", func(c *Config) { c.Listen = "0.0.0.0:8081" }, "loopback"},
		{"wildcard host", func(c *Config) { c.AllowedHosts[0] = "*.example.com" }, "exact DNS host"},
		{"suffix host", func(c *Config) { c.AllowedHosts[0] = "notexample.com" }, "not within RP ID"},
		{"HTTP origin", func(c *Config) { c.AllowedOrigins[0] = "http://auth.example.com" }, "HTTPS"},
		{"origin path", func(c *Config) { c.AllowedOrigins[0] = "https://auth.example.com/path" }, "HTTPS origin"},
		{"origin wildcard", func(c *Config) { c.AllowedOrigins[0] = "https://*.example.com" }, "not in allowed_hosts"},
		{"origin port", func(c *Config) { c.AllowedOrigins[0] = "https://auth.example.com:8443" }, "default-port"},
		{"relative database", func(c *Config) { c.Database = "gate.sqlite3" }, "absolute"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig(t)
			test.mutate(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("expected error containing %q, got %v", test.match, err)
			}
		})
	}
}
