package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
