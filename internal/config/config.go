package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	value, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", node.Value, err)
	}
	d.Duration = value
	return nil
}

type Config struct {
	Listen            string              `yaml:"listen"`
	RPID              string              `yaml:"rp_id"`
	RPName            string              `yaml:"rp_name"`
	ManagementOrigin  string              `yaml:"management_origin"`
	SessionDuration   Duration            `yaml:"session_duration"`
	ChallengeDuration Duration            `yaml:"challenge_duration"`
	FreshAuthDuration Duration            `yaml:"fresh_auth_duration"`
	BootstrapDuration Duration            `yaml:"bootstrap_duration"`
	AllowedOrigins    []string            `yaml:"allowed_origins"`
	AllowedHosts      []string            `yaml:"allowed_hosts"`
	AndroidOrigins    map[string][]string `yaml:"android_origins"`
	Database          string              `yaml:"database"`
	TestMode          bool                `yaml:"test_mode"`

	managementHost string
	originsByHost  map[string][]string
	hostSet        map[string]struct{}
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}

	var cfg Config
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	if c.Listen == "" || c.RPID == "" || c.RPName == "" || c.ManagementOrigin == "" || c.Database == "" {
		return errors.New("listen, rp_id, rp_name, management_origin, and database are required")
	}

	listenHost, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen must include a valid IP and port: %w", err)
	}
	listenIP := net.ParseIP(listenHost)
	if listenIP == nil {
		return errors.New("listen host must be an IP address")
	}
	if !c.TestMode && !listenIP.IsLoopback() {
		return errors.New("listen must be loopback unless test_mode is enabled")
	}

	c.RPID = strings.ToLower(strings.TrimSuffix(c.RPID, "."))
	if strings.ContainsAny(c.RPID, "*:/") || net.ParseIP(c.RPID) != nil {
		return errors.New("rp_id must be a DNS domain without wildcards, scheme, or port")
	}
	if len(c.AllowedHosts) == 0 || len(c.AllowedOrigins) == 0 {
		return errors.New("allowed_hosts and allowed_origins must not be empty")
	}

	c.hostSet = make(map[string]struct{}, len(c.AllowedHosts))
	for i, raw := range c.AllowedHosts {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if host == "" || strings.ContainsAny(host, "*:/\\") || net.ParseIP(host) != nil {
			return fmt.Errorf("allowed_hosts[%d] must be an exact DNS host", i)
		}
		if host != c.RPID && !strings.HasSuffix(host, "."+c.RPID) {
			return fmt.Errorf("allowed host %q is not within RP ID %q", host, c.RPID)
		}
		if _, exists := c.hostSet[host]; exists {
			return fmt.Errorf("duplicate allowed host %q", host)
		}
		c.hostSet[host] = struct{}{}
		c.AllowedHosts[i] = host
	}
	slices.Sort(c.AllowedHosts)

	c.originsByHost = make(map[string][]string, len(c.AllowedOrigins))
	seenOrigins := make(map[string]struct{}, len(c.AllowedOrigins))
	for i, origin := range c.AllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil {
			return fmt.Errorf("allowed_origins[%d]: %w", i, err)
		}
		if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
			(u.Path != "" && u.Path != "/") || u.Port() != "" {
			return fmt.Errorf("allowed origin %q must be an exact default-port HTTPS origin", origin)
		}
		host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		canonical := "https://" + host
		if origin != canonical {
			return fmt.Errorf("allowed origin %q is not canonical; use %q", origin, canonical)
		}
		if _, ok := c.hostSet[host]; !ok {
			return fmt.Errorf("allowed origin host %q is not in allowed_hosts", host)
		}
		if _, exists := seenOrigins[origin]; exists {
			return fmt.Errorf("duplicate allowed origin %q", origin)
		}
		seenOrigins[origin] = struct{}{}
		c.originsByHost[host] = append(c.originsByHost[host], origin)
	}
	for _, host := range c.AllowedHosts {
		if len(c.originsByHost[host]) == 0 {
			return fmt.Errorf("allowed host %q has no matching origin", host)
		}
	}
	slices.Sort(c.AllowedOrigins)

	for host, origins := range c.AndroidOrigins {
		if !c.HostAllowed(host) {
			return fmt.Errorf("android_origins host %q must exactly match an allowed host", host)
		}
		if len(origins) == 0 {
			return fmt.Errorf("android_origins for %q must not be empty", host)
		}
		seen := make(map[string]struct{}, len(origins))
		for _, origin := range origins {
			const prefix = "android:apk-key-hash:"
			digest := strings.TrimPrefix(origin, prefix)
			raw, err := base64.RawURLEncoding.Strict().DecodeString(digest)
			if !strings.HasPrefix(origin, prefix) || err != nil || len(raw) != 32 ||
				base64.RawURLEncoding.EncodeToString(raw) != digest {
				return fmt.Errorf("android origin for %q must be android:apk-key-hash: followed by a canonical unpadded base64url SHA-256 digest", host)
			}
			if _, exists := seen[origin]; exists {
				return fmt.Errorf("duplicate android origin for %q", host)
			}
			seen[origin] = struct{}{}
		}
	}

	managementURL, err := url.Parse(c.ManagementOrigin)
	if err != nil {
		return fmt.Errorf("management_origin: %w", err)
	}
	c.managementHost = strings.ToLower(managementURL.Hostname())
	if c.ManagementOrigin != "https://"+c.managementHost || !slices.Contains(c.AllowedOrigins, c.ManagementOrigin) {
		return errors.New("management_origin must exactly match an allowed HTTPS origin")
	}

	if !filepath.IsAbs(c.Database) {
		return errors.New("database path must be absolute")
	}
	if err := validateDuration("session_duration", c.SessionDuration.Duration, time.Minute, 30*24*time.Hour); err != nil {
		return err
	}
	if err := validateDuration("challenge_duration", c.ChallengeDuration.Duration, 30*time.Second, 5*time.Minute); err != nil {
		return err
	}
	if err := validateDuration("fresh_auth_duration", c.FreshAuthDuration.Duration, 30*time.Second, 5*time.Minute); err != nil {
		return err
	}
	if err := validateDuration("bootstrap_duration", c.BootstrapDuration.Duration, time.Minute, 10*time.Minute); err != nil {
		return err
	}
	return nil
}

func validateDuration(name string, value, minimum, maximum time.Duration) error {
	if value < minimum || value > maximum {
		return fmt.Errorf("%s must be between %s and %s", name, minimum, maximum)
	}
	return nil
}

func (c Config) HostAllowed(host string) bool {
	_, ok := c.hostSet[host]
	return ok
}

func (c Config) OriginsForHost(host string) []string {
	return slices.Clone(c.originsByHost[host])
}

func (c Config) LoginOriginsForHost(host string) []string {
	return append(c.OriginsForHost(host), c.AndroidOrigins[host]...)
}

func (c Config) ManagementHost() string {
	return c.managementHost
}
