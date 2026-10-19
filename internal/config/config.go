package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the master configuration for GravityDNS.
type Config struct {
	mu             sync.RWMutex   `yaml:"-"`
	ConfigFilePath string         `yaml:"-"`
	Server         ServerConfig   `yaml:"server"`
	DNS            DNSConfig      `yaml:"dns"`
	SNIProxy       SNIProxyConfig `yaml:"sniproxy"`
	Redis          RedisConfig    `yaml:"redis"`
	Panel          PanelConfig    `yaml:"panel"`
}

// ServerConfig holds global server identity settings.
type ServerConfig struct {
	Domain     string `yaml:"domain"`      // Base domain e.g. "dns.example.com"
	PublicIPv4 string `yaml:"public_ipv4"` // VPS public IPv4 for hijacking
	PublicIPv6 string `yaml:"public_ipv6"` // VPS public IPv6 (optional)
}

// DNSConfig holds settings for DoT and DoH services.
type DNSConfig struct {
	Enabled         bool     `yaml:"enabled"`
	DoTListen       string   `yaml:"dot_listen"`        // e.g. "0.0.0.0:853"
	DoHListen       string   `yaml:"doh_listen"`        // e.g. "0.0.0.0:8443"
	TLSCertFile     string   `yaml:"tls_cert_file"`     // Path to fullchain.pem
	TLSKeyFile      string   `yaml:"tls_key_file"`      // Path to privkey.pem
	UpstreamDNS     []string `yaml:"upstream_dns"`      // Upstream resolvers e.g. ["1.1.1.1:53", "8.8.8.8:53"]
	SpoofTTL        uint32   `yaml:"spoof_ttl"`         // TTL in seconds for spoofed records (default: 60)
	DeviceWindowSec int      `yaml:"device_window_sec"` // Sliding window duration in seconds (default: 600)
}

// SNIProxyConfig holds settings for the transparent SNI router.
type SNIProxyConfig struct {
	Enabled        bool     `yaml:"enabled"`
	Listen         string   `yaml:"listen"`          // e.g. "0.0.0.0:443"
	UpstreamDNS    []string `yaml:"upstream_dns"`    // Independent upstream DNS for origin resolution
	ConnectTimeout int      `yaml:"connect_timeout"` // Seconds (default: 5)
	IdleTimeout    int      `yaml:"idle_timeout"`    // Seconds (default: 300)
	EnforceRules   bool     `yaml:"enforce_rules"`   // Restrict proxying strictly to hijacked rules
}

// RedisConfig holds connection parameters for Redis.
type RedisConfig struct {
	Addr     string `yaml:"addr"`     // e.g. "127.0.0.1:6379"
	Password string `yaml:"password"` // optional password
	DB       int    `yaml:"db"`       // default 0
}

// PanelConfig holds settings for the Admin Web Panel & API.
type PanelConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Listen        string `yaml:"listen"`         // e.g. "0.0.0.0:8080"
	JWTSecret     string `yaml:"jwt_secret"`     // Secret for signing JWT admin tokens
	AdminUsername string `yaml:"admin_username"` // Master admin username
	AdminPassword string `yaml:"admin_password"` // Master admin password (plain or bcrypt)
	SessionTTL    int    `yaml:"session_ttl"`    // Session duration in hours (default: 24)
}

// DefaultConfig provides sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Domain:     "dns.example.com",
			PublicIPv4: "127.0.0.1",
			PublicIPv6: "",
		},
		DNS: DNSConfig{
			Enabled:         true,
			DoTListen:       "0.0.0.0:853",
			DoHListen:       "0.0.0.0:8443",
			TLSCertFile:     "/etc/letsencrypt/live/dns.example.com/fullchain.pem",
			TLSKeyFile:      "/etc/letsencrypt/live/dns.example.com/privkey.pem",
			UpstreamDNS:     []string{"1.1.1.1:53", "8.8.8.8:53"},
			SpoofTTL:        60,
			DeviceWindowSec: 600,
		},
		SNIProxy: SNIProxyConfig{
			Enabled:        true,
			Listen:         "0.0.0.0:443",
			UpstreamDNS:    []string{"1.1.1.1:53", "8.8.8.8:53"},
			ConnectTimeout: 5,
			IdleTimeout:    300,
			EnforceRules:   true,
		},
		Redis: RedisConfig{
			Addr:     "127.0.0.1:6379",
			Password: "",
			DB:       0,
		},
		Panel: PanelConfig{
			Enabled:       true,
			Listen:        "0.0.0.0:8080",
			JWTSecret:     "gravitydns-super-secret-key-change-me",
			AdminUsername: "admin",
			AdminPassword: "adminpassword123",
			SessionTTL:    24,
		},
	}
}

// LoadConfig loads the configuration from file with fallback to default paths and environment overrides.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	// Candidate file paths
	candidates := []string{
		path,
		"configs/gravity.yaml",
		"gravity.yaml",
		"/etc/gravity/gravity.yaml",
	}

	var foundPath string
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			foundPath = p
			break
		}
	}

	if foundPath != "" {
		data, err := os.ReadFile(foundPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", foundPath, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse yaml config %s: %w", foundPath, err)
		}
		cfg.ConfigFilePath = foundPath
	} else if path != "" {
		cfg.ConfigFilePath = path
	} else {
		cfg.ConfigFilePath = "configs/gravity.yaml"
	}

	// Environment variable overrides
	applyEnvOverrides(cfg)

	// Post-process domain
	cfg.Server.Domain = strings.TrimPrefix(strings.TrimSuffix(cfg.Server.Domain, "."), ".")

	return cfg, nil
}

// SaveConfig writes the current configuration back to the configuration YAML file.
func SaveConfig(cfg *Config) error {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()

	targetPath := cfg.ConfigFilePath
	if targetPath == "" {
		targetPath = "configs/gravity.yaml"
	}

	// Ensure parent directories exist
	parent := filepath.Dir(targetPath)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", parent, err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to serialize config to YAML: %w", err)
	}

	if err := os.WriteFile(targetPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", targetPath, err)
	}

	return nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("GRAVITY_DOMAIN"); v != "" {
		cfg.Server.Domain = v
	}
	if v := os.Getenv("GRAVITY_PUBLIC_IPV4"); v != "" {
		cfg.Server.PublicIPv4 = v
	}
	if v := os.Getenv("GRAVITY_PUBLIC_IPV6"); v != "" {
		cfg.Server.PublicIPv6 = v
	}
	if v := os.Getenv("GRAVITY_REDIS_ADDR"); v != "" {
		cfg.Redis.Addr = v
	}
	if v := os.Getenv("GRAVITY_REDIS_PASSWORD"); v != "" {
		cfg.Redis.Password = v
	}
	if v := os.Getenv("GRAVITY_TLS_CERT"); v != "" {
		cfg.DNS.TLSCertFile = v
	}
	if v := os.Getenv("GRAVITY_TLS_KEY"); v != "" {
		cfg.DNS.TLSKeyFile = v
	}
	if v := os.Getenv("GRAVITY_JWT_SECRET"); v != "" {
		cfg.Panel.JWTSecret = v
	}
	if v := os.Getenv("GRAVITY_ADMIN_USER"); v != "" {
		cfg.Panel.AdminUsername = v
	}
	if v := os.Getenv("GRAVITY_ADMIN_PASS"); v != "" {
		cfg.Panel.AdminPassword = v
	}
}

// ConnectTimeoutDuration returns duration for SNIProxy
func (c *SNIProxyConfig) ConnectTimeoutDuration() time.Duration {
	if c.ConnectTimeout <= 0 {
		return 5 * time.Second
	}
	return time.Duration(c.ConnectTimeout) * time.Second
}

// IdleTimeoutDuration returns duration for SNIProxy
func (c *SNIProxyConfig) IdleTimeoutDuration() time.Duration {
	if c.IdleTimeout <= 0 {
		return 300 * time.Second
	}
	return time.Duration(c.IdleTimeout) * time.Second
}

// AbsolutePath resolves a relative file path relative to current working directory.
func AbsolutePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	cwd, err := os.Getwd()
	if err != nil {
		return path
	}
	return filepath.Join(cwd, path)
}
