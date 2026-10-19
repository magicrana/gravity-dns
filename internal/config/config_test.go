package config

import (
	"os"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Server.Domain != "dns.example.com" {
		t.Errorf("unexpected default domain: %s", cfg.Server.Domain)
	}
	if cfg.DNS.DoTListen != "0.0.0.0:853" {
		t.Errorf("unexpected DoT listen: %s", cfg.DNS.DoTListen)
	}
	if cfg.SNIProxy.Listen != "0.0.0.0:443" {
		t.Errorf("unexpected SNI listen: %s", cfg.SNIProxy.Listen)
	}
	if cfg.DNS.DeviceWindowSec != 600 {
		t.Errorf("unexpected window: %d", cfg.DNS.DeviceWindowSec)
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	os.Setenv("GRAVITY_DOMAIN", "custom.domain.io")
	os.Setenv("GRAVITY_PUBLIC_IPV4", "198.51.100.99")
	defer func() {
		os.Unsetenv("GRAVITY_DOMAIN")
		os.Unsetenv("GRAVITY_PUBLIC_IPV4")
	}()

	cfg := DefaultConfig()
	applyEnvOverrides(cfg)

	if cfg.Server.Domain != "custom.domain.io" {
		t.Errorf("env override failed for domain: %s", cfg.Server.Domain)
	}
	if cfg.Server.PublicIPv4 != "198.51.100.99" {
		t.Errorf("env override failed for IPv4: %s", cfg.Server.PublicIPv4)
	}
}
