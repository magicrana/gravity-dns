package panel

import (
	"strings"
	"testing"

	"gravity-dns/internal/config"
	"gravity-dns/internal/store"
)

func TestGenerateMobileConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Domain = "dns.streamvpn.net"
	cfg.Server.PublicIPv4 = "198.51.100.22"

	user := &store.User{
		Token:    "usr_apple123",
		Username: "Alice iPhone",
	}

	// 1. Test DoT MobileConfig
	dotProfile := GenerateMobileConfig(cfg, user, "DOT")
	if !strings.Contains(dotProfile, "<key>PayloadDisplayName</key>") {
		t.Errorf("missing PayloadDisplayName in XML")
	}
	if !strings.Contains(dotProfile, "com.apple.dnsSettings.managed") {
		t.Errorf("missing Apple DNS payload type")
	}
	if !strings.Contains(dotProfile, "<string>TLS</string>") {
		t.Errorf("expected DNSProtocol TLS")
	}
	if !strings.Contains(dotProfile, "usr_apple123.dns.streamvpn.net") {
		t.Errorf("expected SNI server name in DoT profile")
	}
	if !strings.Contains(dotProfile, "198.51.100.22") {
		t.Errorf("expected server IPv4 in profile")
	}

	// 2. Test DoH MobileConfig
	dohProfile := GenerateMobileConfig(cfg, user, "DOH")
	if !strings.Contains(dohProfile, "<string>HTTPS</string>") {
		t.Errorf("expected DNSProtocol HTTPS")
	}
	if !strings.Contains(dohProfile, "https://dns.streamvpn.net:8443/dns-query/usr_apple123") {
		t.Errorf("expected DoH URL in profile")
	}
}
