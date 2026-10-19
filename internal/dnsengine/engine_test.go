package dnsengine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"gravity-dns/internal/config"
	"gravity-dns/internal/resolver"
	"path/filepath"
)

// generateTestCertificate generates in-memory PEM cert and key for testing.
func generateTestCertificate(dnsNames []string) ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: dnsNames[0],
		},
		DNSNames:              dnsNames,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM, nil
}

func TestDynamicCertificateManagement(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Server.Domain = "test.gravity.local"
	cfg.DNS.TLSCertFile = filepath.Join(tempDir, "fullchain.pem")
	cfg.DNS.TLSKeyFile = filepath.Join(tempDir, "privkey.pem")

	s := &Server{
		cfg:     cfg,
		connSNI: make(map[string]connMeta),
	}
	s.tlsConfig = s.setupTLSConfig()

	certPEM, keyPEM, err := generateTestCertificate([]string{"*.dns.test.com", "dns.test.com"})
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	// 1. Update Certificate Dynamically
	if err := s.UpdateCertificate(certPEM, keyPEM); err != nil {
		t.Fatalf("UpdateCertificate failed: %v", err)
	}

	info := s.GetCertificateInfo()
	if !info.Loaded {
		t.Errorf("expected certificate to be loaded")
	}
	if info.Subject != "*.dns.test.com" {
		t.Errorf("expected CN *.dns.test.com, got %s", info.Subject)
	}
	if len(info.DNSNames) != 2 {
		t.Errorf("expected 2 SAN domains, got %d", len(info.DNSNames))
	}
	if info.DaysRemaining <= 0 {
		t.Errorf("expected days remaining > 0, got %d", info.DaysRemaining)
	}

	// 2. Test Domain Updating
	res := &resolver.Resolver{}
	s.resolver = res
	if err := s.UpdateDomain("newdomain.com", "198.51.100.42", "2001:db8::9"); err != nil {
		t.Fatalf("UpdateDomain failed: %v", err)
	}
	if s.cfg.Server.Domain != "newdomain.com" {
		t.Errorf("domain not updated, got %s", s.cfg.Server.Domain)
	}
	if s.cfg.Server.PublicIPv4 != "198.51.100.42" {
		t.Errorf("public IPv4 not updated, got %s", s.cfg.Server.PublicIPv4)
	}
}

func TestExtractTokenFromSNI(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Domain = "dns.example.com"

	s := &Server{cfg: cfg}

	tests := []struct {
		sni      string
		expected string
	}{
		{"usr_abc123.dns.example.com", "usr_abc123"},
		{"usr_998877.dns.example.com:853", "usr_998877"},
		{"usr_client.custom.sub.domain.com", "usr_client"},
		{"", ""},
	}

	for _, tc := range tests {
		actual := s.extractTokenFromSNI(tc.sni)
		if actual != tc.expected {
			t.Errorf("extractTokenFromSNI(%q) = %q; want %q", tc.sni, actual, tc.expected)
		}
	}
}
