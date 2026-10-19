package resolver

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"gravity-dns/internal/config"
)

func TestMatchDomainPattern(t *testing.T) {
	tests := []struct {
		pattern  string
		domain   string
		expected bool
	}{
		{"netflix.com", "netflix.com", true},
		{"netflix.com", "www.netflix.com", false},
		{"*.netflix.com", "netflix.com", true},
		{"*.netflix.com", "www.netflix.com", true},
		{"*.netflix.com", "api.sub.netflix.com", true},
		{"*.netflix.com", "othernetflix.com", false},
		{"*.netflix.com", "notnetflix.com", false},
		{"hulu.com", "hulu.com", true},
		{"*.disneyplus.com", "stream.disneyplus.com", true},
		{"*.disneyplus.com", "disneyplus.com", true},
		{"*.disneyplus.com", "disney.com", false},
	}

	for _, tc := range tests {
		matched := MatchDomainPattern(tc.pattern, tc.domain)
		if matched != tc.expected {
			t.Errorf("MatchDomainPattern(%q, %q) = %v; want %v", tc.pattern, tc.domain, matched, tc.expected)
		}
	}
}

func TestSynthesizeHijackResponse(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.PublicIPv4 = "198.51.100.55"
	cfg.Server.PublicIPv6 = "2001:db8::1"
	cfg.DNS.SpoofTTL = 60

	r := &Resolver{
		cfg:        cfg,
		clientIPv4: net.ParseIP("198.51.100.55").To4(),
		clientIPv6: net.ParseIP("2001:db8::1"),
	}

	// 1. Test Type A Query
	reqA := new(dns.Msg)
	reqA.SetQuestion("www.netflix.com.", dns.TypeA)
	respA := r.synthesizeHijackResponse(reqA, reqA.Question[0])

	if len(respA.Answer) != 1 {
		t.Fatalf("expected 1 answer for A query, got %d", len(respA.Answer))
	}
	aRecord, ok := respA.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected *dns.A record, got %T", respA.Answer[0])
	}
	if aRecord.A.String() != "198.51.100.55" {
		t.Errorf("expected IP 198.51.100.55, got %s", aRecord.A.String())
	}
	if aRecord.Hdr.Ttl != 60 {
		t.Errorf("expected TTL 60, got %d", aRecord.Hdr.Ttl)
	}

	// 2. Test Type AAAA Query with IPv6
	reqAAAA := new(dns.Msg)
	reqAAAA.SetQuestion("www.netflix.com.", dns.TypeAAAA)
	respAAAA := r.synthesizeHijackResponse(reqAAAA, reqAAAA.Question[0])

	if len(respAAAA.Answer) != 1 {
		t.Fatalf("expected 1 answer for AAAA query, got %d", len(respAAAA.Answer))
	}
	aaaaRecord, ok := respAAAA.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("expected *dns.AAAA record, got %T", respAAAA.Answer[0])
	}
	if aaaaRecord.AAAA.String() != "2001:db8::1" {
		t.Errorf("expected IPv6 2001:db8::1, got %s", aaaaRecord.AAAA.String())
	}

	// 3. Test Type HTTPS (RFC 9460) Query -> Must return NODATA (empty answer)
	reqHTTPS := new(dns.Msg)
	reqHTTPS.SetQuestion("www.netflix.com.", 65) // Type HTTPS
	respHTTPS := r.synthesizeHijackResponse(reqHTTPS, reqHTTPS.Question[0])

	if len(respHTTPS.Answer) != 0 {
		t.Fatalf("expected 0 answers (NODATA) for HTTPS query, got %d", len(respHTTPS.Answer))
	}
	if respHTTPS.Rcode != dns.RcodeSuccess {
		t.Errorf("expected RcodeSuccess for NODATA, got %d", respHTTPS.Rcode)
	}
}
