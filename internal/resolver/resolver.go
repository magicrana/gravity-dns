package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"gravity-dns/internal/config"
	"gravity-dns/internal/store"
)

// DNSCacheEntry holds cached response for upstream forwarding.
type DNSCacheEntry struct {
	Msg       *dns.Msg
	ExpiresAt time.Time
}

// Resolver handles selective hijacking and upstream resolution.
type Resolver struct {
	cfg        *config.Config
	store      *store.Store
	clientIPv4 net.IP
	clientIPv6 net.IP

	// Rules cache
	rulesMu     sync.RWMutex
	rules       []string
	rulesLoaded time.Time

	// Upstream DNS clients
	dnsClient *dns.Client

	// In-memory DNS cache
	cacheMu sync.RWMutex
	cache   map[string]DNSCacheEntry
}

// New creates a new Resolver instance.
func New(cfg *config.Config, st *store.Store) (*Resolver, error) {
	ipv4 := net.ParseIP(cfg.Server.PublicIPv4)
	if ipv4 == nil {
		ipv4 = net.ParseIP("127.0.0.1")
	}

	var ipv6 net.IP
	if cfg.Server.PublicIPv6 != "" {
		ipv6 = net.ParseIP(cfg.Server.PublicIPv6)
	}

	r := &Resolver{
		cfg:        cfg,
		store:      st,
		clientIPv4: ipv4.To4(),
		clientIPv6: ipv6,
		dnsClient: &dns.Client{
			Net:     "udp",
			Timeout: 2 * time.Second,
		},
		cache: make(map[string]DNSCacheEntry),
	}

	// Initial load of rules
	_ = r.ReloadRules(context.Background())

	// Start background cache cleaner and rule refresher
	go r.startBackgroundTasks()

	return r, nil
}

// UpdateServerIPs dynamically updates the spoofed IPv4 and IPv6 target addresses.
func (r *Resolver) UpdateServerIPs(ipv4Str, ipv6Str string) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	if ip4 := net.ParseIP(ipv4Str); ip4 != nil && ip4.To4() != nil {
		r.clientIPv4 = ip4.To4()
	}
	if ipv6Str != "" {
		if ip6 := net.ParseIP(ipv6Str); ip6 != nil {
			r.clientIPv6 = ip6
		}
	} else {
		r.clientIPv6 = nil
	}
}

// FlushCache clears the in-memory DNS forwarding cache and returns the number of evicted items.
func (r *Resolver) FlushCache() int {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	count := len(r.cache)
	r.cache = make(map[string]DNSCacheEntry)
	return count
}

// ReloadRules refreshes in-memory hijack rules from Redis.
func (r *Resolver) ReloadRules(ctx context.Context) error {
	domains, err := r.store.GetActiveRuleDomains(ctx)
	if err != nil {
		return err
	}

	r.rulesMu.Lock()
	r.rules = domains
	r.rulesLoaded = time.Now()
	r.rulesMu.Unlock()
	return nil
}

// MatchesHijack checks if the domain satisfies any active hijack rules.
func (r *Resolver) MatchesHijack(qname string) (bool, string) {
	domain := strings.ToLower(strings.TrimSuffix(qname, "."))

	r.rulesMu.RLock()
	defer r.rulesMu.RUnlock()

	for _, rule := range r.rules {
		if MatchDomainPattern(rule, domain) {
			return true, rule
		}
	}
	return false, ""
}

// MatchDomainPattern checks whether a query domain matches a rule pattern.
// Supported patterns:
// - "netflix.com" exact match
// - "*.netflix.com" matches "netflix.com", "www.netflix.com", "sub.api.netflix.com"
func MatchDomainPattern(pattern, domain string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	domain = strings.ToLower(strings.TrimSpace(domain))

	if pattern == "" || domain == "" {
		return false
	}

	// Catch-all wildcard: hijacks 100% of all domains
	if pattern == "*" || pattern == "*.*" {
		return true
	}

	// Exact match
	if pattern == domain {
		return true
	}

	// Wildcard prefix: e.g. *.netflix.com
	if strings.HasPrefix(pattern, "*.") {
		base := pattern[2:]
		// Match domain itself (e.g. *.netflix.com matches netflix.com)
		if domain == base {
			return true
		}
		// Match any subdomain (e.g. www.netflix.com has suffix .netflix.com)
		if strings.HasSuffix(domain, "."+base) {
			return true
		}
	}

	return false
}

// Resolve handles a DNS question, either synthesizing a hijacked answer or forwarding upstream.
func (r *Resolver) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, bool, error) {
	if len(req.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeFormatError)
		return m, false, nil
	}

	q := req.Question[0]
	qname := strings.ToLower(q.Name)

	// Check hijack rules
	matched, _ := r.MatchesHijack(qname)
	if matched {
		resp := r.synthesizeHijackResponse(req, q)
		return resp, true, nil
	}

	// Forward upstream
	resp, err := r.forwardUpstream(ctx, req)
	return resp, false, err
}

// synthesizeHijackResponse generates A, AAAA, or NODATA responses for hijacked domains.
func (r *Resolver) synthesizeHijackResponse(req *dns.Msg, q dns.Question) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.RecursionAvailable = true

	ttl := r.cfg.DNS.SpoofTTL
	if ttl == 0 {
		ttl = 60
	}

	switch q.Qtype {
	case dns.TypeA:
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			A: r.clientIPv4,
		}
		m.Answer = append(m.Answer, rr)

	case dns.TypeAAAA:
		if r.clientIPv6 != nil {
			rr := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				AAAA: r.clientIPv6,
			}
			m.Answer = append(m.Answer, rr)
		}
		// If no IPv6 configured, return NOERROR with empty answer (NODATA)
		// forcing the dual-stack client to fall back to IPv4 A record.

	case 65: // dns.TypeHTTPS (RFC 9460)
		// Return NOERROR with empty answer (NODATA) to disable Encrypted ClientHello (ECH)
		// and force standard A record resolution through our SNI proxy.
		m.Rcode = dns.RcodeSuccess

	default:
		// For MX, TXT, etc., return NOERROR with empty answer or forward
		m.Rcode = dns.RcodeSuccess
	}

	return m
}

// forwardUpstream forwards a query to configured upstream servers with caching.
func (r *Resolver) forwardUpstream(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Question[0]
	cacheKey := fmt.Sprintf("%s:%d", q.Name, q.Qtype)

	// Check cache
	r.cacheMu.RLock()
	entry, found := r.cache[cacheKey]
	r.cacheMu.RUnlock()

	if found && time.Now().Before(entry.ExpiresAt) {
		resp := entry.Msg.Copy()
		resp.Id = req.Id
		remainingTTL := uint32(time.Until(entry.ExpiresAt).Seconds())
		for _, rr := range resp.Answer {
			rr.Header().Ttl = remainingTTL
		}
		return resp, nil
	}

	// Query upstreams with round-robin/failover
	upstreams := r.cfg.DNS.UpstreamDNS
	if len(upstreams) == 0 {
		upstreams = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}

	var lastErr error
	for _, upstream := range upstreams {
		if !strings.Contains(upstream, ":") {
			upstream += ":53"
		}

		resp, _, err := r.dnsClient.ExchangeContext(ctx, req, upstream)
		if err == nil && resp != nil {
			// Cache answer if response is successful and has answers
			if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
				minTTL := uint32(300)
				for _, rr := range resp.Answer {
					if rr.Header().Ttl < minTTL && rr.Header().Ttl > 0 {
						minTTL = rr.Header().Ttl
					}
				}
				if minTTL > 600 {
					minTTL = 600 // Cap max cache time to 10 mins
				}

				r.cacheMu.Lock()
				r.cache[cacheKey] = DNSCacheEntry{
					Msg:       resp.Copy(),
					ExpiresAt: time.Now().Add(time.Duration(minTTL) * time.Second),
				}
				r.cacheMu.Unlock()
			}
			return resp, nil
		}
		lastErr = err
	}

	// If all upstreams failed, return ServerFailure
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)
	return m, fmt.Errorf("all upstream DNS servers failed, last error: %w", lastErr)
}

// startBackgroundTasks periodically refreshes rules from Redis and cleans expired cache entries.
func (r *Resolver) startBackgroundTasks() {
	ruleTicker := time.NewTicker(10 * time.Second)
	cacheTicker := time.NewTicker(1 * time.Minute)
	defer ruleTicker.Stop()
	defer cacheTicker.Stop()

	for {
		select {
		case <-ruleTicker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = r.ReloadRules(ctx)
			cancel()

		case <-cacheTicker.C:
			now := time.Now()
			r.cacheMu.Lock()
			for k, v := range r.cache {
				if now.After(v.ExpiresAt) {
					delete(r.cache, k)
				}
			}
			r.cacheMu.Unlock()
		}
	}
}
