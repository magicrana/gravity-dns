package sniproxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gravity-dns/internal/config"
	"gravity-dns/internal/resolver"
)

// Proxy represents the high-performance transparent TLS SNI Router.
type Proxy struct {
	cfg          *config.Config
	resolver     *resolver.Resolver
	listener     net.Listener
	upstreamDNS  []string
	customRes    *net.Resolver
	activeConns  int64
	totalProxied int64

	// Origin DNS Cache
	dnsCacheMu sync.RWMutex
	dnsCache   map[string]originCacheEntry

	ctx    context.Context
	cancel context.CancelFunc
}

type originCacheEntry struct {
	ip        string
	expiresAt time.Time
}

// New creates a new SNIProxy server.
func New(cfg *config.Config, res *resolver.Resolver) *Proxy {
	ctx, cancel := context.WithCancel(context.Background())

	upstreams := cfg.SNIProxy.UpstreamDNS
	if len(upstreams) == 0 {
		upstreams = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}

	// Custom net.Resolver that explicitly targets independent upstream DNS
	customResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			target := upstreams[0]
			if !strings.Contains(target, ":") {
				target += ":53"
			}
			return d.DialContext(ctx, "udp", target)
		},
	}

	return &Proxy{
		cfg:         cfg,
		resolver:    res,
		upstreamDNS: upstreams,
		customRes:   customResolver,
		dnsCache:    make(map[string]originCacheEntry),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start begins listening and serving connections on the configured SNI proxy port.
func (p *Proxy) Start() error {
	listenAddr := p.cfg.SNIProxy.Listen
	if listenAddr == "" {
		listenAddr = "0.0.0.0:443"
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to bind SNI proxy on %s: %w", listenAddr, err)
	}
	p.listener = ln

	log.Printf("[SNI-PROXY] Transparent SNI Stream Router listening on %s (Zero-Copy Splice enabled)", listenAddr)

	go p.cleanDNSCache()

	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				return nil
			default:
				log.Printf("[SNI-PROXY] Accept error: %v", err)
				continue
			}
		}

		atomic.AddInt64(&p.activeConns, 1)
		go p.handleConn(conn)
	}
}

// Close terminates the proxy server.
func (p *Proxy) Close() error {
	p.cancel()
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

// handleConn inspects ClientHello, resolves origin, and pipes traffic.
func (p *Proxy) handleConn(clientConn net.Conn) {
	defer func() {
		_ = clientConn.Close()
		atomic.AddInt64(&p.activeConns, -1)
	}()

	// 1. Set handshake read deadline
	_ = clientConn.SetReadDeadline(time.Now().Add(p.cfg.SNIProxy.ConnectTimeoutDuration()))

	// 2. Read initial TLS handshake record (standard ClientHello is 512-2048 bytes)
	buf := make([]byte, 4096)
	n, err := clientConn.Read(buf)
	if err != nil {
		return
	}
	initialBytes := buf[:n]

	// 3. Extract SNI hostname
	sni, err := ExtractSNI(initialBytes)
	if err != nil {
		return
	}

	// 4. Validate domain against hijack rules if EnforceRules is enabled
	if p.cfg.SNIProxy.EnforceRules && p.resolver != nil {
		matched, _ := p.resolver.MatchesHijack(sni)
		if !matched {
			// SNI not permitted through this proxy
			return
		}
	}

	// 5. Resolve origin IP via independent upstream DNS
	originIP, err := p.resolveOrigin(sni)
	if err != nil {
		log.Printf("[SNI-PROXY] Origin DNS resolution failed for %s: %v", sni, err)
		return
	}

	// 6. Connect to real origin on port 443
	originAddr := net.JoinHostPort(originIP, "443")
	d := net.Dialer{Timeout: p.cfg.SNIProxy.ConnectTimeoutDuration()}
	targetConn, err := d.DialContext(p.ctx, "tcp", originAddr)
	if err != nil {
		log.Printf("[SNI-PROXY] Failed to dial origin %s (%s): %v", sni, originAddr, err)
		return
	}
	defer targetConn.Close()

	// 7. Replay the initial ClientHello bytes to origin
	if _, err := targetConn.Write(initialBytes); err != nil {
		return
	}

	// 8. Configure TCP options for high-throughput streaming
	p.optimizeTCP(clientConn)
	p.optimizeTCP(targetConn)

	// 9. Clear read deadlines or set idle timeout
	idleTimeout := p.cfg.SNIProxy.IdleTimeoutDuration()
	_ = clientConn.SetDeadline(time.Now().Add(idleTimeout))
	_ = targetConn.SetDeadline(time.Now().Add(idleTimeout))

	atomic.AddInt64(&p.totalProxied, 1)

	// 10. Bidirectional streaming (Go runtime uses Linux splice(2) zero-copy for *net.TCPConn)
	p.streamBidirectional(clientConn, targetConn, idleTimeout)
}

// optimizeTCP enables KeepAlive and TCP_NODELAY.
func (p *Proxy) optimizeTCP(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
}

// streamBidirectional pipes data bidirectionally between client and origin.
func (p *Proxy) streamBidirectional(client, origin net.Conn, idleTimeout time.Duration) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Origin
	go func() {
		defer wg.Done()
		defer func() {
			if tc, ok := origin.(interface{ CloseWrite() error }); ok {
				_ = tc.CloseWrite()
			}
		}()
		_, _ = io.Copy(origin, client)
	}()

	// Origin -> Client
	go func() {
		defer wg.Done()
		defer func() {
			if cc, ok := client.(interface{ CloseWrite() error }); ok {
				_ = cc.CloseWrite()
			}
		}()
		_, _ = io.Copy(client, origin)
	}()

	wg.Wait()
}

// resolveOrigin resolves the actual origin IPv4 using public upstream DNS.
func (p *Proxy) resolveOrigin(host string) (string, error) {
	// Check in-memory cache
	p.dnsCacheMu.RLock()
	entry, found := p.dnsCache[host]
	p.dnsCacheMu.RUnlock()

	if found && time.Now().Before(entry.expiresAt) {
		return entry.ip, nil
	}

	// Lookup via custom resolver
	ctx, cancel := context.WithTimeout(p.ctx, 3*time.Second)
	defer cancel()

	ips, err := p.customRes.LookupHost(ctx, host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("no IP resolved for host %s: %w", host, err)
	}

	// Pick first valid IPv4
	var chosenIP string
	for _, ipStr := range ips {
		parsed := net.ParseIP(ipStr)
		if parsed != nil && parsed.To4() != nil {
			// Guard against looping back to VPS IP
			if ipStr != p.cfg.Server.PublicIPv4 {
				chosenIP = ipStr
				break
			}
		}
	}

	if chosenIP == "" {
		chosenIP = ips[0]
	}

	// Cache IP for 60 seconds
	p.dnsCacheMu.Lock()
	p.dnsCache[host] = originCacheEntry{
		ip:        chosenIP,
		expiresAt: time.Now().Add(60 * time.Second),
	}
	p.dnsCacheMu.Unlock()

	return chosenIP, nil
}

// cleanDNSCache periodically evicts expired entries.
func (p *Proxy) cleanDNSCache() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			p.dnsCacheMu.Lock()
			for host, entry := range p.dnsCache {
				if now.After(entry.expiresAt) {
					delete(p.dnsCache, host)
				}
			}
			p.dnsCacheMu.Unlock()
		}
	}
}

// Stats returns proxy performance counters.
func (p *Proxy) Stats() (active int64, total int64) {
	return atomic.LoadInt64(&p.activeConns), atomic.LoadInt64(&p.totalProxied)
}
