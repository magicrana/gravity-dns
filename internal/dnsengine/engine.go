package dnsengine

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"gravity-dns/internal/config"
	"gravity-dns/internal/limiter"
	"gravity-dns/internal/resolver"
	"gravity-dns/internal/store"
)

// Server coordinates DoT and DoH services with client token authentication.
type Server struct {
	cfg       *config.Config
	store     *store.Store
	limiter   *limiter.Limiter
	resolver  *resolver.Resolver
	tlsConfig *tls.Config

	// DoT connection tracker (maps remote IP:Port -> SNI)
	connMu  sync.RWMutex
	connSNI map[string]connMeta

	dotServer *dns.Server
	dohServer *http.Server

	ctx    context.Context
	cancel context.CancelFunc
}

type connMeta struct {
	sni       string
	updatedAt time.Time
}

// New creates a new DNS Engine Server.
func New(cfg *config.Config, st *store.Store, lim *limiter.Limiter, res *resolver.Resolver) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		cfg:      cfg,
		store:    st,
		limiter:  lim,
		resolver: res,
		connSNI:  make(map[string]connMeta),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Setup TLS configuration with wildcard cert and SNI tracking
	tlsCfg, err := s.setupTLSConfig()
	if err != nil {
		log.Printf("[DNS] Notice: TLS certificates not yet loaded (%v). Testing self-signed fallback.", err)
		tlsCfg = s.createFallbackTLSConfig()
	}
	s.tlsConfig = tlsCfg

	return s, nil
}

// setupTLSConfig initializes TLS with client hello hook to track connection SNI.
func (s *Server) setupTLSConfig() (*tls.Config, error) {
	certFile := s.cfg.DNS.TLSCertFile
	keyFile := s.cfg.DNS.TLSKeyFile

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if hello.Conn != nil {
				remoteAddr := hello.Conn.RemoteAddr().String()
				s.connMu.Lock()
				s.connSNI[remoteAddr] = connMeta{
					sni:       hello.ServerName,
					updatedAt: time.Now(),
				}
				s.connMu.Unlock()
			}
			return nil, nil // Uses default config & certs
		},
	}

	return tlsConfig, nil
}

// createFallbackTLSConfig creates an ephemeral self-signed cert for testing/development.
func (s *Server) createFallbackTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.Conn != nil {
				remoteAddr := hello.Conn.RemoteAddr().String()
				s.connMu.Lock()
				s.connSNI[remoteAddr] = connMeta{
					sni:       hello.ServerName,
					updatedAt: time.Now(),
				}
				s.connMu.Unlock()
			}
			return nil, errors.New("no certificates configured")
		},
	}
}

// Start launches both DoT and DoH services.
func (s *Server) Start() error {
	go s.cleanupStaleConnections()

	errChan := make(chan error, 2)

	// 1. Start DoT (DNS-over-TLS) on :853
	go func() {
		dotAddr := s.cfg.DNS.DoTListen
		if dotAddr == "" {
			dotAddr = "0.0.0.0:853"
		}

		s.dotServer = &dns.Server{
			Addr:      dotAddr,
			Net:       "tcp-tls",
			TLSConfig: s.tlsConfig,
			Handler:   dns.HandlerFunc(s.handleDoT),
		}

		log.Printf("[DNS] DoT (DNS-over-TLS) engine listening on %s", dotAddr)
		if err := s.dotServer.ListenAndServe(); err != nil && !errors.Is(err, net.ErrClosed) {
			errChan <- fmt.Errorf("DoT server failed: %w", err)
		}
	}()

	// 2. Start DoH (DNS-over-HTTPS) on :8443
	go func() {
		dohAddr := s.cfg.DNS.DoHListen
		if dohAddr == "" {
			dohAddr = "0.0.0.0:8443"
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/dns-query", s.handleDoH)
		mux.HandleFunc("/dns-query/", s.handleDoH)

		s.dohServer = &http.Server{
			Addr:         dohAddr,
			Handler:      mux,
			TLSConfig:    s.tlsConfig,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		}

		log.Printf("[DNS] DoH (DNS-over-HTTPS) engine listening on %s (/dns-query/{token})", dohAddr)
		var err error
		if len(s.tlsConfig.Certificates) > 0 {
			err = s.dohServer.ListenAndServeTLS("", "")
		} else {
			// Fallback to HTTP for dev/local or reverse-proxy setups
			err = s.dohServer.ListenAndServe()
		}

		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- fmt.Errorf("DoH server failed: %w", err)
		}
	}()

	select {
	case <-s.ctx.Done():
		return nil
	case err := <-errChan:
		return err
	}
}

// Close gracefully stops the servers.
func (s *Server) Close() error {
	s.cancel()
	if s.dotServer != nil {
		_ = s.dotServer.Shutdown()
	}
	if s.dohServer != nil {
		_ = s.dohServer.Shutdown(context.Background())
	}
	return nil
}

// handleDoT handles incoming DNS-over-TLS queries on port 853.
func (s *Server) handleDoT(w dns.ResponseWriter, r *dns.Msg) {
	clientRemote := w.RemoteAddr().String()

	// 1. Extract SNI from TLS ConnectionState or mapped handshake
	sni := ""
	if csGetter, ok := w.(interface{ ConnectionState() *tls.ConnectionState }); ok {
		if cs := csGetter.ConnectionState(); cs != nil {
			sni = cs.ServerName
		}
	}

	if sni == "" {
		s.connMu.RLock()
		if meta, found := s.connSNI[clientRemote]; found {
			sni = meta.sni
		}
		s.connMu.RUnlock()
	}

	// 2. Extract client token from SNI: <token>.dns.domain.com
	token := s.extractTokenFromSNI(sni)

	// 3. Process the query
	resp := s.processDNSQuery(r, token, clientRemote, "DoT")
	_ = w.WriteMsg(resp)
}

// handleDoH handles incoming DNS-over-HTTPS queries (RFC 8484).
func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	clientRemote := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		clientRemote = strings.Split(fwd, ",")[0]
	}

	// Extract token from path: /dns-query/{token} or Host: <token>.dns.domain.com
	token := ""
	path := strings.TrimPrefix(r.URL.Path, "/dns-query")
	path = strings.TrimPrefix(path, "/")
	if path != "" {
		token = path
	} else if qToken := r.URL.Query().Get("token"); qToken != "" {
		token = qToken
	} else {
		// Try host
		token = s.extractTokenFromSNI(r.Host)
	}

	var reqMsg dns.Msg

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "missing 'dns' query parameter", http.StatusBadRequest)
			return
		}

		rawQuery, err := base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			// Try standard URL encoding
			rawQuery, err = base64.URLEncoding.DecodeString(dnsParam)
			if err != nil {
				http.Error(w, "invalid base64url encoding", http.StatusBadRequest)
				return
			}
		}

		if err := reqMsg.Unpack(rawQuery); err != nil {
			http.Error(w, "invalid DNS wireformat message", http.StatusBadRequest)
			return
		}

	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}

		if err := reqMsg.Unpack(body); err != nil {
			http.Error(w, "invalid DNS wireformat message", http.StatusBadRequest)
			return
		}

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	respMsg := s.processDNSQuery(&reqMsg, token, clientRemote, "DoH")
	packed, err := respMsg.Pack()
	if err != nil {
		http.Error(w, "failed to pack DNS response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(packed)
}

// processDNSQuery authenticates the token, enforces device limits, and resolves the query.
func (s *Server) processDNSQuery(req *dns.Msg, token, clientRemote, protocol string) *dns.Msg {
	clientIP := limiter.NormalizeIP(clientRemote)
	qname := "unknown"
	qtype := "A"
	if len(req.Question) > 0 {
		qname = strings.ToLower(strings.TrimSuffix(req.Question[0].Name, "."))
		qtype = dns.TypeToString[req.Question[0].Qtype]
	}

	// 1. Authenticate Token & Sliding-Window Device Limit
	if token == "" {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		s.store.RecordQuery(context.Background(), store.QueryLogEntry{
			Timestamp: time.Now().Unix(),
			Token:     "unauthenticated",
			ClientIP:  clientIP,
			Domain:    qname,
			QType:     qtype,
			Action:    "REFUSED_AUTH",
			Protocol:  protocol,
		})
		return m
	}

	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
	defer cancel()

	limResult, err := s.limiter.CheckAndRecordQuery(ctx, token, clientIP)
	if err != nil || !limResult.Allowed {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)

		action := "REFUSED_AUTH"
		if errors.Is(err, limiter.ErrDeviceLimit) || (limResult != nil && limResult.Reason == "DEVICE_LIMIT_EXCEEDED") {
			action = "REFUSED_LIMIT"
		}

		s.store.RecordQuery(context.Background(), store.QueryLogEntry{
			Timestamp: time.Now().Unix(),
			Token:     token,
			Username:  getUsername(limResult),
			ClientIP:  clientIP,
			Domain:    qname,
			QType:     qtype,
			Action:    action,
			Protocol:  protocol,
		})
		return m
	}

	// 2. Resolve DNS (Selective Hijack or Upstream Forward)
	resp, hijacked, err := s.resolver.Resolve(ctx, req)
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		return m
	}

	action := "FORWARDED"
	if hijacked {
		action = "HIJACKED"
	}

	s.store.RecordQuery(context.Background(), store.QueryLogEntry{
		Timestamp: time.Now().Unix(),
		Token:     token,
		Username:  getUsername(limResult),
		ClientIP:  clientIP,
		Domain:    qname,
		QType:     qtype,
		Action:    action,
		Protocol:  protocol,
	})

	return resp
}

// extractTokenFromSNI extracts the leading subdomain from <token>.dns.domain.com.
func (s *Server) extractTokenFromSNI(sni string) string {
	sni = strings.ToLower(strings.TrimSpace(sni))
	if sni == "" {
		return ""
	}

	// Remove port if present
	if host, _, err := net.SplitHostPort(sni); err == nil {
		sni = host
	}

	baseDomain := strings.ToLower(s.cfg.Server.Domain)
	if baseDomain != "" && strings.HasSuffix(sni, "."+baseDomain) {
		token := strings.TrimSuffix(sni, "."+baseDomain)
		// If there are multiple subdomain levels (e.g. usr1.extra.dns.domain.com), get the first label
		parts := strings.Split(token, ".")
		return parts[0]
	}

	// If SNI has labels, treat first label as token
	parts := strings.Split(sni, ".")
	if len(parts) >= 3 {
		return parts[0]
	}

	return ""
}

func getUsername(res *limiter.Result) string {
	if res != nil && res.User != nil {
		return res.User.Username
	}
	return ""
}

// cleanupStaleConnections periodically cleans the DoT SNI map.
func (s *Server) cleanupStaleConnections() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			threshold := time.Now().Add(-10 * time.Minute)
			s.connMu.Lock()
			for addr, meta := range s.connSNI {
				if meta.updatedAt.Before(threshold) {
					delete(s.connSNI, addr)
				}
			}
			s.connMu.Unlock()
		}
	}
}
