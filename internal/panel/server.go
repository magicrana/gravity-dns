package panel

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"gravity-dns/internal/config"
	"gravity-dns/internal/dnsengine"
	"gravity-dns/internal/resolver"
	"gravity-dns/internal/store"
)

// Server coordinates the admin web panel and REST APIs.
type Server struct {
	cfg        *config.Config
	store      *store.Store
	resolver   *resolver.Resolver
	dnsEngine  *dnsengine.Server
	httpServer *http.Server
	templates  *template.Template
}

// NewServer creates a new Panel server instance.
func NewServer(cfg *config.Config, st *store.Store, res *resolver.Resolver, engine *dnsengine.Server) *Server {
	return &Server{
		cfg:       cfg,
		store:     st,
		resolver:  res,
		dnsEngine: engine,
	}
}

// Start initializes routing, loads templates, and starts HTTP listener.
func (s *Server) Start() error {
	// Ensure default admin user is initialized in Redis if specified in config
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if s.cfg.Panel.AdminUsername != "" && s.cfg.Panel.AdminPassword != "" {
		if err := s.store.EnsureAdminUser(ctx, s.cfg.Panel.AdminUsername, s.cfg.Panel.AdminPassword); err != nil {
			log.Printf("[PANEL] Warning: Failed to ensure default admin user: %v", err)
		} else {
			log.Printf("[PANEL] Default admin initialized: '%s'", s.cfg.Panel.AdminUsername)
		}
	}

	r := chi.NewRouter()

	// Middlewares
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// CORS settings
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	api := NewAPIHandler(s.cfg, s.store, s.resolver, s.dnsEngine)

	// Static files handler
	staticDir := config.AbsolutePath("web/static")
	if _, err := os.Stat(staticDir); err == nil {
		fileServer := http.FileServer(http.Dir(staticDir))
		r.Handle("/static/*", http.StripPrefix("/static", fileServer))
	}

	// Public Web & Setup Routes
	r.Get("/login", s.renderLoginPage)
	r.Post("/api/login", api.handleLogin)
	r.Get("/api/setup/status", api.handleCheckSetupStatus)
	r.Post("/api/setup/initialize", api.handleInitialSetup)
	r.Get("/api/user/{token}/mobileconfig", api.handleGetMobileConfig)

	// Protected Routes (Session / JWT Token required)
	r.Group(func(protected chi.Router) {
		protected.Use(AuthMiddleware(s.cfg.Panel.JWTSecret))

		// Web Dashboard SPA
		protected.Get("/", s.renderDashboard)

		// Auth & Admin Profile
		protected.Post("/api/logout", api.handleLogout)
		protected.Post("/api/admin/profile", api.handleUpdateAdminProfile)

		// User Management
		protected.Get("/api/users", api.handleGetUsers)
		protected.Post("/api/users", api.handleCreateUser)
		protected.Put("/api/users/{token}", api.handleUpdateUser)
		protected.Delete("/api/users/{token}", api.handleDeleteUser)
		protected.Post("/api/users/{token}/kill-sessions", api.handleKillSessions)
		protected.Get("/api/users/{token}/devices", api.handleGetUserDevices)

		// Domain Hijack Rules & Streaming Presets
		protected.Get("/api/rules", api.handleGetRules)
		protected.Post("/api/rules", api.handleAddRule)
		protected.Delete("/api/rules/{domain}", api.handleDeleteRule)
		protected.Post("/api/rules/{domain}/toggle", api.handleToggleRule)
		protected.Get("/api/presets", api.handleGetPresets)
		protected.Post("/api/presets/{id}/apply", api.handleApplyPreset)

		// Domain & Network Settings
		protected.Get("/api/settings", api.handleGetSettings)
		protected.Put("/api/settings/domain", api.handleUpdateDomainSettings)

		// TLS Certificate Management
		protected.Get("/api/settings/certificate", api.handleGetCertificateInfo)
		protected.Post("/api/settings/certificate", api.handleUploadCertificate)
		protected.Post("/api/settings/certificate/reload", api.handleReloadCertificate)
		protected.Post("/api/settings/certificate/test-cf", api.handleTestCloudflare)
		protected.Post("/api/settings/certificate/auto-issue", api.handleAutoIssueCertificate)

		// Redis Server Management
		protected.Get("/api/redis/info", api.handleGetRedisInfo)
		protected.Post("/api/redis/test", api.handleTestRedisConnection)
		protected.Post("/api/redis/config", api.handleUpdateRedisConfig)
		protected.Post("/api/redis/flush-sessions", api.handleFlushRedisSessions)
		protected.Post("/api/redis/flush-cache", api.handleFlushDNSCache)

		// Metrics, Logs & Server Info
		protected.Get("/api/stats", api.handleGetStats)
		protected.Get("/api/logs", api.handleGetLogs)
		protected.Get("/api/server-info", api.handleGetServerInfo)
	})

	listenAddr := s.cfg.Panel.Listen
	if listenAddr == "" {
		listenAddr = "0.0.0.0:8080"
	}

	s.httpServer = &http.Server{
		Addr:         listenAddr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	log.Printf("[PANEL] GravityDNS Control Plane listening on http://%s", listenAddr)
	return s.httpServer.ListenAndServe()
}

// Close terminates the HTTP server.
func (s *Server) Close() error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(context.Background())
	}
	return nil
}

// renderLoginPage renders the clean login page with initial setup detection.
func (s *Server) renderLoginPage(w http.ResponseWriter, r *http.Request) {
	// If already authenticated, redirect to /
	if cookie, err := r.Cookie(CookieTokenName); err == nil && cookie.Value != "" {
		if _, err := ValidateJWT(s.cfg.Panel.JWTSecret, cookie.Value); err == nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	tmplPath := config.AbsolutePath(filepath.Join("web", "templates", "login.html"))
	t, err := template.ParseFiles(tmplPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Template error: %v", err), http.StatusInternalServerError)
		return
	}

	hasAdmin, _ := s.store.HasAdminUsers(r.Context())

	_ = t.Execute(w, map[string]interface{}{
		"Title":      "Login - GravityDNS",
		"Domain":     s.cfg.Server.Domain,
		"IsNewSetup": !hasAdmin,
	})
}

// renderDashboard renders the main administration panel.
func (s *Server) renderDashboard(w http.ResponseWriter, r *http.Request) {
	username, _ := r.Context().Value(AdminContextKey).(string)

	tmplPath := config.AbsolutePath(filepath.Join("web", "templates", "dashboard.html"))
	t, err := template.ParseFiles(tmplPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Template error: %v", err), http.StatusInternalServerError)
		return
	}

	_ = t.Execute(w, map[string]interface{}{
		"Username":   username,
		"BaseDomain": s.cfg.Server.Domain,
		"PublicIPv4": s.cfg.Server.PublicIPv4,
		"PublicIPv6": s.cfg.Server.PublicIPv6,
		"DoTListen":  s.cfg.DNS.DoTListen,
		"DoHListen":  s.cfg.DNS.DoHListen,
		"SNIListen":  s.cfg.SNIProxy.Listen,
		"RedisAddr":  s.cfg.Redis.Addr,
		"RedisDB":    s.cfg.Redis.DB,
	})
}
