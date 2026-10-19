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
	"gravity-dns/internal/resolver"
	"gravity-dns/internal/store"
)

// Server coordinates the admin web panel and REST APIs.
type Server struct {
	cfg        *config.Config
	store      *store.Store
	resolver   *resolver.Resolver
	httpServer *http.Server
	templates  *template.Template
}

// NewServer creates a new Panel server instance.
func NewServer(cfg *config.Config, st *store.Store, res *resolver.Resolver) *Server {
	return &Server{
		cfg:      cfg,
		store:    st,
		resolver: res,
	}
}

// Start initializes routing, loads templates, and starts HTTP listener.
func (s *Server) Start() error {
	// Ensure default admin user is initialized in Redis
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.store.EnsureAdminUser(ctx, s.cfg.Panel.AdminUsername, s.cfg.Panel.AdminPassword); err != nil {
		log.Printf("[PANEL] Warning: Failed to ensure default admin user: %v", err)
	} else {
		log.Printf("[PANEL] Default admin initialized: '%s'", s.cfg.Panel.AdminUsername)
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

	api := NewAPIHandler(s.cfg, s.store, s.resolver)

	// Static files handler
	staticDir := config.AbsolutePath("web/static")
	if _, err := os.Stat(staticDir); err == nil {
		fileServer := http.FileServer(http.Dir(staticDir))
		r.Handle("/static/*", http.StripPrefix("/static", fileServer))
	}

	// Public Web & Auth Routes
	r.Get("/login", s.renderLoginPage)
	r.Post("/api/login", api.handleLogin)
	r.Get("/api/user/{token}/mobileconfig", api.handleGetMobileConfig)

	// Protected Routes
	r.Group(func(protected chi.Router) {
		protected.Use(AuthMiddleware(s.cfg.Panel.JWTSecret))

		// Web Dashboard
		protected.Get("/", s.renderDashboard)

		// Auth & Security
		protected.Post("/api/logout", api.handleLogout)
		protected.Post("/api/admin/change-password", api.handleChangePassword)

		// User Management
		protected.Get("/api/users", api.handleGetUsers)
		protected.Post("/api/users", api.handleCreateUser)
		protected.Put("/api/users/{token}", api.handleUpdateUser)
		protected.Delete("/api/users/{token}", api.handleDeleteUser)
		protected.Post("/api/users/{token}/kill-sessions", api.handleKillSessions)
		protected.Get("/api/users/{token}/devices", api.handleGetUserDevices)

		// Rules & Presets
		protected.Get("/api/rules", api.handleGetRules)
		protected.Post("/api/rules", api.handleAddRule)
		protected.Delete("/api/rules/{domain}", api.handleDeleteRule)
		protected.Post("/api/rules/{domain}/toggle", api.handleToggleRule)
		protected.Get("/api/presets", api.handleGetPresets)
		protected.Post("/api/presets/{id}/apply", api.handleApplyPreset)

		// Metrics, Logs & Info
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

// renderLoginPage renders the clean login page.
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

	_ = t.Execute(w, map[string]interface{}{
		"Title":  "Login - GravityDNS",
		"Domain": s.cfg.Server.Domain,
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
		"DoTListen":  s.cfg.DNS.DoTListen,
		"DoHListen":  s.cfg.DNS.DoHListen,
		"SNIListen":  s.cfg.SNIProxy.Listen,
	})
}
