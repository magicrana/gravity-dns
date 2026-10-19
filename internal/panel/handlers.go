package panel

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"gravity-dns/internal/config"
	"gravity-dns/internal/resolver"
	"gravity-dns/internal/store"
)

type APIHandler struct {
	cfg      *config.Config
	store    *store.Store
	resolver *resolver.Resolver
}

func NewAPIHandler(cfg *config.Config, st *store.Store, res *resolver.Resolver) *APIHandler {
	return &APIHandler{
		cfg:      cfg,
		store:    st,
		resolver: res,
	}
}

// JSON helpers
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// handleLogin validates admin credentials and returns session token.
func (h *APIHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	if err := h.store.AuthenticateAdmin(r.Context(), req.Username, req.Password); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	tokenStr, err := GenerateJWT(h.cfg.Panel.JWTSecret, req.Username, h.cfg.Panel.SessionTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate authentication token")
		return
	}

	// Set HTTP-only Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     CookieTokenName,
		Value:    tokenStr,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   h.cfg.Panel.SessionTTL * 3600,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"token":    tokenStr,
		"username": req.Username,
	})
}

// handleLogout clears the session cookie.
func (h *APIHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieTokenName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// handleChangePassword allows admin to update their master password.
func (h *APIHandler) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	username, _ := r.Context().Value(AdminContextKey).(string)
	if username == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	if len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}

	if err := h.store.AuthenticateAdmin(r.Context(), username, req.OldPassword); err != nil {
		writeError(w, http.StatusUnauthorized, "incorrect current password")
		return
	}

	if err := h.store.UpdateAdminPassword(r.Context(), username, req.NewPassword); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update password")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "password updated successfully"})
}

// handleGetUsers returns all registered users with their active device count.
func (h *APIHandler) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	windowSec := h.cfg.DNS.DeviceWindowSec
	users, err := h.store.ListUsers(r.Context(), windowSec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, users)
}

// handleCreateUser adds a new user token account.
func (h *APIHandler) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var u store.User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	// Auto-generate token if empty
	if strings.TrimSpace(u.Token) == "" {
		b := make([]byte, 6)
		_, _ = rand.Read(b)
		u.Token = "usr_" + hex.EncodeToString(b)
	}

	u.Token = strings.ToLower(strings.TrimSpace(u.Token))
	if u.Username == "" {
		u.Username = u.Token
	}
	if u.MaxDevices <= 0 {
		u.MaxDevices = 2
	}
	if u.Status == "" {
		u.Status = "active"
	}

	if err := h.store.CreateUser(r.Context(), &u); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, u)
}

// handleUpdateUser updates user parameters.
func (h *APIHandler) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if token == "" {
		writeError(w, http.StatusBadRequest, "token required")
		return
	}

	var u store.User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	u.Token = token

	if err := h.store.UpdateUser(r.Context(), &u); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, u)
}

// handleDeleteUser deletes a user and flushes their sessions.
func (h *APIHandler) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if token == "" {
		writeError(w, http.StatusBadRequest, "token required")
		return
	}

	if err := h.store.DeleteUser(r.Context(), token); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// handleKillSessions immediately invalidates all active sessions for a user.
func (h *APIHandler) handleKillSessions(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if token == "" {
		writeError(w, http.StatusBadRequest, "token required")
		return
	}

	if err := h.store.KillUserSessions(r.Context(), token); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "active sessions killed successfully",
	})
}

// handleGetUserDevices returns the list of active device IPs and last-seen timestamps.
func (h *APIHandler) handleGetUserDevices(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if token == "" {
		writeError(w, http.StatusBadRequest, "token required")
		return
	}

	devices, err := h.store.GetActiveDevices(r.Context(), token, h.cfg.DNS.DeviceWindowSec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, devices)
}

// handleGetMobileConfig generates and streams the Apple iOS/macOS profile.
func (h *APIHandler) handleGetMobileConfig(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if token == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}

	u, err := h.store.GetUser(r.Context(), token)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	protocol := r.URL.Query().Get("protocol")
	if protocol == "" {
		protocol = "DOT"
	}

	profileXML := GenerateMobileConfig(h.cfg, u, protocol)
	filename := fmt.Sprintf("GravityDNS_%s.mobileconfig", u.Username)

	w.Header().Set("Content-Type", "application/x-apple-aspen-config; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(profileXML))
}

// handleGetRules returns all domain rules.
func (h *APIHandler) handleGetRules(w http.ResponseWriter, r *http.Request) {
	rules, err := h.store.ListRules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

// handleAddRule adds a domain hijacking pattern.
func (h *APIHandler) handleAddRule(w http.ResponseWriter, r *http.Request) {
	var rule store.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	rule.Domain = strings.ToLower(strings.TrimSpace(rule.Domain))
	if rule.Domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	if rule.Category == "" {
		rule.Category = "Custom"
	}
	rule.Enabled = true

	if err := h.store.AddRule(r.Context(), rule); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Trigger immediate rule reload
	if h.resolver != nil {
		_ = h.resolver.ReloadRules(r.Context())
	}

	writeJSON(w, http.StatusCreated, rule)
}

// handleDeleteRule deletes a domain rule.
func (h *APIHandler) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain required")
		return
	}

	if err := h.store.DeleteRule(r.Context(), domain); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if h.resolver != nil {
		_ = h.resolver.ReloadRules(r.Context())
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// handleToggleRule enables or disables a domain rule.
func (h *APIHandler) handleToggleRule(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain required")
		return
	}

	if err := h.store.ToggleRule(r.Context(), domain); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if h.resolver != nil {
		_ = h.resolver.ReloadRules(r.Context())
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// handleGetPresets returns predefined streaming service bundles.
func (h *APIHandler) handleGetPresets(w http.ResponseWriter, r *http.Request) {
	presets := store.GetDefaultStreamingPresets()
	writeJSON(w, http.StatusOK, presets)
}

// handleApplyPreset enables all domains in a preset.
func (h *APIHandler) handleApplyPreset(w http.ResponseWriter, r *http.Request) {
	presetID := chi.URLParam(r, "id")
	presets := store.GetDefaultStreamingPresets()

	var selected *store.StreamingPreset
	for _, p := range presets {
		if p.ID == presetID {
			selected = &p
			break
		}
	}

	if selected == nil {
		writeError(w, http.StatusNotFound, "preset not found")
		return
	}

	for _, domain := range selected.Domains {
		_ = h.store.AddRule(r.Context(), store.Rule{
			Domain:    domain,
			Category:  selected.Name,
			Enabled:   true,
			CreatedAt: time.Now().Unix(),
		})
	}

	if h.resolver != nil {
		_ = h.resolver.ReloadRules(r.Context())
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"preset":  selected.Name,
		"count":   len(selected.Domains),
	})
}

// handleGetStats returns system-wide metrics.
func (h *APIHandler) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.GetStats(r.Context(), h.cfg.DNS.DeviceWindowSec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// handleGetLogs returns the latest 50 DNS queries.
func (h *APIHandler) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := int64(50)
	if limitStr != "" {
		if l, err := strconv.ParseInt(limitStr, 10, 64); err == nil {
			limit = l
		}
	}

	logs, err := h.store.GetRecentQueryLogs(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, logs)
}

// handleGetServerInfo returns server IP, base domain, endpoints, and setup helpers.
func (h *APIHandler) handleGetServerInfo(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{
		"base_domain":      h.cfg.Server.Domain,
		"public_ipv4":      h.cfg.Server.PublicIPv4,
		"public_ipv6":      h.cfg.Server.PublicIPv6,
		"dot_port":         h.cfg.DNS.DoTListen,
		"doh_port":         h.cfg.DNS.DoHListen,
		"sniproxy_port":    h.cfg.SNIProxy.Listen,
		"device_window_sec": h.cfg.DNS.DeviceWindowSec,
		"version":          "1.0.0-production",
	}
	writeJSON(w, http.StatusOK, info)
}
