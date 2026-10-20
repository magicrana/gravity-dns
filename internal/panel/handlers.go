package panel

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"
	"gravity-dns/internal/config"
	"gravity-dns/internal/dnsengine"
	"gravity-dns/internal/resolver"
	"gravity-dns/internal/store"
)

type APIHandler struct {
	cfg       *config.Config
	store     *store.Store
	resolver  *resolver.Resolver
	dnsEngine *dnsengine.Server
}

func NewAPIHandler(cfg *config.Config, st *store.Store, res *resolver.Resolver, engine *dnsengine.Server) *APIHandler {
	return &APIHandler{
		cfg:       cfg,
		store:     st,
		resolver:  res,
		dnsEngine: engine,
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

// ==================== AUTHENTICATION & SETUP ====================

// handleCheckSetupStatus reports whether the platform has an admin initialized.
func (h *APIHandler) handleCheckSetupStatus(w http.ResponseWriter, r *http.Request) {
	hasAdmin, err := h.store.HasAdminUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{
		"configured": hasAdmin,
	})
}

// handleInitialSetup sets initial admin credentials if no admin currently exists.
func (h *APIHandler) handleInitialSetup(w http.ResponseWriter, r *http.Request) {
	hasAdmin, err := h.store.HasAdminUsers(r.Context())
	if err == nil && hasAdmin {
		writeError(w, http.StatusForbidden, "platform is already initialized with an admin account")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "username required and password must be at least 8 characters")
		return
	}

	if err := h.store.EnsureAdminUser(r.Context(), req.Username, req.Password); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create admin: "+err.Error())
		return
	}

	// Update config & save
	h.cfg.Panel.AdminUsername = req.Username
	h.cfg.Panel.AdminPassword = req.Password
	_ = config.SaveConfig(h.cfg)

	tokenStr, err := GenerateJWT(h.cfg.Panel.JWTSecret, req.Username, h.cfg.Panel.SessionTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to issue token")
		return
	}

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
		"username": req.Username,
		"token":    tokenStr,
	})
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
		// Self-healing fallback: If Redis hash didn't match (e.g. out of sync after manual config edit or reinstall),
		// check against the configured master admin credentials in gravity.yaml and resync Redis if valid.
		if h.cfg.Panel.AdminUsername != "" && req.Username == h.cfg.Panel.AdminUsername &&
			h.cfg.Panel.AdminPassword != "" && req.Password == h.cfg.Panel.AdminPassword {
			_ = h.store.ResetAdminPassword(r.Context(), req.Username, req.Password)
		} else {
			writeError(w, http.StatusUnauthorized, "invalid username or password")
			return
		}
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

// handleUpdateAdminProfile updates both admin username and password.
func (h *APIHandler) handleUpdateAdminProfile(w http.ResponseWriter, r *http.Request) {
	currentAdmin, _ := r.Context().Value(AdminContextKey).(string)
	if currentAdmin == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewUsername     string `json:"new_username"`
		NewPassword     string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	req.NewUsername = strings.TrimSpace(req.NewUsername)
	if req.NewUsername == "" {
		req.NewUsername = currentAdmin
	}

	if req.NewPassword != "" && len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}

	if err := h.store.UpdateAdminProfile(r.Context(), currentAdmin, req.NewUsername, req.CurrentPassword, req.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, "profile update failed: "+err.Error())
		return
	}

	// Update config & save
	h.cfg.Panel.AdminUsername = req.NewUsername
	if req.NewPassword != "" {
		h.cfg.Panel.AdminPassword = req.NewPassword
	}
	_ = config.SaveConfig(h.cfg)

	// Issue new token for new username
	newToken, err := GenerateJWT(h.cfg.Panel.JWTSecret, req.NewUsername, h.cfg.Panel.SessionTTL)
	if err == nil {
		http.SetCookie(w, &http.Cookie{
			Name:     CookieTokenName,
			Value:    newToken,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   h.cfg.Panel.SessionTTL * 3600,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"username": req.NewUsername,
		"token":    newToken,
		"message":  "admin profile updated successfully",
	})
}

// ==================== DOMAIN & SYSTEM SETTINGS ====================

// handleGetSettings returns global platform settings.
func (h *APIHandler) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	currentAdmin, _ := r.Context().Value(AdminContextKey).(string)

	panelListen := h.cfg.Panel.Listen
	if panelListen == "" {
		panelListen = "0.0.0.0:8080"
	}
	panelPort := 8080
	if _, portStr, err := net.SplitHostPort(panelListen); err == nil {
		if p, err := strconv.Atoi(portStr); err == nil {
			panelPort = p
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"domain":            h.cfg.Server.Domain,
		"public_ipv4":       h.cfg.Server.PublicIPv4,
		"public_ipv6":       h.cfg.Server.PublicIPv6,
		"panel_listen":      panelListen,
		"panel_port":        panelPort,
		"dot_listen":        h.cfg.DNS.DoTListen,
		"doh_listen":        h.cfg.DNS.DoHListen,
		"sni_listen":        h.cfg.SNIProxy.Listen,
		"device_window_sec": h.cfg.DNS.DeviceWindowSec,
		"spoof_ttl":         h.cfg.DNS.SpoofTTL,
		"admin_username":    currentAdmin,
		"config_file":       h.cfg.ConfigFilePath,
	})
}

// handleUpdateDomainSettings updates base domain, spoofing IPs, and custom panel port.
func (h *APIHandler) handleUpdateDomainSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain     string `json:"domain"`
		PublicIPv4 string `json:"public_ipv4"`
		PublicIPv6 string `json:"public_ipv6"`
		PanelPort  int    `json:"panel_port"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	req.Domain = strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(req.Domain), "."), ".")
	req.PublicIPv4 = strings.TrimSpace(req.PublicIPv4)
	if req.Domain == "" || req.PublicIPv4 == "" {
		writeError(w, http.StatusBadRequest, "domain and public IPv4 are required")
		return
	}

	if h.dnsEngine != nil {
		if err := h.dnsEngine.UpdateDomain(req.Domain, req.PublicIPv4, req.PublicIPv6); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update domain: "+err.Error())
			return
		}
	} else {
		h.cfg.Server.Domain = req.Domain
		h.cfg.Server.PublicIPv4 = req.PublicIPv4
		h.cfg.Server.PublicIPv6 = req.PublicIPv6
		if h.resolver != nil {
			h.resolver.UpdateServerIPs(req.PublicIPv4, req.PublicIPv6)
		}
	}

	portChanged := false
	currentPort := 8080
	if _, pStr, err := net.SplitHostPort(h.cfg.Panel.Listen); err == nil {
		if p, err := strconv.Atoi(pStr); err == nil {
			currentPort = p
		}
	}
	if req.PanelPort > 0 && req.PanelPort <= 65535 && req.PanelPort != currentPort {
		h.cfg.Panel.Listen = fmt.Sprintf("0.0.0.0:%d", req.PanelPort)
		portChanged = true
	}

	_ = config.SaveConfig(h.cfg)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"domain":       h.cfg.Server.Domain,
		"public_ipv4":  h.cfg.Server.PublicIPv4,
		"public_ipv6":  h.cfg.Server.PublicIPv6,
		"panel_port":   req.PanelPort,
		"port_changed": portChanged,
		"message":      "Settings updated successfully.",
	})
}

// ==================== TLS CERTIFICATES ====================

// handleGetCertificateInfo returns current certificate status and details.
func (h *APIHandler) handleGetCertificateInfo(w http.ResponseWriter, r *http.Request) {
	if h.dnsEngine != nil {
		info := h.dnsEngine.GetCertificateInfo()
		writeJSON(w, http.StatusOK, info)
		return
	}

	// Fallback to config path inspection
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"loaded":    false,
		"cert_path": h.cfg.DNS.TLSCertFile,
		"key_path":  h.cfg.DNS.TLSKeyFile,
	})
}

// handleUploadCertificate applies new PEM certificate and private key.
func (h *APIHandler) handleUploadCertificate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	req.CertPEM = strings.TrimSpace(req.CertPEM)
	req.KeyPEM = strings.TrimSpace(req.KeyPEM)

	if req.CertPEM == "" || req.KeyPEM == "" {
		writeError(w, http.StatusBadRequest, "both certificate (fullchain.pem) and private key (privkey.pem) are required")
		return
	}

	// Validate keypair before applying
	if _, err := tls.X509KeyPair([]byte(req.CertPEM), []byte(req.KeyPEM)); err != nil {
		writeError(w, http.StatusBadRequest, "invalid TLS certificate or private key: "+err.Error())
		return
	}

	if h.dnsEngine != nil {
		if err := h.dnsEngine.UpdateCertificate([]byte(req.CertPEM), []byte(req.KeyPEM)); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to apply certificate: "+err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "TLS certificate and private key updated and applied dynamically",
	})
}

// handleReloadCertificate reloads certificate from disk.
func (h *APIHandler) handleReloadCertificate(w http.ResponseWriter, r *http.Request) {
	if h.dnsEngine != nil {
		if err := h.dnsEngine.ReloadCertificatesFromDisk(); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to reload certificates: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// handleAutoIssueCertificate automates issuing genuine Let's Encrypt Wildcard SSL certificates via Cloudflare DNS.
func getApexDomain(domain string) string {
	parts := strings.Split(strings.Trim(domain, "."), ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return domain
}

func testCloudflareAuth(token, email, domain string) (isToken bool, zoneName string, errMsg string, err error) {
	client := &http.Client{Timeout: 10 * time.Second}
	apex := getApexDomain(domain)

	// 1. Try Token verify endpoint
	tokenReq, _ := http.NewRequest("GET", "https://api.cloudflare.com/client/v4/user/tokens/verify", nil)
	tokenReq.Header.Set("Authorization", "Bearer "+token)
	tokenResp, tokenErr := client.Do(tokenReq)
	if tokenErr == nil {
		defer tokenResp.Body.Close()
		var res struct {
			Success bool `json:"success"`
			Result  struct {
				Status string `json:"status"`
			} `json:"result"`
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		if json.NewDecoder(tokenResp.Body).Decode(&res) == nil && res.Success && res.Result.Status == "active" {
			// Now verify if token has permission to access the apex zone
			zoneReq, _ := http.NewRequest("GET", "https://api.cloudflare.com/client/v4/zones?name="+apex, nil)
			zoneReq.Header.Set("Authorization", "Bearer "+token)
			zoneResp, zoneErr := client.Do(zoneReq)
			if zoneErr == nil {
				defer zoneResp.Body.Close()
				var zRes struct {
					Success bool `json:"success"`
					Result  []struct {
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"result"`
				}
				if json.NewDecoder(zoneResp.Body).Decode(&zRes) == nil && zRes.Success && len(zRes.Result) > 0 {
					return true, zRes.Result[0].Name, "", nil
				}
			}
			return true, apex, "", nil
		}
	}

	// 2. Try Global API Key if email is provided
	if email != "" && !strings.HasPrefix(email, "admin@") {
		keyReq, _ := http.NewRequest("GET", "https://api.cloudflare.com/client/v4/zones?name="+apex, nil)
		keyReq.Header.Set("X-Auth-Email", email)
		keyReq.Header.Set("X-Auth-Key", token)
		keyResp, keyErr := client.Do(keyReq)
		if keyErr == nil {
			defer keyResp.Body.Close()
			var zRes struct {
				Success bool `json:"success"`
				Result  []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"result"`
				Errors []struct {
					Message string `json:"message"`
				} `json:"errors"`
			}
			if json.NewDecoder(keyResp.Body).Decode(&zRes) == nil {
				if zRes.Success && len(zRes.Result) > 0 {
					return false, zRes.Result[0].Name, "", nil
				}
				if len(zRes.Errors) > 0 {
					return false, "", fmt.Sprintf("Cloudflare authentication failed: %s (Please verify that your email address matches your Cloudflare login account)", zRes.Errors[0].Message), fmt.Errorf("cf auth failed")
				}
			}
		}
	}

	// Helper diagnostic message based on input format
	if len(token) == 37 {
		return false, "", "Detected 37-character Global API Key. When using a Global API Key, you must enter your Cloudflare account login email in the Email field.", fmt.Errorf("email required")
	}

	return false, "", "Cloudflare could not verify your API Token. Please ensure your token is active and has permissions: Zone -> DNS -> Edit (All zones or " + apex + ").", fmt.Errorf("token invalid")
}

// handleTestCloudflare tests Cloudflare credentials before certificate issuance.
func (h *APIHandler) handleTestCloudflare(w http.ResponseWriter, r *http.Request) {
	var req struct {
		APIToken string `json:"api_token"`
		Email    string `json:"email"`
		Domain   string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	apiToken := strings.TrimSpace(req.APIToken)
	email := strings.TrimSpace(req.Email)
	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		domain = h.cfg.Server.Domain
	}

	if apiToken == "" {
		writeError(w, http.StatusBadRequest, "Cloudflare API token or Global API Key is required.")
		return
	}

	isToken, zoneName, msg, err := testCloudflareAuth(apiToken, email, domain)
	if err != nil {
		writeError(w, http.StatusBadRequest, msg)
		return
	}

	credType := "API Token"
	if !isToken {
		credType = "Global API Key"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"type":      credType,
		"zone_name": zoneName,
		"message":   fmt.Sprintf("Cloudflare %s verified successfully! Zone '%s' is active and ready.", credType, zoneName),
	})
}

// handleAutoIssueCertificate automates issuing genuine Let's Encrypt Wildcard SSL certificates via Cloudflare DNS.
func (h *APIHandler) handleAutoIssueCertificate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider string `json:"provider"`
		APIToken string `json:"api_token"`
		Email    string `json:"email"`
		Domain   string `json:"domain"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	domain := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(req.Domain), "."), ".")
	if domain == "" {
		domain = h.cfg.Server.Domain
	}
	if domain == "" {
		writeError(w, http.StatusBadRequest, "Base domain is not configured. Please save base domain first.")
		return
	}

	apiToken := strings.TrimSpace(req.APIToken)
	if apiToken == "" {
		writeError(w, http.StatusBadRequest, "Cloudflare API token or Global API Key is required.")
		return
	}

	email := strings.TrimSpace(req.Email)
	if email == "" {
		email = "admin@" + domain
	}

	if runtime.GOOS != "linux" {
		writeError(w, http.StatusBadRequest, "Automated certbot issuance is supported on Linux servers (Ubuntu/Debian). On Windows local dev, please use the upload certificate option.")
		return
	}

	// 1. Verify credentials against Cloudflare API
	isToken, _, authErrMsg, authErr := testCloudflareAuth(apiToken, email, domain)
	if authErr != nil {
		writeError(w, http.StatusBadRequest, authErrMsg)
		return
	}

	// 2. Ensure certbot is installed
	if _, err := exec.LookPath("certbot"); err != nil {
		cmd := exec.Command("apt-get", "update", "-y")
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		_ = cmd.Run()
		installCmd := exec.Command("apt-get", "install", "-y", "--no-install-recommends", "certbot", "curl", "python3")
		installCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		if out, err := installCmd.CombinedOutput(); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to install certbot: %v\nOutput: %s", err, string(out)))
			return
		}
	}

	// 3. Write Cloudflare credentials JSON for auth hook
	credsData := map[string]interface{}{
		"token":    apiToken,
		"email":    email,
		"is_token": isToken,
		"apex":     getApexDomain(domain),
	}
	credsJSON, _ := json.Marshal(credsData)
	_ = os.MkdirAll("/etc/gravity", 0755)
	_ = os.WriteFile("/etc/gravity/cf-creds.json", credsJSON, 0600)
	_ = os.MkdirAll("/var/lib/gravity", 0755)
	_ = os.WriteFile("/var/lib/gravity/cf-creds.json", credsJSON, 0600)

	// Ensure auth hook and cleanup hook exist and are executable in /var/lib/gravity
	authHook := "/var/lib/gravity/cf-auth-hook.sh"
	cleanupHook := "/var/lib/gravity/cf-cleanup-hook.sh"
	_ = os.WriteFile(authHook, []byte(cfAuthHookScript), 0755)
	_ = os.WriteFile(cleanupHook, []byte(cfCleanupHookScript), 0755)
	_ = exec.Command("chmod", "+x", authHook, cleanupHook).Run()

	// 4. Execute Certbot ACME DNS-01 Challenge with automated Cloudflare hooks
	// This uses native Cloudflare REST API via hooks, completely bypassing broken python3-certbot-dns-cloudflare packages
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "certbot", "certonly",
		"--manual",
		"--preferred-challenges", "dns",
		"--manual-auth-hook", authHook,
		"--manual-cleanup-hook", cleanupHook,
		"--manual-public-ip-logging-ok",
		"-d", domain,
		"-d", "*."+domain,
		"--email", email,
		"--agree-tos",
		"--no-eff-email",
		"--non-interactive",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Certbot issuance failed: %v\nDetails:\n%s", err, string(out)))
		return
	}

	// 4. Verify issued certificates and apply dynamically
	certPath := fmt.Sprintf("/etc/letsencrypt/live/%s/fullchain.pem", domain)
	keyPath := fmt.Sprintf("/etc/letsencrypt/live/%s/privkey.pem", domain)

	if _, err := os.Stat(certPath); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Certificate file not found at %s after certbot execution.\nOutput:\n%s", certPath, string(out)))
		return
	}

	// Setup deploy hook for future automatic renewals
	deployHookDir := "/etc/letsencrypt/renewal-hooks/deploy"
	_ = os.MkdirAll(deployHookDir, 0755)
	hookScript := "#!/usr/bin/env bash\nset -euo pipefail\nif systemctl is-active --quiet gravity.service; then\n    systemctl restart gravity.service\nfi\n"
	_ = os.WriteFile(filepath.Join(deployHookDir, "gravitydns.sh"), []byte(hookScript), 0755)

	// Update configuration
	h.cfg.DNS.TLSCertFile = certPath
	h.cfg.DNS.TLSKeyFile = keyPath
	_ = config.SaveConfig(h.cfg)

	// Reload DNS engine dynamically
	if h.dnsEngine != nil {
		_ = h.dnsEngine.ReloadCertificatesFromDisk()
	}

	var certInfo dnsengine.CertInfo
	if h.dnsEngine != nil {
		certInfo = h.dnsEngine.GetCertificateInfo()
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"message":   "Let's Encrypt Wildcard certificate issued and applied successfully!",
		"cert_info": certInfo,
		"log":       string(out),
	})
}

// ==================== REDIS SERVER MANAGEMENT ====================

// handleGetRedisInfo returns live metrics from the Redis server.
func (h *APIHandler) handleGetRedisInfo(w http.ResponseWriter, r *http.Request) {
	info, err := h.store.GetRedisInfo(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	info["addr"] = h.cfg.Redis.Addr
	info["db"] = h.cfg.Redis.DB
	info["has_password"] = h.cfg.Redis.Password != ""

	writeJSON(w, http.StatusOK, info)
}

// handleTestRedisConnection verifies connection to candidate Redis parameters.
func (h *APIHandler) handleTestRedisConnection(w http.ResponseWriter, r *http.Request) {
	var req config.RedisConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	if req.Addr == "" {
		req.Addr = "127.0.0.1:6379"
	}

	testClient := redis.NewClient(&redis.Options{
		Addr:        req.Addr,
		Password:    req.Password,
		DB:          req.DB,
		DialTimeout: 2 * time.Second,
	})
	defer testClient.Close()

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	start := time.Now()
	if err := testClient.Ping(ctx).Err(); err != nil {
		writeError(w, http.StatusBadRequest, "connection failed: "+err.Error())
		return
	}
	latency := float64(time.Since(start).Microseconds()) / 1000.0

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":    true,
		"latency_ms": latency,
		"message":    "Redis connection verified successfully",
	})
}

// handleUpdateRedisConfig updates Redis connection and reconnects.
func (h *APIHandler) handleUpdateRedisConfig(w http.ResponseWriter, r *http.Request) {
	var req config.RedisConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	if req.Addr == "" {
		req.Addr = "127.0.0.1:6379"
	}

	if err := h.store.Reconnect(&req); err != nil {
		writeError(w, http.StatusBadRequest, "failed to connect: "+err.Error())
		return
	}

	h.cfg.Redis = req
	_ = config.SaveConfig(h.cfg)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Redis connection updated and active",
	})
}

// handleFlushRedisSessions removes all sliding-window active device keys.
func (h *APIHandler) handleFlushRedisSessions(w http.ResponseWriter, r *http.Request) {
	deleted, err := h.store.FlushAllSessions(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"deleted": deleted,
		"message": fmt.Sprintf("cleared %d active device sessions", deleted),
	})
}

// handleFlushDNSCache clears the in-memory DNS cache.
func (h *APIHandler) handleFlushDNSCache(w http.ResponseWriter, r *http.Request) {
	cleared := 0
	if h.resolver != nil {
		cleared = h.resolver.FlushCache()
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"cleared": cleared,
		"message": fmt.Sprintf("cleared %d cached DNS records", cleared),
	})
}

// ==================== USER MANAGEMENT ====================

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

// ==================== DOMAIN HIJACK RULES ====================

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

// ==================== STATS & LOGS ====================

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
		"base_domain":       h.cfg.Server.Domain,
		"public_ipv4":       h.cfg.Server.PublicIPv4,
		"public_ipv6":       h.cfg.Server.PublicIPv6,
		"dot_port":          h.cfg.DNS.DoTListen,
		"doh_port":          h.cfg.DNS.DoHListen,
		"sniproxy_port":     h.cfg.SNIProxy.Listen,
		"device_window_sec": h.cfg.DNS.DeviceWindowSec,
		"version":           "1.0.0-production",
	}
	writeJSON(w, http.StatusOK, info)
}

const cfAuthHookScript = `#!/usr/bin/env bash
# GravityDNS - Automated Cloudflare ACME DNS-01 Challenge Hook
set -euo pipefail

CREDS_FILE="${GRAVITY_CF_CREDS:-/etc/gravity/cf-creds.json}"
if [ ! -f "$CREDS_FILE" ]; then
    CREDS_FILE="/var/lib/gravity/cf-creds.json"
fi

if [ ! -f "$CREDS_FILE" ]; then
    echo "[ERROR] Cloudflare credentials missing at $CREDS_FILE" >&2
    exit 1
fi

get_json_val() {
    local key="$1"
    local file="$2"
    if command -v python3 &>/dev/null; then
        python3 -c "import json, sys; d=json.load(open('$file')); print(d.get('$key',''))" 2>/dev/null && return
    fi
    grep -o "\"${key}\"[[:space:]]*:[[:space:]]*\"[^\"]*" "$file" 2>/dev/null | head -n1 | sed -E "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"//"
}

CF_TOKEN=$(get_json_val "token" "$CREDS_FILE")
CF_EMAIL=$(get_json_val "email" "$CREDS_FILE")
IS_TOKEN=$(get_json_val "is_token" "$CREDS_FILE")
APEX=$(get_json_val "apex" "$CREDS_FILE")

if [ -z "$CF_TOKEN" ]; then
    echo "[ERROR] Cloudflare token is empty in $CREDS_FILE" >&2
    exit 1
fi

if [ "$IS_TOKEN" = "false" ]; then
    AUTH_H1="X-Auth-Key: ${CF_TOKEN}"
    AUTH_H2="X-Auth-Email: ${CF_EMAIL}"
else
    AUTH_H1="Authorization: Bearer ${CF_TOKEN}"
    AUTH_H2=""
fi

if [ -n "$AUTH_H2" ]; then
    ZONE_RES=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=${APEX}" \
        -H "${AUTH_H1}" \
        -H "${AUTH_H2}" \
        -H "Content-Type: application/json")
else
    ZONE_RES=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=${APEX}" \
        -H "${AUTH_H1}" \
        -H "Content-Type: application/json")
fi

ZONE_ID=$(echo "$ZONE_RES" | grep -o '"id":"[^"]*' | head -n1 | cut -d'"' -f4)
if [ -z "$ZONE_ID" ]; then
    echo "[ERROR] Could not resolve Cloudflare Zone ID for ${APEX}. Response: $ZONE_RES" >&2
    exit 1
fi

CLEAN_DOMAIN=$(echo "${CERTBOT_DOMAIN}" | sed 's/^\*\.//')
RECORD_NAME="_acme-challenge.${CLEAN_DOMAIN}"

PAYLOAD="{\"type\":\"TXT\",\"name\":\"${RECORD_NAME}\",\"content\":\"${CERTBOT_VALIDATION}\",\"ttl\":60}"

if [ -n "$AUTH_H2" ]; then
    CREATE_RES=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" \
        -H "${AUTH_H1}" \
        -H "${AUTH_H2}" \
        -H "Content-Type: application/json" \
        --data "$PAYLOAD")
else
    CREATE_RES=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" \
        -H "${AUTH_H1}" \
        -H "Content-Type: application/json" \
        --data "$PAYLOAD")
fi

RECORD_ID=$(echo "$CREATE_RES" | grep -o '"id":"[^"]*' | head -n1 | cut -d'"' -f4)
if [ -z "$RECORD_ID" ]; then
    echo "[ERROR] Failed to create TXT record ${RECORD_NAME} in Cloudflare. Response: $CREATE_RES" >&2
    exit 1
fi

TRACK_DIR="/tmp/gravity_acme_records"
mkdir -p "$TRACK_DIR"
echo "${ZONE_ID}:${RECORD_ID}" >> "${TRACK_DIR}/${CERTBOT_VALIDATION}"

echo "[GravityDNS] Successfully created ACME TXT record in Cloudflare DNS for ${RECORD_NAME} (ID: ${RECORD_ID})."
echo "[GravityDNS] Propagating challenge across Cloudflare authoritative network..."

# Baseline sleep for initial Cloudflare anycast distribution
sleep 20

# Active verification via Cloudflare & Google Public DoH
echo "[GravityDNS] Verifying TXT challenge resolution on public DNS resolvers..."
for i in {1..20}; do
    CF_DOH=$(curl -s "https://cloudflare-dns.com/dns-query?name=${RECORD_NAME}&type=TXT" -H "accept: application/dns-json" 2>/dev/null || true)
    GOOG_DOH=$(curl -s "https://dns.google/resolve?name=${RECORD_NAME}&type=TXT" 2>/dev/null || true)
    
    if echo "$CF_DOH" | grep -q "${CERTBOT_VALIDATION}"; then
        echo "[GravityDNS] Confirmed on Cloudflare DoH (attempt ${i}/20)."
        if echo "$GOOG_DOH" | grep -q "${CERTBOT_VALIDATION}"; then
            echo "[GravityDNS] Confirmed on Google Public DNS."
            break
        fi
    fi
    sleep 3
done

# Secondary validation buffer: Let's Encrypt performs multi-perspective secondary validation
# from multiple global datacenters. Giving an extra 30s settling buffer guarantees that ALL
# secondary validation vantage points query up-to-date authoritative records without network timeouts.
echo "[GravityDNS] Waiting 30s settling buffer for Let's Encrypt secondary validation vantage points..."
sleep 30
echo "[GravityDNS] Challenge ready for Let's Encrypt verification!"
`

const cfCleanupHookScript = `#!/usr/bin/env bash
# GravityDNS - Cloudflare ACME DNS-01 Cleanup Hook
set -euo pipefail

CREDS_FILE="${GRAVITY_CF_CREDS:-/etc/gravity/cf-creds.json}"
if [ ! -f "$CREDS_FILE" ]; then
    CREDS_FILE="/var/lib/gravity/cf-creds.json"
fi

if [ ! -f "$CREDS_FILE" ]; then
    exit 0
fi

get_json_val() {
    local key="$1"
    local file="$2"
    if command -v python3 &>/dev/null; then
        python3 -c "import json, sys; d=json.load(open('$file')); print(d.get('$key',''))" 2>/dev/null && return
    fi
    grep -o "\"${key}\"[[:space:]]*:[[:space:]]*\"[^\"]*" "$file" 2>/dev/null | head -n1 | sed -E "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"//"
}

CF_TOKEN=$(get_json_val "token" "$CREDS_FILE")
CF_EMAIL=$(get_json_val "email" "$CREDS_FILE")
IS_TOKEN=$(get_json_val "is_token" "$CREDS_FILE")

if [ -z "$CF_TOKEN" ]; then
    exit 0
fi

if [ "$IS_TOKEN" = "false" ]; then
    AUTH_H1="X-Auth-Key: ${CF_TOKEN}"
    AUTH_H2="X-Auth-Email: ${CF_EMAIL}"
else
    AUTH_H1="Authorization: Bearer ${CF_TOKEN}"
    AUTH_H2=""
fi

REC_FILE="/tmp/gravity_acme_records/${CERTBOT_VALIDATION:-}"
if [ -f "$REC_FILE" ]; then
    while IFS=: read -r ZONE_ID RECORD_ID; do
        if [ -n "$ZONE_ID" ] && [ -n "$RECORD_ID" ]; then
            if [ -n "$AUTH_H2" ]; then
                curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${RECORD_ID}" \
                    -H "${AUTH_H1}" \
                    -H "${AUTH_H2}" \
                    -H "Content-Type: application/json" >/dev/null 2>&1 || true
            else
                curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${RECORD_ID}" \
                    -H "${AUTH_H1}" \
                    -H "Content-Type: application/json" >/dev/null 2>&1 || true
            fi
        fi
    done < "$REC_FILE"
    rm -f "$REC_FILE"
fi
`
