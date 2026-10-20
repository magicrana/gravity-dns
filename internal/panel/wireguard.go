package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/skip2/go-qrcode"
	"gravity-dns/internal/config"
	"gravity-dns/internal/store"
)

const (
	wgDir        = "/etc/wireguard"
	wgConfFile   = "/etc/wireguard/wg0.conf"
	wgClientsDir = "/etc/wireguard/clients"
	wgPort       = 51820
	wgSubnetBase = "10.66.66"
	wgServerIP   = "10.66.66.1"
)

type WGPeerInfo struct {
	Name                 string `json:"name"`
	UserToken            string `json:"user_token,omitempty"`
	Username             string `json:"username,omitempty"`
	TunnelIP             string `json:"tunnel_ip"`
	PublicKey            string `json:"public_key"`
	Endpoint             string `json:"endpoint"`
	AllowedIPs           string `json:"allowed_ips"`
	LatestHandshake      int64  `json:"latest_handshake"`
	LatestHandshakeHuman string `json:"latest_handshake_human"`
	TransferRx           int64  `json:"transfer_rx"`
	TransferTx           int64  `json:"transfer_tx"`
	TransferRxHuman      string `json:"transfer_rx_human"`
	TransferTxHuman      string `json:"transfer_tx_human"`
}

type WGStatusResponse struct {
	Installed    bool         `json:"installed"`
	Active       bool         `json:"active"`
	ServerIP     string       `json:"server_ip"`
	Port         int          `json:"port"`
	Subnet       string       `json:"subnet"`
	PublicIPv4   string       `json:"public_ipv4"`
	ServerPubKey string       `json:"server_pub_key"`
	TotalPeers   int          `json:"total_peers"`
	Peers        []WGPeerInfo `json:"peers"`
	Error        string       `json:"error,omitempty"`
}

// formatBytes formats raw bytes into human readable format (KB, MB, GB).
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// formatTimeAgo returns a human-readable duration string since a unix timestamp.
func formatTimeAgo(ts int64) string {
	if ts <= 0 {
		return "Never"
	}
	diff := time.Now().Unix() - ts
	if diff < 60 {
		return fmt.Sprintf("%d seconds ago", diff)
	}
	if diff < 3600 {
		return fmt.Sprintf("%d mins ago", diff/60)
	}
	if diff < 86400 {
		return fmt.Sprintf("%d hours ago", diff/3600)
	}
	return fmt.Sprintf("%d days ago", diff/86400)
}

// generateQRCodeSVG generates a vector SVG QR code from text content.
func generateQRCodeSVG(content string) ([]byte, error) {
	qr, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return nil, err
	}

	bitmap := qr.Bitmap()
	size := len(bitmap)
	if size == 0 {
		return nil, errors.New("empty qr code bitmap")
	}

	scale := 8
	border := 4
	totalSize := (size + border*2) * scale

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="100%%" height="100%%" shape-rendering="crispEdges">`, totalSize, totalSize))
	sb.WriteString(fmt.Sprintf(`<rect width="%d" height="%d" fill="#ffffff"/>`, totalSize, totalSize))
	sb.WriteString(`<path fill="#000000" d="`)

	for y, row := range bitmap {
		for x, val := range row {
			if val {
				vx := (x + border) * scale
				vy := (y + border) * scale
				sb.WriteString(fmt.Sprintf("M%d,%dh%dv%dh-%dz ", vx, vy, scale, scale, scale))
			}
		}
	}
	sb.WriteString(`"/></svg>`)

	return []byte(sb.String()), nil
}

// extractTunnelIP extracts the clean IPv4 address (stripping any /32 or /24 CIDR suffix) from a .conf string.
func extractTunnelIP(conf string) string {
	for _, l := range strings.Split(conf, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "Address") {
			parts := strings.SplitN(l, "=", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				return strings.Split(val, "/")[0]
			}
		}
	}
	return ""
}

// sanitizePeerName keeps only safe alphanumeric, dash, and underscore characters.
func sanitizePeerName(s string) string {
	reg := regexp.MustCompile("[^a-zA-Z0-9_-]")
	res := reg.ReplaceAllString(s, "")
	if res == "" {
		res = fmt.Sprintf("peer_%d", time.Now().Unix()%10000)
	}
	return res
}

// getWireGuardStatus inspects wg0 status, live peers, and configured client files.
func (h *APIHandler) getWireGuardStatus(ctx context.Context) WGStatusResponse {
	resp := WGStatusResponse{
		ServerIP:   wgServerIP,
		Port:       wgPort,
		Subnet:     wgSubnetBase + ".0/24",
		PublicIPv4: h.cfg.Server.PublicIPv4,
		Peers:      []WGPeerInfo{},
	}

	// 1. Check if wg command exists
	if _, err := exec.LookPath("wg"); err != nil {
		resp.Installed = false
		resp.Active = false
		resp.Error = "WireGuard tools ('wg') not installed on this host."
		return resp
	}
	resp.Installed = true

	// 2. Check if server_public.key exists
	pubKeyPath := filepath.Join(wgDir, "server_public.key")
	if data, err := os.ReadFile(pubKeyPath); err == nil {
		resp.ServerPubKey = strings.TrimSpace(string(data))
	}

	// 3. Check if wg0 is active
	out, err := exec.Command("wg", "show", "wg0").CombinedOutput()
	if err == nil && len(out) > 0 {
		resp.Active = true
	}

	// 4. Map user tokens to wg peer names from Redis
	userMap := make(map[string]*store.User)
	users, _ := h.store.ListUsers(ctx, 0)
	for i := range users {
		u := &users[i]
		if u.WGPeer != "" {
			userMap[u.WGPeer] = u
		}
	}

	// 5. Read all client config files in /etc/wireguard/clients/*.conf
	clientFiles, _ := filepath.Glob(filepath.Join(wgClientsDir, "*.conf"))
	peerMap := make(map[string]*WGPeerInfo) // key: peer name or public key

	for _, cf := range clientFiles {
		baseName := strings.TrimSuffix(filepath.Base(cf), ".conf")
		content, rErr := os.ReadFile(cf)
		if rErr != nil {
			continue
		}
		lines := strings.Split(string(content), "\n")
		var clientPriv, clientIP, serverPub string
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if strings.HasPrefix(l, "PrivateKey") {
				parts := strings.SplitN(l, "=", 2)
				if len(parts) == 2 {
					clientPriv = strings.TrimSpace(parts[1])
				}
			} else if strings.HasPrefix(l, "Address") {
				parts := strings.SplitN(l, "=", 2)
				if len(parts) == 2 {
					clientIP = strings.TrimSpace(parts[1])
				}
			} else if strings.HasPrefix(l, "PublicKey") {
				parts := strings.SplitN(l, "=", 2)
				if len(parts) == 2 {
					serverPub = strings.TrimSpace(parts[1])
				}
			}
		}

		// Calculate client public key from private key
		clientPub := ""
		if clientPriv != "" {
			cmd := exec.Command("wg", "pubkey")
			cmd.Stdin = strings.NewReader(clientPriv)
			if pOut, pErr := cmd.Output(); pErr == nil {
				clientPub = strings.TrimSpace(string(pOut))
			}
		}

		cleanIP := strings.TrimSpace(clientIP)
		if idx := strings.Index(cleanIP, "/"); idx != -1 {
			cleanIP = cleanIP[:idx]
		}

		info := &WGPeerInfo{
			Name:       baseName,
			TunnelIP:   cleanIP,
			PublicKey:  clientPub,
			AllowedIPs: clientIP,
		}

		if u, ok := userMap[baseName]; ok {
			info.UserToken = u.Token
			info.Username = u.Username
		}

		if resp.ServerPubKey == "" && serverPub != "" {
			resp.ServerPubKey = serverPub
		}

		peerMap[baseName] = info
		if clientPub != "" {
			peerMap[clientPub] = info
		}
	}

	// 6. Enrich with live metrics from `wg show wg0 dump`
	dumpOut, dErr := exec.Command("wg", "show", "wg0", "dump").Output()
	if dErr == nil {
		lines := strings.Split(string(dumpOut), "\n")
		// Line 0 is interface info, subsequent lines are peers
		for idx, l := range lines {
			if idx == 0 || strings.TrimSpace(l) == "" {
				continue
			}
			parts := strings.Split(l, "\t")
			// format: <public_key> <preshared_key> <endpoint> <allowed_ips> <latest_handshake> <rx_bytes> <tx_bytes> <persistent_keepalive>
			if len(parts) >= 7 {
				pubKey := parts[0]
				endpoint := parts[2]
				allowed := parts[3]
				hs, _ := strconv.ParseInt(parts[4], 10, 64)
				rx, _ := strconv.ParseInt(parts[5], 10, 64)
				tx, _ := strconv.ParseInt(parts[6], 10, 64)

				peer, exists := peerMap[pubKey]
				if exists {
					peer.Endpoint = endpoint
					peer.AllowedIPs = allowed
					peer.LatestHandshake = hs
					peer.LatestHandshakeHuman = formatTimeAgo(hs)
					peer.TransferRx = rx
					peer.TransferTx = tx
					peer.TransferRxHuman = formatBytes(rx)
					peer.TransferTxHuman = formatBytes(tx)
				}
			}
		}
	}

	// 7. Collect unique peers into response list
	seenNames := make(map[string]bool)
	for _, p := range peerMap {
		if !seenNames[p.Name] {
			seenNames[p.Name] = true
			if p.LatestHandshakeHuman == "" {
				p.LatestHandshakeHuman = "Never"
			}
			if p.TransferRxHuman == "" {
				p.TransferRxHuman = "0 B"
			}
			if p.TransferTxHuman == "" {
				p.TransferTxHuman = "0 B"
			}
			resp.Peers = append(resp.Peers, *p)
		}
	}

	resp.TotalPeers = len(resp.Peers)
	return resp
}

// handleGetWireGuardStatus handles GET /api/wireguard/status
func (h *APIHandler) handleGetWireGuardStatus(w http.ResponseWriter, r *http.Request) {
	st := h.getWireGuardStatus(r.Context())
	writeJSON(w, http.StatusOK, st)
}

// ensureWireGuardRouting enables kernel IP forwarding, NAT masquerade, MSS clamping, and DNS redirection.
func ensureWireGuardRouting() {
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	_ = exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "10.66.66.0/24", "-j", "MASQUERADE").Run()
	_ = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.66.66.0/24", "-j", "MASQUERADE").Run()
	_ = exec.Command("iptables", "-C", "FORWARD", "-i", "wg0", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-A", "FORWARD", "-i", "wg0", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-C", "FORWARD", "-o", "wg0", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-A", "FORWARD", "-o", "wg0", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-t", "mangle", "-C", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()
	_ = exec.Command("iptables", "-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()
	_ = exec.Command("iptables", "-t", "nat", "-C", "PREROUTING", "-i", "wg0", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "1.1.1.1:53").Run()
	_ = exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-i", "wg0", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "1.1.1.1:53").Run()
}

// handleInitWireGuard handles POST /api/wireguard/init
func (h *APIHandler) handleInitWireGuard(w http.ResponseWriter, r *http.Request) {
	scriptPath := "/opt/gravity-dns/scripts/setup-wireguard.sh"
	if _, err := os.Stat(scriptPath); err != nil {
		scriptPath = config.AbsolutePath("scripts/setup-wireguard.sh")
	}

	cmd := exec.Command("bash", scriptPath, "status")
	_ = cmd.Run()

	ensureWireGuardRouting()

	// Ensure systemd service is active
	_ = exec.Command("systemctl", "enable", "wg-quick@wg0").Run()
	_ = exec.Command("systemctl", "restart", "wg-quick@wg0").Run()

	st := h.getWireGuardStatus(r.Context())
	writeJSON(w, http.StatusOK, st)
}

// getNextWireGuardIP scans existing configs to find the next free IP in 10.66.66.2 - 10.66.66.254.
func getNextWireGuardIP() string {
	usedIPs := make(map[int]bool)
	usedIPs[1] = true // 10.66.66.1 is server gateway

	clientFiles, _ := filepath.Glob(filepath.Join(wgClientsDir, "*.conf"))
	for _, cf := range clientFiles {
		data, err := os.ReadFile(cf)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Address") {
				parts := strings.Split(line, "=")
				if len(parts) == 2 {
					ipStr := strings.TrimSpace(parts[1])
					ipStr = strings.Split(ipStr, "/")[0]
					octets := strings.Split(ipStr, ".")
					if len(octets) == 4 && octets[0] == "10" && octets[1] == "66" && octets[2] == "66" {
						if lastOctet, err := strconv.Atoi(octets[3]); err == nil {
							usedIPs[lastOctet] = true
						}
					}
				}
			}
		}
	}

	for i := 2; i <= 254; i++ {
		if !usedIPs[i] {
			return fmt.Sprintf("%s.%d", wgSubnetBase, i)
		}
	}
	return fmt.Sprintf("%s.254", wgSubnetBase)
}

// handleCreateWireGuardPeer handles POST /api/wireguard/peers
func (h *APIHandler) handleCreateWireGuardPeer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		UserToken string `json:"user_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	clientName := sanitizePeerName(strings.TrimSpace(req.Name))
	userToken := strings.TrimSpace(req.UserToken)

	// If name not provided, derive from user token or timestamp
	if clientName == "" || clientName == "peer" {
		if userToken != "" {
			if len(userToken) > 8 {
				clientName = "user_" + userToken[:8]
			} else {
				clientName = "user_" + userToken
			}
		} else {
			clientName = fmt.Sprintf("peer_%d", time.Now().Unix()%10000)
		}
	}

	_ = os.MkdirAll(wgClientsDir, 0700)
	clientConfPath := filepath.Join(wgClientsDir, clientName+".conf")

	// If already exists, return existing configuration
	if confData, err := os.ReadFile(clientConfPath); err == nil {
		if userToken != "" {
			_ = h.store.SetUserWGPeer(r.Context(), userToken, clientName)
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":    true,
			"name":       clientName,
			"user_token": userToken,
			"tunnel_ip":  extractTunnelIP(string(confData)),
			"conf":       string(confData),
			"qr_svg_url": fmt.Sprintf("/api/wireguard/peers/%s/qr.svg", clientName),
			"reused":     true,
		})
		return
	}

	// 1. Generate client private and public keys
	privCmd := exec.Command("wg", "genkey")
	privOut, privErr := privCmd.Output()
	if privErr != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate WireGuard private key: "+privErr.Error())
		return
	}
	clientPriv := strings.TrimSpace(string(privOut))

	pubCmd := exec.Command("wg", "pubkey")
	pubCmd.Stdin = strings.NewReader(clientPriv)
	pubOut, pubErr := pubCmd.Output()
	if pubErr != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate WireGuard public key: "+pubErr.Error())
		return
	}
	clientPub := strings.TrimSpace(string(pubOut))

	// 2. Read Server Public Key
	serverPubPath := filepath.Join(wgDir, "server_public.key")
	serverPubData, sErr := os.ReadFile(serverPubPath)
	serverPub := ""
	if sErr == nil {
		serverPub = strings.TrimSpace(string(serverPubData))
	}
	if serverPub == "" {
		// Try deriving from server_private.key
		if serverPrivData, pErr := os.ReadFile(filepath.Join(wgDir, "server_private.key")); pErr == nil {
			c := exec.Command("wg", "pubkey")
			c.Stdin = strings.NewReader(strings.TrimSpace(string(serverPrivData)))
			if out, oErr := c.Output(); oErr == nil {
				serverPub = strings.TrimSpace(string(out))
				_ = os.WriteFile(serverPubPath, []byte(serverPub), 0644)
			}
		}
	}

	// 3. Assign Next IP
	clientIP := getNextWireGuardIP()

	// 4. Server Public IP & Port
	serverEndpoint := fmt.Sprintf("%s:%d", h.cfg.Server.PublicIPv4, wgPort)

	// 5. Append Peer to /etc/wireguard/wg0.conf
	peerBlock := fmt.Sprintf("\n# Client: %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n", clientName, clientPub, clientIP)
	f, fErr := os.OpenFile(wgConfFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if fErr == nil {
		_, _ = f.WriteString(peerBlock)
		f.Close()
	}

	// 6. Generate Client Configuration File (.conf)
	clientConf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`, clientPriv, clientIP, serverPub, serverEndpoint)

	if err := os.WriteFile(clientConfPath, []byte(clientConf), 0600); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save client configuration file: "+err.Error())
		return
	}

	// 7. Live Sync: Directly register peer in running wg0 kernel table, ensure routing, and update wg0.conf
	ensureWireGuardRouting()
	_ = exec.Command("wg", "set", "wg0", "peer", clientPub, "allowed-ips", clientIP+"/32").Run()
	_ = exec.Command("bash", "-c", "wg syncconf wg0 <(wg-quick strip wg0) 2>/dev/null || systemctl restart wg-quick@wg0 || true").Run()

	// 8. Associate with User in Redis
	if userToken != "" {
		_ = h.store.SetUserWGPeer(r.Context(), userToken, clientName)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":     true,
		"name":        clientName,
		"user_token":  userToken,
		"tunnel_ip":   clientIP,
		"allowed_ips": clientIP + "/32",
		"conf":        clientConf,
		"qr_svg_url":  fmt.Sprintf("/api/wireguard/peers/%s/qr.svg", clientName),
	})
}

// handleGetWireGuardPeer handles GET /api/wireguard/peers/{name}
func (h *APIHandler) handleGetWireGuardPeer(w http.ResponseWriter, r *http.Request) {
	name := sanitizePeerName(chi.URLParam(r, "name"))
	clientConfPath := filepath.Join(wgClientsDir, name+".conf")

	data, err := os.ReadFile(clientConfPath)
	if err != nil {
		writeError(w, http.StatusNotFound, "client peer config not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name":       name,
		"tunnel_ip":  extractTunnelIP(string(data)),
		"conf":       string(data),
		"qr_svg_url": fmt.Sprintf("/api/wireguard/peers/%s/qr.svg", name),
	})
}

// handleGetWireGuardQRCode handles GET /api/wireguard/peers/{name}/qr.svg
func (h *APIHandler) handleGetWireGuardQRCode(w http.ResponseWriter, r *http.Request) {
	name := sanitizePeerName(chi.URLParam(r, "name"))
	clientConfPath := filepath.Join(wgClientsDir, name+".conf")

	data, err := os.ReadFile(clientConfPath)
	if err != nil {
		http.Error(w, "peer config not found: "+err.Error(), http.StatusNotFound)
		return
	}

	// 1. Try pure Go SVG generator first (encodes full .conf text directly without external dependencies)
	svgOut, qErr := generateQRCodeSVG(string(data))
	if qErr != nil {
		// 2. Fallback to qrencode CLI reading from stdin
		cmd := exec.Command("qrencode", "-t", "SVG", "-o", "-")
		cmd.Stdin = bytes.NewReader(data)
		out, cmdErr := cmd.Output()
		if cmdErr != nil {
			http.Error(w, "failed to generate QR code: "+qErr.Error(), http.StatusInternalServerError)
			return
		}
		svgOut = out
	}

	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(svgOut)
}

// handleDownloadWireGuardConf handles GET /api/wireguard/peers/{name}/download
func (h *APIHandler) handleDownloadWireGuardConf(w http.ResponseWriter, r *http.Request) {
	name := sanitizePeerName(chi.URLParam(r, "name"))
	clientConfPath := filepath.Join(wgClientsDir, name+".conf")

	data, err := os.ReadFile(clientConfPath)
	if err != nil {
		http.Error(w, "peer config file not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.conf\"", name))
	w.Header().Set("Content-Type", "application/x-wireguard-profile")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleDeleteWireGuardPeer handles DELETE /api/wireguard/peers/{name}
func (h *APIHandler) handleDeleteWireGuardPeer(w http.ResponseWriter, r *http.Request) {
	name := sanitizePeerName(chi.URLParam(r, "name"))
	clientConfPath := filepath.Join(wgClientsDir, name+".conf")

	// 1. Remove peer block from /etc/wireguard/wg0.conf
	delCmd := exec.Command("sed", "-i", fmt.Sprintf("/# Client: %s/,/^$/d", name), wgConfFile)
	_ = delCmd.Run()

	// 2. Remove client .conf file
	_ = os.Remove(clientConfPath)

	// 3. Live sync peers
	_ = exec.Command("bash", "-c", "wg syncconf wg0 <(wg-quick strip wg0) 2>/dev/null || true").Run()

	// 4. Remove association from user in Redis
	users, _ := h.store.ListUsers(r.Context(), 0)
	for _, u := range users {
		if u.WGPeer == name {
			_ = h.store.ClearUserWGPeer(r.Context(), u.Token)
			break
		}
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// handleGetUserWireGuard handles GET /api/users/{token}/wireguard
func (h *APIHandler) handleGetUserWireGuard(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	user, err := h.store.GetUser(r.Context(), token)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	if user.WGPeer == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"has_peer":   false,
			"user_token": token,
			"username":   user.Username,
		})
		return
	}

	clientConfPath := filepath.Join(wgClientsDir, user.WGPeer+".conf")
	data, err := os.ReadFile(clientConfPath)
	if err != nil {
		// Clean stale association
		_ = h.store.ClearUserWGPeer(r.Context(), token)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"has_peer":   false,
			"user_token": token,
			"username":   user.Username,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"has_peer":   true,
		"peer_name":  user.WGPeer,
		"user_token": token,
		"username":   user.Username,
		"tunnel_ip":  extractTunnelIP(string(data)),
		"conf":       string(data),
		"qr_svg_url": fmt.Sprintf("/api/wireguard/peers/%s/qr.svg", user.WGPeer),
	})
}
