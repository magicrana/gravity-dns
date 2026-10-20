package panel

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"golang.org/x/crypto/curve25519"
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

// generateKeypair generates a WireGuard-compatible Curve25519 keypair in base64.
// Tries `wg genkey` CLI first, and falls back to pure Go Curve25519 if wg CLI is not available.
func generateKeypair() (privBase64 string, pubBase64 string, err error) {
	if _, lErr := exec.LookPath("wg"); lErr == nil {
		privOut, privErr := exec.Command("wg", "genkey").Output()
		if privErr == nil {
			privStr := strings.TrimSpace(string(privOut))
			pubCmd := exec.Command("wg", "pubkey")
			pubCmd.Stdin = strings.NewReader(privStr)
			if pubOut, pubErr := pubCmd.Output(); pubErr == nil {
				return privStr, strings.TrimSpace(string(pubOut)), nil
			}
		}
	}

	var privKey, pubKey [32]byte
	if _, err := io.ReadFull(rand.Reader, privKey[:]); err != nil {
		return "", "", err
	}
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	curve25519.ScalarBaseMult(&pubKey, &privKey)
	return base64.StdEncoding.EncodeToString(privKey[:]), base64.StdEncoding.EncodeToString(pubKey[:]), nil
}

// derivePublicKey derives the WireGuard Curve25519 public key from a base64 private key.
func derivePublicKey(privBase64 string) (string, error) {
	privBase64 = strings.TrimSpace(privBase64)
	if privBase64 == "" {
		return "", errors.New("empty private key")
	}

	if _, lErr := exec.LookPath("wg"); lErr == nil {
		cmd := exec.Command("wg", "pubkey")
		cmd.Stdin = strings.NewReader(privBase64)
		if pubOut, pubErr := cmd.Output(); pubErr == nil {
			pub := strings.TrimSpace(string(pubOut))
			if pub != "" {
				return pub, nil
			}
		}
	}

	privBytes, err := base64.StdEncoding.DecodeString(privBase64)
	if err != nil || len(privBytes) != 32 {
		return "", errors.New("invalid private key base64")
	}
	var privKey, pubKey [32]byte
	copy(privKey[:], privBytes)
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	curve25519.ScalarBaseMult(&pubKey, &privKey)
	return base64.StdEncoding.EncodeToString(pubKey[:]), nil
}

// getServerPublicKey returns the WireGuard server public key, ensuring keys exist on disk.
func getServerPublicKey() (string, error) {
	serverPubPath := filepath.Join(wgDir, "server_public.key")
	serverPrivPath := filepath.Join(wgDir, "server_private.key")

	// 1. Check if server_public.key exists and has valid content
	if data, err := os.ReadFile(serverPubPath); err == nil {
		pub := strings.TrimSpace(string(data))
		if pub != "" {
			return pub, nil
		}
	}

	// 2. Check if server_private.key exists to derive public key
	if data, err := os.ReadFile(serverPrivPath); err == nil {
		priv := strings.TrimSpace(string(data))
		if priv != "" {
			if pub, err := derivePublicKey(priv); err == nil && pub != "" {
				_ = os.WriteFile(serverPubPath, []byte(pub+"\n"), 0644)
				return pub, nil
			}
		}
	}

	// 3. Generate a brand new server keypair if missing
	_ = os.MkdirAll(wgDir, 0700)
	priv, pub, err := generateKeypair()
	if err != nil {
		return "", fmt.Errorf("failed to generate server keypair: %w", err)
	}

	_ = os.WriteFile(serverPrivPath, []byte(priv+"\n"), 0600)
	_ = os.WriteFile(serverPubPath, []byte(pub+"\n"), 0644)
	return pub, nil
}

// ensureServerWireGuardConfig ensures /etc/wireguard directory, keys, and wg0.conf exist with optimal forwarding rules.
func ensureServerWireGuardConfig() error {
	_ = os.MkdirAll(wgDir, 0700)
	_ = os.MkdirAll(wgClientsDir, 0700)

	_, err := getServerPublicKey()
	if err != nil {
		return err
	}

	serverPrivPath := filepath.Join(wgDir, "server_private.key")
	privData, _ := os.ReadFile(serverPrivPath)
	serverPriv := strings.TrimSpace(string(privData))

	desiredPostUp := "iptables -I FORWARD 1 -i wg0 -j ACCEPT; iptables -I FORWARD 2 -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -I POSTROUTING 1 -s 10.66.66.0/24 ! -o wg0 -j MASQUERADE; iptables -t mangle -I FORWARD 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
	desiredPostDown := "iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -o wg0 -m state --state RELATED,ESTABLISHED 2>/dev/null || true; iptables -t nat -D POSTROUTING -s 10.66.66.0/24 ! -o wg0 -j MASQUERADE 2>/dev/null || true; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true"

	if _, err := os.Stat(wgConfFile); os.IsNotExist(err) && serverPriv != "" {
		confContent := fmt.Sprintf(`[Interface]
Address = %s/24
ListenPort = %d
PrivateKey = %s
SaveConfig = false

# NAT firewall, MSS clamping & internet forwarding rules
PostUp = %s
PostDown = %s
`, wgServerIP, wgPort, serverPriv, desiredPostUp, desiredPostDown)

		_ = os.WriteFile(wgConfFile, []byte(confContent), 0600)
		_ = exec.Command("systemctl", "enable", "wg-quick@wg0").Run()
		_ = exec.Command("systemctl", "restart", "wg-quick@wg0").Run()
	} else if data, err := os.ReadFile(wgConfFile); err == nil {
		// Update existing wg0.conf if it contains outdated/broken rules (e.g. DNAT or -A FORWARD)
		confStr := string(data)
		if strings.Contains(confStr, "DNAT") || !strings.Contains(confStr, "! -o wg0") || !strings.Contains(confStr, "-I FORWARD 1") {
			rePostUp := regexp.MustCompile(`(?m)^PostUp[ \t]*=.*$`)
			rePostDown := regexp.MustCompile(`(?m)^PostDown[ \t]*=.*$`)
			confStr = rePostUp.ReplaceAllString(confStr, "PostUp = "+desiredPostUp)
			confStr = rePostDown.ReplaceAllString(confStr, "PostDown = "+desiredPostDown)
			_ = os.WriteFile(wgConfFile, []byte(confStr), 0600)
			_ = exec.Command("bash", "-c", "wg syncconf wg0 <(wg-quick strip wg0) 2>/dev/null || systemctl restart wg-quick@wg0 || true").Run()
		}
	}
	syncAllWireGuardPeers()
	return nil
}

// syncAllWireGuardPeers ensures all client configurations on disk are active in wg0.conf and kernel wg0 table.
func syncAllWireGuardPeers() {
	clientFiles, _ := filepath.Glob(filepath.Join(wgClientsDir, "*.conf"))
	if len(clientFiles) == 0 {
		return
	}

	wgData, _ := os.ReadFile(wgConfFile)
	wgConfStr := string(wgData)
	var peersToAppend strings.Builder

	for _, cf := range clientFiles {
		cname := strings.TrimSuffix(filepath.Base(cf), ".conf")
		confStr, rErr := readAndRepairClientConf(cname)
		if rErr != nil {
			continue
		}

		lines := strings.Split(confStr, "\n")
		var clientPriv, clientIP string
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
			}
		}

		if clientPriv == "" {
			continue
		}
		clientPub, pErr := derivePublicKey(clientPriv)
		if pErr != nil || clientPub == "" {
			continue
		}
		cleanIP := strings.TrimSpace(clientIP)
		if idx := strings.Index(cleanIP, "/"); idx != -1 {
			cleanIP = cleanIP[:idx]
		}
		if cleanIP == "" {
			continue
		}

		// 1. Ensure peer exists in wg0.conf
		if !strings.Contains(wgConfStr, clientPub) {
			peerBlock := fmt.Sprintf("\n# Client: %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n", cname, clientPub, cleanIP)
			peersToAppend.WriteString(peerBlock)
			wgConfStr += peerBlock
		}

		// 2. Register peer directly in live kernel wg0 table
		_ = exec.Command("wg", "set", "wg0", "peer", clientPub, "allowed-ips", cleanIP+"/32").Run()
	}

	if peersToAppend.Len() > 0 {
		if f, fErr := os.OpenFile(wgConfFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600); fErr == nil {
			_, _ = f.WriteString(peersToAppend.String())
			f.Close()
		}
	}
}

// patchMissingServerPubKey repairs client configurations where PublicKey was left empty or MTU is missing.
func patchMissingServerPubKey(conf string, serverPub string) (string, bool) {
	changed := false
	serverPub = strings.TrimSpace(serverPub)
	if serverPub != "" {
		re := regexp.MustCompile(`(?m)^([ \t]*PublicKey[ \t]*=[ \t]*)$`)
		if re.MatchString(conf) {
			conf = re.ReplaceAllString(conf, fmt.Sprintf("PublicKey = %s", serverPub))
			changed = true
		}
	}
	if !strings.Contains(conf, "MTU =") && !strings.Contains(conf, "MTU=") {
		reDNS := regexp.MustCompile(`(?m)^(DNS[ \t]*=.*)$`)
		if reDNS.MatchString(conf) {
			conf = reDNS.ReplaceAllString(conf, "$1\nMTU = 1420")
			changed = true
		}
	}
	return conf, changed
}

// readAndRepairClientConf reads a client .conf file and auto-repairs missing server public keys.
func readAndRepairClientConf(name string) (string, error) {
	clientConfPath := filepath.Join(wgClientsDir, name+".conf")
	data, err := os.ReadFile(clientConfPath)
	if err != nil {
		return "", err
	}
	confStr := string(data)
	if serverPub, err := getServerPublicKey(); err == nil && serverPub != "" {
		if patched, changed := patchMissingServerPubKey(confStr, serverPub); changed {
			confStr = patched
			_ = os.WriteFile(clientConfPath, []byte(patched), 0600)
		}
	}
	return confStr, nil
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

	// 2. Fetch or generate server public key
	if pub, err := getServerPublicKey(); err == nil && pub != "" {
		resp.ServerPubKey = pub
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
		confStr := string(content)
		if resp.ServerPubKey != "" {
			if patched, changed := patchMissingServerPubKey(confStr, resp.ServerPubKey); changed {
				confStr = patched
				_ = os.WriteFile(cf, []byte(patched), 0600)
			}
		}

		lines := strings.Split(confStr, "\n")
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
			if pub, err := derivePublicKey(clientPriv); err == nil {
				clientPub = pub
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

// ensureWireGuardRouting enables kernel IP forwarding, rp_filter loose mode, UFW routing, and NAT masquerade.
func ensureWireGuardRouting() {
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	_ = exec.Command("sysctl", "-w", "net.ipv4.conf.all.forwarding=1").Run()
	_ = exec.Command("sysctl", "-w", "net.ipv4.conf.all.rp_filter=2").Run()
	_ = exec.Command("sysctl", "-w", "net.ipv4.conf.default.rp_filter=2").Run()

	// Ensure UFW allows packet forwarding instead of dropping
	_ = exec.Command("ufw", "route", "allow", "in", "on", "wg0").Run()
	_ = exec.Command("ufw", "route", "allow", "out", "on", "wg0").Run()
	_ = exec.Command("ufw", "allow", "51820/udp").Run()

	// Flush old / conflicting rules
	_ = exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-i", "wg0", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "1.1.1.1:53").Run()
	_ = exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-i", "wg0", "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", "1.1.1.1:53").Run()
	_ = exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "10.66.66.0/24", "-j", "MASQUERADE").Run()
	_ = exec.Command("iptables", "-D", "FORWARD", "-i", "wg0", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-D", "FORWARD", "-o", "wg0", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-t", "mangle", "-D", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()
	_ = exec.Command("iptables", "-D", "INPUT", "-p", "udp", "--dport", "51820", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "10.66.66.0/24", "!", "-o", "wg0", "-j", "MASQUERADE").Run()

	// Insert rules at TOP of chains (ahead of ufw-reject-forward)
	_ = exec.Command("iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", "51820", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-I", "FORWARD", "1", "-i", "wg0", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-I", "FORWARD", "2", "-o", "wg0", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", "10.66.66.0/24", "!", "-o", "wg0", "-j", "MASQUERADE").Run()
	_ = exec.Command("iptables", "-t", "mangle", "-I", "FORWARD", "1", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()
}

// handleInitWireGuard handles POST /api/wireguard/init
func (h *APIHandler) handleInitWireGuard(w http.ResponseWriter, r *http.Request) {
	_ = ensureServerWireGuardConfig()

	scriptPath := "/opt/gravity-dns/scripts/setup-wireguard.sh"
	if _, err := os.Stat(scriptPath); err != nil {
		scriptPath = config.AbsolutePath("scripts/setup-wireguard.sh")
	}

	cmd := exec.Command("bash", scriptPath, "init")
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

	// If already exists, return existing configuration (with self-healing if server public key was missing)
	if confStr, err := readAndRepairClientConf(clientName); err == nil {
		if userToken != "" {
			_ = h.store.SetUserWGPeer(r.Context(), userToken, clientName)
		}
		// Ensure all peers (including this one) are registered into live wg0 kernel table
		syncAllWireGuardPeers()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":    true,
			"name":       clientName,
			"user_token": userToken,
			"tunnel_ip":  extractTunnelIP(confStr),
			"conf":       confStr,
			"qr_svg_url": fmt.Sprintf("/api/wireguard/peers/%s/qr.svg", clientName),
			"reused":     true,
		})
		return
	}

	// 1. Generate client private and public keys (via wg genkey or Curve25519)
	clientPriv, clientPub, keyErr := generateKeypair()
	if keyErr != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate WireGuard client keys: "+keyErr.Error())
		return
	}

	// 2. Ensure server keys & wg0 config exist, then retrieve server public key
	_ = ensureServerWireGuardConfig()
	serverPub, sErr := getServerPublicKey()
	if sErr != nil || serverPub == "" {
		writeError(w, http.StatusInternalServerError, "failed to determine WireGuard server public key: "+sErr.Error())
		return
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
MTU = 1420

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
	confStr, err := readAndRepairClientConf(name)
	if err != nil {
		writeError(w, http.StatusNotFound, "client peer config not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name":       name,
		"tunnel_ip":  extractTunnelIP(confStr),
		"conf":       confStr,
		"qr_svg_url": fmt.Sprintf("/api/wireguard/peers/%s/qr.svg", name),
	})
}

// handleGetWireGuardQRCode handles GET /api/wireguard/peers/{name}/qr.svg
func (h *APIHandler) handleGetWireGuardQRCode(w http.ResponseWriter, r *http.Request) {
	name := sanitizePeerName(chi.URLParam(r, "name"))
	confStr, err := readAndRepairClientConf(name)
	if err != nil {
		http.Error(w, "peer config not found: "+err.Error(), http.StatusNotFound)
		return
	}

	// 1. Try pure Go SVG generator first (encodes full .conf text directly without external dependencies)
	svgOut, qErr := generateQRCodeSVG(confStr)
	if qErr != nil {
		// 2. Fallback to qrencode CLI reading from stdin
		cmd := exec.Command("qrencode", "-t", "SVG", "-o", "-")
		cmd.Stdin = strings.NewReader(confStr)
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
	confStr, err := readAndRepairClientConf(name)
	if err != nil {
		http.Error(w, "peer config file not found", http.StatusNotFound)
		return
	}

	outBytes := []byte(confStr)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.conf\"", name))
	w.Header().Set("Content-Type", "application/x-wireguard-profile")
	w.Header().Set("Content-Length", strconv.Itoa(len(outBytes)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(outBytes)
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

	confStr, err := readAndRepairClientConf(user.WGPeer)
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
		"tunnel_ip":  extractTunnelIP(confStr),
		"conf":       confStr,
		"qr_svg_url": fmt.Sprintf("/api/wireguard/peers/%s/qr.svg", user.WGPeer),
	})
}

