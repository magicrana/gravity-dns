#!/usr/bin/env bash
# ==============================================================================
# GravityDNS - Automated Interactive Ubuntu 22.04 / 24.04 LTS Installer
# Builds and deploys High-Performance SmartDNS & SNI Proxy Platform
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
cat << 'EOF'
   ______                 _ __        ____  _   _______
  / ____/________ __   __(_) /___  __/ __ \/ | / / ___/
 / / __/ ___/ __ `/ | / / / __/ / / / / / /  |/ /\__ \ 
/ /_/ / /  / /_/ /| |/ / / /_/ /_/ / /_/ / /|  /___/ / 
\____/_/   \__,_/ |___/_/\__/\__, /_____/_/ |_//____/  
                            /____/                     
  High-Performance SmartDNS & SNI Proxy Platform (Go)
EOF
echo -e "${NC}"

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This installer must be executed as root (sudo).${NC}"
    exit 1
fi

# Detect Public IP
DETECTED_IP=$(curl -s4 --max-time 5 https://ifconfig.me || curl -s4 --max-time 5 https://api.ipify.org || ip route get 1.1.1.1 | awk '{print $7}' | head -n1)

echo -e "${BOLD}=== Step 1: Configuration Parameters ===${NC}"

# Domain prompt
DEFAULT_DOMAIN="${GRAVITY_DOMAIN:-dns.example.com}"
read -rp "Enter your Base Domain (e.g. dns.mydomain.com): [${DEFAULT_DOMAIN}] " USER_DOMAIN
DOMAIN="${USER_DOMAIN:-$DEFAULT_DOMAIN}"

# Public IP prompt
read -rp "Enter Public VPS IPv4 for DNS Spoofing: [${DETECTED_IP}] " USER_IP
PUBLIC_IP="${USER_IP:-$DETECTED_IP}"

# Admin Password prompt
DEFAULT_PW=$(openssl rand -hex 6 2>/dev/null || echo "admin123456")
read -rp "Set Web Panel Admin Password: [${DEFAULT_PW}] " USER_PW
ADMIN_PASS="${USER_PW:-$DEFAULT_PW}"

echo ""
echo -e "${CYAN}Configuration Summary:${NC}"
echo -e "  Base Domain: ${BOLD}${DOMAIN}${NC} (Wildcard: *.${DOMAIN})"
echo -e "  Public IPv4: ${BOLD}${PUBLIC_IP}${NC}"
echo -e "  Admin User:  ${BOLD}admin${NC}"
echo -e "  Admin Pass:  ${BOLD}${ADMIN_PASS}${NC}"
echo ""
read -rp "Proceed with automated installation? (Y/n) " CONFIRM
if [[ "${CONFIRM:-Y}" =~ ^[Nn] ]]; then
    echo -e "${YELLOW}Installation aborted.${NC}"
    exit 0
fi

echo -e "\n${BOLD}=== Step 2: System Packages & Dependencies ===${NC}"
apt-get update -y
apt-get install -y --no-install-recommends \
    curl git build-essential ufw redis-server certbot ca-certificates openssl

# Ensure Go 1.22+ is available
if ! command -v go &>/dev/null || [[ $(go version | awk '{print $3}' | sed 's/go//' | cut -d. -f2) -lt 21 ]]; then
    echo -e "${YELLOW}Installing modern Go toolchain...${NC}"
    GO_TAR="go1.23.2.linux-amd64.tar.gz"
    curl -fsSL "https://go.dev/dl/${GO_TAR}" -o "/tmp/${GO_TAR}"
    rm -rf /usr/local/go && tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    export PATH="/usr/local/go/bin:${PATH}"
    echo 'export PATH="/usr/local/go/bin:${PATH}"' >> /etc/profile
    rm -f "/tmp/${GO_TAR}"
fi

echo -e "${GREEN}Go toolchain: $(go version)${NC}"

# Configure and start Redis
systemctl enable redis-server
systemctl restart redis-server

echo -e "\n${BOLD}=== Step 3: Kernel Network & Sysctl Tuning ===${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [ -f "${PROJECT_ROOT}/configs/sysctl-tuning.conf" ]; then
    cp "${PROJECT_ROOT}/configs/sysctl-tuning.conf" /etc/sysctl.d/99-gravitydns.conf
    sysctl -p /etc/sysctl.d/99-gravitydns.conf || true
    echo -e "${GREEN}Sysctl TCP BBR and socket buffers tuned.${NC}"
fi

echo -e "\n${BOLD}=== Step 4: Compiling GravityDNS Binaries ===${NC}"
cd "${PROJECT_ROOT}"

echo "Building unified CLI binary: /usr/local/bin/gravity..."
go build -ldflags="-s -w" -o /usr/local/bin/gravity ./cmd/gravity

echo "Building standalone binaries..."
go build -ldflags="-s -w" -o /usr/local/bin/gravity-dns ./cmd/dns
go build -ldflags="-s -w" -o /usr/local/bin/gravity-sniproxy ./cmd/sniproxy
go build -ldflags="-s -w" -o /usr/local/bin/gravity-panel ./cmd/panel

chmod +x /usr/local/bin/gravity*
echo -e "${GREEN}Binaries successfully compiled to /usr/local/bin/${NC}"

echo -e "\n${BOLD}=== Step 5: Setting Up Environment & Directories ===${NC}"
mkdir -p /etc/gravity
mkdir -p /var/log/gravity
mkdir -p /var/lib/gravity/web

# Copy web templates to /var/lib/gravity/web
cp -r "${PROJECT_ROOT}/web" /var/lib/gravity/

# Generate /etc/gravity/gravity.yaml
JWT_SECRET=$(openssl rand -hex 24 2>/dev/null || echo "gravity_secret_token_123456789")

cat > /etc/gravity/gravity.yaml << EOF
server:
  domain: "${DOMAIN}"
  public_ipv4: "${PUBLIC_IP}"
  public_ipv6: ""

dns:
  enabled: true
  dot_listen: "0.0.0.0:853"
  doh_listen: "0.0.0.0:8443"
  tls_cert_file: "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
  tls_key_file: "/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
  upstream_dns:
    - "1.1.1.1:53"
    - "8.8.8.8:53"
  spoof_ttl: 60
  device_window_sec: 600

sniproxy:
  enabled: true
  listen: "0.0.0.0:443"
  upstream_dns:
    - "1.1.1.1:53"
    - "8.8.8.8:53"
  connect_timeout: 5
  idle_timeout: 300
  enforce_rules: true

redis:
  addr: "127.0.0.1:6379"
  password: ""
  db: 0

panel:
  enabled: true
  listen: "0.0.0.0:8080"
  jwt_secret: "${JWT_SECRET}"
  admin_username: "admin"
  admin_password: "${ADMIN_PASS}"
  session_ttl: 24
EOF

chmod 600 /etc/gravity/gravity.yaml
echo -e "${GREEN}Configuration file created at /etc/gravity/gravity.yaml${NC}"

echo -e "\n${BOLD}=== Step 6: Systemd Service Installation ===${NC}"
cat > /etc/systemd/system/gravity.service << EOF
[Unit]
Description=GravityDNS SmartDNS and SNI Proxy Platform
After=network.target redis-server.service
Wants=redis-server.service

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/gravity
ExecStart=/usr/local/bin/gravity all -config /etc/gravity/gravity.yaml
Restart=always
RestartSec=3s
LimitNOFILE=1048576

# Security Sandbox
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_BIND_SERVICE

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable gravity.service

# Setup Certbot renewal hook
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cp "${PROJECT_ROOT}/scripts/certbot-hook.sh" /etc/letsencrypt/renewal-hooks/deploy/gravitydns.sh
chmod +x /etc/letsencrypt/renewal-hooks/deploy/gravitydns.sh

echo -e "\n${BOLD}=== Step 7: Firewall (UFW) Configuration ===${NC}"
if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    echo "Opening firewall ports (853, 8443, 443, 80, 8080)..."
    ufw allow 853/tcp comment "GravityDNS DoT"
    ufw allow 8443/tcp comment "GravityDNS DoH"
    ufw allow 443/tcp comment "GravityDNS SNI Proxy"
    ufw allow 80/tcp comment "Certbot ACME"
    ufw allow 8080/tcp comment "GravityDNS Web Panel"
fi

echo -e "\n${BOLD}=== Step 8: TLS Wildcard Certificate Setup ===${NC}"
if [ ! -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
    echo -e "${YELLOW}Notice: Wildcard certificate not yet present for *.${DOMAIN}.${NC}"
    echo -e "To acquire a free Let's Encrypt Wildcard certificate via DNS challenge, run:"
    echo -e "  ${BOLD}certbot certonly --manual --preferred-challenges dns -d \"${DOMAIN}\" -d \"*.${DOMAIN}\"${NC}"
    echo -e "Or use Cloudflare DNS plugin: ${BOLD}apt-get install python3-certbot-dns-cloudflare${NC}"
fi

# Start service
systemctl restart gravity.service || true

echo -e "\n${GREEN}${BOLD}================================================================${NC}"
echo -e "${GREEN}${BOLD}        GravityDNS Installation Completed Successfully!         ${NC}"
echo -e "${GREEN}${BOLD}================================================================${NC}"
echo -e "  Admin Control Panel:  ${BOLD}http://${PUBLIC_IP}:8080${NC} (or http://${DOMAIN}:8080)"
echo -e "  Username:             ${BOLD}admin${NC}"
echo -e "  Password:             ${BOLD}${ADMIN_PASS}${NC}"
echo -e ""
echo -e "  DNS-over-TLS (DoT):   ${BOLD}Port 853${NC} (<token>.${DOMAIN})"
echo -e "  DNS-over-HTTPS (DoH): ${BOLD}https://${DOMAIN}:8443/dns-query/<token>${NC}"
echo -e "  SNI Stream Proxy:     ${BOLD}Port 443${NC} (TCP Zero-Copy)"
echo -e ""
echo -e "  Manage Service:       ${BOLD}systemctl status gravity.service${NC}"
echo -e "  Live Logs:            ${BOLD}journalctl -u gravity.service -f${NC}"
echo -e "  CLI Control:          ${BOLD}gravity --help${NC}"
echo -e "${GREEN}${BOLD}================================================================${NC}\n"
EOF
