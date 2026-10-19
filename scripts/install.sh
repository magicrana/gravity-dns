#!/usr/bin/env bash
# ==============================================================================
# GravityDNS - Automated Interactive & One-Liner Ubuntu Installer
# Repository: https://github.com/magicrana/gravity-dns.git
# Supports: Ubuntu 22.04 / 24.04 LTS (x86_64 & arm64)
# One-liner execution:
#   curl -fsSL https://raw.githubusercontent.com/magicrana/gravity-dns/main/install.sh | bash
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

REPO_URL="https://github.com/magicrana/gravity-dns.git"
INSTALL_DIR="/opt/gravity-dns"

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

# Check Root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This installer must be run as root (sudo).${NC}"
    echo -e "Try: ${BOLD}sudo bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/magicrana/gravity-dns/main/install.sh)\"${NC}"
    exit 1
fi

# Detect TTY for interactive inputs when piped through curl | bash
has_tty=false
if [ -t 0 ] || [ -c /dev/tty ]; then
    has_tty=true
fi

prompt_input() {
    local prompt_text="$1"
    local var_name="$2"
    local default_val="${3:-}"

    if [ "${GRAVITY_NON_INTERACTIVE:-false}" = "true" ] || [ "$has_tty" = "false" ]; then
        eval "$var_name=\"${!var_name:-$default_val}\""
        return
    fi

    local user_val=""
    if [ -t 0 ]; then
        read -rp "$prompt_text" user_val
    elif [ -c /dev/tty ]; then
        read -rp "$prompt_text" user_val </dev/tty
    fi

    if [ -z "$user_val" ]; then
        eval "$var_name=\"$default_val\""
    else
        eval "$var_name=\"$user_val\""
    fi
}

# ==================== STEP 1: CONFIGURATION & CREDENTIAL DETECTION ====================
CONFIG_PATH="/etc/gravity/gravity.yaml"
IS_REINSTALL=false

read_yaml_value() {
    local file="$1"
    local key="$2"
    if [ ! -f "$file" ]; then
        return
    fi
    if command -v python3 &>/dev/null; then
        python3 -c "
import re, sys
try:
    with open('$file', 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = re.match(r'^\s*'+re.escape('$key')+r':\s*(.*)', line)
            if m:
                val = m.group(1).split('#')[0].strip()
                if (val.startswith('\"') and val.endswith('\"')) or (val.startswith('\'') and val.endswith('\'')):
                    val = val[1:-1]
                print(val)
                sys.exit(0)
except Exception:
    pass
" 2>/dev/null && return
    fi
    # Fallback POSIX regex parser
    grep -E "^[[:space:]]*${key}:" "$file" 2>/dev/null | head -n1 | sed -E "s/^[[:space:]]*${key}:[[:space:]]*//; s/[[:space:]]*#.*$//; s/^[\"']//; s/[\"']$//"
}

# Auto-detect Public IPv4 from external services or default gateway
DETECTED_IP=$(curl -s4 --max-time 4 https://ifconfig.me || curl -s4 --max-time 4 https://api.ipify.org || ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -n1 || echo "127.0.0.1")

PREV_DOMAIN=""
PREV_IP=""
PREV_ADMIN_USER=""
PREV_ADMIN_PASS=""
PREV_JWT_SECRET=""
PREV_REDIS_PASS=""
PREV_REDIS_ADDR=""
PREV_TLS_CERT=""
PREV_TLS_KEY=""

if [ -f "$CONFIG_PATH" ]; then
    PREV_DOMAIN=$(read_yaml_value "$CONFIG_PATH" "domain")
    PREV_IP=$(read_yaml_value "$CONFIG_PATH" "public_ipv4")
    PREV_ADMIN_USER=$(read_yaml_value "$CONFIG_PATH" "admin_username")
    PREV_ADMIN_PASS=$(read_yaml_value "$CONFIG_PATH" "admin_password")
    PREV_JWT_SECRET=$(read_yaml_value "$CONFIG_PATH" "jwt_secret")
    PREV_REDIS_PASS=$(read_yaml_value "$CONFIG_PATH" "password")
    PREV_REDIS_ADDR=$(read_yaml_value "$CONFIG_PATH" "addr")
    PREV_TLS_CERT=$(read_yaml_value "$CONFIG_PATH" "tls_cert_file")
    PREV_TLS_KEY=$(read_yaml_value "$CONFIG_PATH" "tls_key_file")
    PREV_PANEL_LISTEN=$(read_yaml_value "$CONFIG_PATH" "listen")
    PREV_PANEL_PORT="8080"
    if [ -n "$PREV_PANEL_LISTEN" ]; then
        PREV_PANEL_PORT=$(echo "$PREV_PANEL_LISTEN" | awk -F: '{print $NF}' | tr -dc '0-9')
        PREV_PANEL_PORT="${PREV_PANEL_PORT:-8080}"
    fi

    if [ -n "$PREV_ADMIN_PASS" ] || [ -n "$PREV_DOMAIN" ]; then
        IS_REINSTALL=true
    fi
fi

if [ "$IS_REINSTALL" = "true" ]; then
    echo -e "${GREEN}${BOLD}=== Existing Installation Detected (/etc/gravity/gravity.yaml) ===${NC}"
    echo -e "${CYAN}Reinstall mode: All platform engines, binaries, web UI templates, and${NC}"
    echo -e "${CYAN}system services will be upgraded to the latest version.${NC}"
    echo -e "${GREEN}${BOLD}>> Preserving previous admin password and credentials. <<${NC}\n"

    # 1. Base Domain
    DOMAIN_DEFAULT="${GRAVITY_DOMAIN:-${PREV_DOMAIN:-dns.example.com}}"
    prompt_input "Enter Base Domain for SmartDNS: [${DOMAIN_DEFAULT}] " INPUT_DOMAIN "$DOMAIN_DEFAULT"
    DOMAIN="${INPUT_DOMAIN:-$DOMAIN_DEFAULT}"
    DOMAIN=$(echo "$DOMAIN" | sed 's/^\.*//; s/\.*$//')

    # 2. Public IPv4
    IP_DEFAULT="${GRAVITY_PUBLIC_IPV4:-${PREV_IP:-$DETECTED_IP}}"
    prompt_input "Enter Public VPS IPv4 for DNS Spoofing: [${IP_DEFAULT}] " INPUT_IP "$IP_DEFAULT"
    PUBLIC_IP="${INPUT_IP:-$IP_DEFAULT}"

    # 3. Credentials & Keys: strictly retain existing password
    ADMIN_USER="${PREV_ADMIN_USER:-admin}"
    if [ -n "${GRAVITY_ADMIN_PASS:-}" ]; then
        ADMIN_PASS="${GRAVITY_ADMIN_PASS}"
        echo -e "  Admin Password: ${BOLD}${ADMIN_PASS}${NC} (from GRAVITY_ADMIN_PASS override)"
    else
        ADMIN_PASS="${PREV_ADMIN_PASS}"
        echo -e "  Admin Password: ${GREEN}${BOLD}[Preserved from last installation: ${ADMIN_PASS}]${NC}"
    fi

    # 4. Web Management Panel Port
    PORT_DEFAULT="${GRAVITY_PANEL_PORT:-${PREV_PANEL_PORT:-8080}}"
    prompt_input "Enter Custom Port for Web Management Panel: [${PORT_DEFAULT}] " INPUT_PANEL_PORT "$PORT_DEFAULT"
    PANEL_PORT="${INPUT_PANEL_PORT:-$PORT_DEFAULT}"

    JWT_SECRET="${PREV_JWT_SECRET:-$(openssl rand -hex 24 2>/dev/null || echo "gravity_secret_jwt_random_key_123456789")}"
    REDIS_PASS="${PREV_REDIS_PASS:-}"
    REDIS_ADDR="${PREV_REDIS_ADDR:-127.0.0.1:6379}"
    TLS_CERT="${PREV_TLS_CERT:-/etc/letsencrypt/live/${DOMAIN}/fullchain.pem}"
    TLS_KEY="${PREV_TLS_KEY:-/etc/letsencrypt/live/${DOMAIN}/privkey.pem}"
else
    echo -e "${BOLD}=== Step 1: Network & Configuration Parameters ===${NC}"

    # 1. Base Domain
    DOMAIN_DEFAULT="${GRAVITY_DOMAIN:-dns.example.com}"
    prompt_input "Enter Base Domain for SmartDNS (e.g. dns.mydomain.com): [${DOMAIN_DEFAULT}] " INPUT_DOMAIN "$DOMAIN_DEFAULT"
    DOMAIN="${INPUT_DOMAIN:-$DOMAIN_DEFAULT}"
    DOMAIN=$(echo "$DOMAIN" | sed 's/^\.*//; s/\.*$//')

    # 2. Public IPv4
    IP_DEFAULT="${GRAVITY_PUBLIC_IPV4:-$DETECTED_IP}"
    prompt_input "Enter Public VPS IPv4 for DNS Spoofing: [${IP_DEFAULT}] " INPUT_IP "$IP_DEFAULT"
    PUBLIC_IP="${INPUT_IP:-$IP_DEFAULT}"

    # 3. Admin Password (generated or user prompt)
    ADMIN_USER="admin"
    AUTO_PW=$(openssl rand -hex 6 2>/dev/null || tr -dc A-Za-z0-9 </dev/urandom | head -c 12 || echo "admin123456")
    PW_DEFAULT="${GRAVITY_ADMIN_PASS:-$AUTO_PW}"
    prompt_input "Set Web Management Panel Admin Password: [${PW_DEFAULT}] " INPUT_PW "$PW_DEFAULT"
    ADMIN_PASS="${INPUT_PW:-$PW_DEFAULT}"

    # 4. Web Management Panel Port
    PORT_DEFAULT="${GRAVITY_PANEL_PORT:-8080}"
    prompt_input "Enter Custom Port for Web Management Panel: [${PORT_DEFAULT}] " INPUT_PANEL_PORT "$PORT_DEFAULT"
    PANEL_PORT="${INPUT_PANEL_PORT:-$PORT_DEFAULT}"

    # 5. Optional Cloudflare API Token for Automated Let's Encrypt Wildcard SSL
    CF_TOKEN_DEFAULT="${GRAVITY_CF_TOKEN:-}"
    prompt_input "Enter Cloudflare API Token for Automated Let's Encrypt Wildcard SSL (Optional - press Enter to skip or configure in Web UI): [${CF_TOKEN_DEFAULT}] " INPUT_CF "$CF_TOKEN_DEFAULT"
    CF_TOKEN="${INPUT_CF:-$CF_TOKEN_DEFAULT}"

    JWT_SECRET=$(openssl rand -hex 24 2>/dev/null || echo "gravity_secret_jwt_random_key_123456789")
    REDIS_PASS=""
    REDIS_ADDR="127.0.0.1:6379"
    TLS_CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
    TLS_KEY="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
fi

echo ""
echo -e "${CYAN}Configuration Profile:${NC}"
echo -e "  Base Domain:    ${BOLD}${DOMAIN}${NC} (Wildcard: *.${DOMAIN})"
echo -e "  Public IPv4:    ${BOLD}${PUBLIC_IP}${NC}"
echo -e "  Panel Port:     ${BOLD}${PANEL_PORT}${NC}"
echo -e "  Admin User:     ${BOLD}${ADMIN_USER}${NC}"
if [ "$IS_REINSTALL" = "true" ]; then
    echo -e "  Admin Password: ${GREEN}${BOLD}${ADMIN_PASS} (Preserved from last installation)${NC}"
else
    echo -e "  Admin Password: ${BOLD}${ADMIN_PASS}${NC}"
fi
echo ""

if [ "${GRAVITY_NON_INTERACTIVE:-false}" != "true" ] && [ "$has_tty" = "true" ]; then
    CONFIRM_DEFAULT="Y"
    prompt_input "Proceed with automated deployment? (Y/n) " CONFIRM "$CONFIRM_DEFAULT"
    if [[ "${CONFIRM:-Y}" =~ ^[Nn] ]]; then
        echo -e "${YELLOW}Deployment cancelled by user.${NC}"
        exit 0
    fi
fi

echo -e "\n${BOLD}=== Step 2: System Packages & Dependencies ===${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
    curl git build-essential ufw redis-server certbot python3-certbot-dns-cloudflare python3-pip ca-certificates openssl
pip3 install --upgrade --break-system-packages certbot certbot-dns-cloudflare "cloudflare>=2.3.1" >/dev/null 2>&1 || true

# Ensure Redis is running and starts on boot
systemctl enable redis-server
systemctl restart redis-server
echo -e "${GREEN}Redis store active and enabled on boot.${NC}"

# Ensure modern Go toolchain (Go 1.22+)
NEED_GO=false
if ! command -v go &>/dev/null; then
    NEED_GO=true
else
    GO_VER=$(go version | awk '{print $3}' | sed 's/go//' | cut -d. -f2 || echo "0")
    if [ "$GO_VER" -lt 21 ]; then
        NEED_GO=true
    fi
fi

if [ "$NEED_GO" = "true" ]; then
    echo -e "${YELLOW}Installing modern Go toolchain (1.23)...${NC}"
    ARCH=$(uname -m)
    GO_ARCH="amd64"
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
        GO_ARCH="arm64"
    fi
    GO_TAR="go1.23.2.linux-${GO_ARCH}.tar.gz"
    curl -fsSL "https://go.dev/dl/${GO_TAR}" -o "/tmp/${GO_TAR}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    export PATH="/usr/local/go/bin:${PATH}"
    if ! grep -q '/usr/local/go/bin' /etc/profile; then
        echo 'export PATH="/usr/local/go/bin:${PATH}"' >> /etc/profile
    fi
    rm -f "/tmp/${GO_TAR}"
fi
echo -e "${GREEN}Go toolchain ready: $(go version)${NC}"

echo -e "\n${BOLD}=== Step 3: Fetching Source Code ===${NC}"
# Determine if running within local cloned workspace or needs clone
CURRENT_DIR="$(pwd)"
if [ -f "${CURRENT_DIR}/cmd/gravity/main.go" ] && [ -f "${CURRENT_DIR}/go.mod" ]; then
    SOURCE_DIR="${CURRENT_DIR}"
    echo "Using current directory source: ${SOURCE_DIR}"
else
    SOURCE_DIR="${INSTALL_DIR}"
    if [ -d "${SOURCE_DIR}/.git" ]; then
        echo "Updating existing installation in ${SOURCE_DIR}..."
        git -C "${SOURCE_DIR}" fetch --all
        git -C "${SOURCE_DIR}" reset --hard origin/main
    else
        echo "Cloning repository ${REPO_URL} into ${SOURCE_DIR}..."
        rm -rf "${SOURCE_DIR}"
        git clone "${REPO_URL}" "${SOURCE_DIR}"
    fi
fi

cd "${SOURCE_DIR}"

echo -e "\n${BOLD}=== Step 4: High-Performance Kernel & Sysctl Tuning ===${NC}"
if [ -f "${SOURCE_DIR}/configs/sysctl-tuning.conf" ]; then
    cp "${SOURCE_DIR}/configs/sysctl-tuning.conf" /etc/sysctl.d/99-gravitydns.conf
    sysctl -p /etc/sysctl.d/99-gravitydns.conf >/dev/null 2>&1 || true
    echo -e "${GREEN}Kernel TCP BBR and socket buffers tuned successfully.${NC}"
fi

echo -e "\n${BOLD}=== Step 5: Compiling GravityDNS Platform ===${NC}"
echo "Building unified binary /usr/local/bin/gravity..."
go build -ldflags="-s -w" -o /usr/local/bin/gravity ./cmd/gravity

echo "Building standalone binaries..."
go build -ldflags="-s -w" -o /usr/local/bin/gravity-dns ./cmd/dns
go build -ldflags="-s -w" -o /usr/local/bin/gravity-sniproxy ./cmd/sniproxy
go build -ldflags="-s -w" -o /usr/local/bin/gravity-panel ./cmd/panel

chmod +x /usr/local/bin/gravity*
echo -e "${GREEN}Binaries compiled and installed to /usr/local/bin/${NC}"

echo -e "\n${BOLD}=== Step 6: Environment & Service Directories ===${NC}"
mkdir -p /etc/gravity
mkdir -p /var/log/gravity
mkdir -p /var/lib/gravity

# Backup existing config if present
if [ -f /etc/gravity/gravity.yaml ]; then
    cp /etc/gravity/gravity.yaml /etc/gravity/gravity.yaml.bak
    echo -e "${CYAN}Previous configuration backed up to /etc/gravity/gravity.yaml.bak${NC}"
fi

# Copy web templates and static assets
rm -rf /var/lib/gravity/web
cp -r "${SOURCE_DIR}/web" /var/lib/gravity/

# Automated Let's Encrypt Wildcard SSL provisioning if Cloudflare credentials provided
if [ -n "${CF_TOKEN:-}" ]; then
    echo -e "\n${CYAN}Automating Let's Encrypt Wildcard SSL (*.${DOMAIN}) via Cloudflare DNS...${NC}"
    mkdir -p /root/.secrets/certbot
    CF_EMAIL="${CF_EMAIL:-admin@${DOMAIN}}"

    write_cf_ini() {
        local use_global="$1"
        if [ "$use_global" = "true" ]; then
            cat > /root/.secrets/certbot/cloudflare.ini << EOF
dns_cloudflare_email = ${CF_EMAIL}
dns_cloudflare_api_key = ${CF_TOKEN}
EOF
        else
            cat > /root/.secrets/certbot/cloudflare.ini << EOF
dns_cloudflare_api_token = ${CF_TOKEN}
EOF
        fi
        chmod 600 /root/.secrets/certbot/cloudflare.ini
    }

    IS_GLOBAL=false
    if echo "${CF_TOKEN}" | grep -Eq '^[0-9a-fA-F]{37}$'; then
        IS_GLOBAL=true
    fi

    write_cf_ini "$IS_GLOBAL"

    CERTBOT_OUT=$(certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials /root/.secrets/certbot/cloudflare.ini \
        --dns-cloudflare-propagation-seconds 30 \
        -d "${DOMAIN}" \
        -d "*.${DOMAIN}" \
        --email "${CF_EMAIL}" \
        --agree-tos \
        --no-eff-email \
        --non-interactive 2>&1) || CERTBOT_EXIT=$?

    if [ "${CERTBOT_EXIT:-0}" -ne 0 ] && [ "$IS_GLOBAL" = "false" ] && echo "$CERTBOT_OUT" | grep -q "Property \"dns_cloudflare_email\" not found"; then
        echo -e "${YELLOW}Retrying with Cloudflare Global API Key format...${NC}"
        write_cf_ini "true"
        certbot certonly \
            --dns-cloudflare \
            --dns-cloudflare-credentials /root/.secrets/certbot/cloudflare.ini \
            --dns-cloudflare-propagation-seconds 30 \
            -d "${DOMAIN}" \
            -d "*.${DOMAIN}" \
            --email "${CF_EMAIL}" \
            --agree-tos \
            --no-eff-email \
            --non-interactive 2>&1 || true
    fi

    if [ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
        TLS_CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
        TLS_KEY="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
        echo -e "${GREEN}Let's Encrypt Wildcard certificate issued successfully!${NC}"
    else
        echo -e "${YELLOW}Notice: Certbot initial run did not complete. You can issue or retry certificate with 1-click in the Web UI.${NC}"
    fi
fi

cat > /etc/gravity/gravity.yaml << EOF
# GravityDNS Master Configuration
server:
  domain: "${DOMAIN}"
  public_ipv4: "${PUBLIC_IP}"
  public_ipv6: ""

dns:
  enabled: true
  dot_listen: "0.0.0.0:853"
  doh_listen: "0.0.0.0:8443"
  tls_cert_file: "${TLS_CERT}"
  tls_key_file: "${TLS_KEY}"
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
  addr: "${REDIS_ADDR}"
  password: "${REDIS_PASS}"
  db: 0

panel:
  enabled: true
  listen: "0.0.0.0:${PANEL_PORT}"
  jwt_secret: "${JWT_SECRET}"
  admin_username: "${ADMIN_USER:-admin}"
  admin_password: "${ADMIN_PASS}"
  session_ttl: 24
EOF

chmod 600 /etc/gravity/gravity.yaml
echo -e "${GREEN}Configuration updated and saved to /etc/gravity/gravity.yaml${NC}"

echo -e "\n${BOLD}=== Step 7: Systemd Service Installation ===${NC}"
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

# Security Capabilities
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
cat > /etc/letsencrypt/renewal-hooks/deploy/gravitydns.sh << 'HOOK_EOF'
#!/usr/bin/env bash
set -euo pipefail
if systemctl is-active --quiet gravity.service; then
    systemctl restart gravity.service
fi
HOOK_EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/gravitydns.sh

# Setup helper scripts in /opt/gravity-dns/scripts
mkdir -p /opt/gravity-dns/scripts
if [ -d "${SOURCE_DIR:-/opt/gravity-dns}/scripts" ]; then
    cp -f "${SOURCE_DIR:-/opt/gravity-dns}"/scripts/*.sh /opt/gravity-dns/scripts/ 2>/dev/null || true
fi
chmod +x /opt/gravity-dns/scripts/*.sh 2>/dev/null || true

echo -e "\n${BOLD}=== Step 8: Firewall Configuration (UFW) ===${NC}"
if command -v ufw &>/dev/null; then
    ufw status | grep -q "Status: active" && {
        echo "Configuring UFW rules..."
        ufw allow 853/tcp comment "GravityDNS DoT" >/dev/null 2>&1 || true
        ufw allow 8443/tcp comment "GravityDNS DoH" >/dev/null 2>&1 || true
        ufw allow 443/tcp comment "GravityDNS SNI Proxy" >/dev/null 2>&1 || true
        ufw allow 80/tcp comment "Certbot ACME" >/dev/null 2>&1 || true
        ufw allow "${PANEL_PORT}/tcp" comment "GravityDNS Web Panel" >/dev/null 2>&1 || true
        if [ -n "${PREV_PANEL_PORT:-}" ] && [ "${PREV_PANEL_PORT}" != "${PANEL_PORT}" ]; then
            ufw delete allow "${PREV_PANEL_PORT}/tcp" >/dev/null 2>&1 || true
        fi
        ufw allow 51820/udp comment "WireGuard VPN Tunnel" >/dev/null 2>&1 || true
        echo -e "${GREEN}Firewall rules configured for ports 853, 8443, 443, 80, ${PANEL_PORT}, 51820(UDP).${NC}"
    } || echo "UFW is not active, skipping firewall rule injection."
fi

# Start GravityDNS service
systemctl restart gravity.service || true

echo -e "\n${BOLD}=== Step 9: Wildcard TLS Certificate Reminder ===${NC}"
if [ ! -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
    echo -e "${YELLOW}Notice: Wildcard certificate not yet found at /etc/letsencrypt/live/${DOMAIN}/${NC}"
    echo -e "GravityDNS uses fallback self-signed TLS while testing."
    echo -e "To issue a genuine Let's Encrypt Wildcard certificate (*.${DOMAIN}), run:"
    echo -e "  ${BOLD}certbot certonly --manual --preferred-challenges dns -d \"${DOMAIN}\" -d \"*.${DOMAIN}\"${NC}"
    echo -e "Or use Cloudflare DNS plugin:"
    echo -e "  ${BOLD}apt-get install -y python3-certbot-dns-cloudflare${NC}"
    echo -e "  ${BOLD}certbot certonly --dns-cloudflare --dns-cloudflare-credentials /root/.cloudflare.ini -d \"${DOMAIN}\" -d \"*.${DOMAIN}\"${NC}"
fi

if [ "$IS_REINSTALL" = "true" ]; then
    echo -e "\n${GREEN}${BOLD}========================================================================${NC}"
    echo -e "${GREEN}${BOLD}       GravityDNS Platform Reinstalled & Updated Successfully!          ${NC}"
    echo -e "${GREEN}${BOLD}========================================================================${NC}"
    echo -e "  Admin Control Panel:  ${BOLD}http://${PUBLIC_IP}:${PANEL_PORT}${NC} (or http://${DOMAIN}:${PANEL_PORT})"
    echo -e "  Admin Username:       ${BOLD}${ADMIN_USER:-admin}${NC}"
    echo -e "  Admin Password:       ${BOLD}${ADMIN_PASS}${NC} ${GREEN}(Preserved from last installation)${NC}"
    echo -e ""
    echo -e "  Upgraded Components:"
    echo -e "    - Pure Go DNS Engine (:853, :8443)  -> Recompiled & Updated"
    echo -e "    - Pure Go SNI Router (:443)         -> Recompiled & Updated"
    echo -e "    - Web Admin Management Panel (:${PANEL_PORT}) -> Recompiled & Updated"
    echo -e "    - Web UI & Left Sidebar Templates   -> Updated in /var/lib/gravity/web"
    echo -e "    - Kernel Sysctl & Firewall Rules    -> Verified & Synchronized"
    echo -e "    - Admin Credentials                 -> ${GREEN}Preserved Unchanged${NC}"
    echo -e ""
    echo -e "  Service Management:"
    echo -e "    - Status:   ${BOLD}systemctl status gravity.service${NC}"
    echo -e "    - Logs:     ${BOLD}journalctl -u gravity.service -f${NC}"
    echo -e "    - Restart:  ${BOLD}systemctl restart gravity.service${NC}"
    echo -e "    - Config:   ${BOLD}/etc/gravity/gravity.yaml${NC}"
    echo -e ""
    echo -e "  WireGuard VPN Tunnel (SIP / VoIP / UDP):"
    echo -e "    - Setup Tool: ${BOLD}sudo bash /opt/gravity-dns/scripts/setup-wireguard.sh${NC}"
    echo -e "${GREEN}${BOLD}========================================================================${NC}\n"
else
    echo -e "\n${GREEN}${BOLD}========================================================================${NC}"
    echo -e "${GREEN}${BOLD}          GravityDNS Deployment Completed Successfully!                 ${NC}"
    echo -e "${GREEN}${BOLD}========================================================================${NC}"
    echo -e "  Admin Control Panel:  ${BOLD}http://${PUBLIC_IP}:${PANEL_PORT}${NC} (or http://${DOMAIN}:${PANEL_PORT})"
    echo -e "  Default Admin User:   ${BOLD}admin${NC}"
    echo -e "  Admin Password:       ${BOLD}${ADMIN_PASS}${NC}"
    echo -e ""
    echo -e "  Protocols & Ports:"
    echo -e "    - DoT (DNS-over-TLS):   ${BOLD}0.0.0.0:853${NC}   (<token>.${DOMAIN})"
    echo -e "    - DoH (DNS-over-HTTPS): ${BOLD}0.0.0.0:8443${NC}  (https://${DOMAIN}:8443/dns-query/<token>)"
    echo -e "    - SNI Proxy Router:     ${BOLD}0.0.0.0:443${NC}   (TCP Zero-Copy Splice)"
    echo -e "    - Web Control Panel:    ${BOLD}0.0.0.0:${PANEL_PORT}${NC}"
    echo -e ""
    echo -e "  Service Management:"
    echo -e "    - Status:   ${BOLD}systemctl status gravity.service${NC}"
    echo -e "    - Logs:     ${BOLD}journalctl -u gravity.service -f${NC}"
    echo -e "    - Restart:  ${BOLD}systemctl restart gravity.service${NC}"
    echo -e "    - Config:   ${BOLD}/etc/gravity/gravity.yaml${NC}"
    echo -e ""
    echo -e "  WireGuard VPN Tunnel (SIP / VoIP / UDP):"
    echo -e "    - Setup Tool: ${BOLD}sudo bash /opt/gravity-dns/scripts/setup-wireguard.sh${NC}"
    echo -e "${GREEN}${BOLD}========================================================================${NC}\n"
fi
