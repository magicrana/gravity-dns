#!/usr/bin/env bash
# ==============================================================================
# GravityDNS - Complete Platform Uninstaller
# Safely tears down and removes all GravityDNS services, binaries, configs,
# Redis state, sysctl tuning, firewall rules, and optional WireGuard tunnels.
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Self-relocation: if running from inside /opt/gravity-dns or /etc/gravity,
# copy script to /tmp and re-execute. This guarantees that deleting
# /opt/gravity-dns will not truncate this script during execution or lock the CWD.
# ------------------------------------------------------------------------------
SELF_PATH="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"
if [[ "$SELF_PATH" == /opt/gravity-dns/* ]] || [[ "$PWD" == /opt/gravity-dns* ]] || [[ "$SELF_PATH" == /etc/gravity/* ]]; then
    TMP_EXEC="/tmp/gravity_uninstall_exec_$$.sh"
    cp -f "$SELF_PATH" "$TMP_EXEC"
    chmod +x "$TMP_EXEC"
    cd /tmp
    exec bash "$TMP_EXEC" "$@"
fi

# Trap to remove any temporary execution script on exit
trap 'rm -f /tmp/gravity_uninstall_exec_$$.sh /tmp/gravity_uninstall_exec_*.sh 2>/dev/null || true' EXIT

# Always switch working directory out of /opt/gravity-dns to avoid directory locking
cd /tmp

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

FORCE=false
PURGE_REDIS=true
REMOVE_WG=true
REMOVE_CERTS=false
FLUSH_ALL_REDIS=false

# Check for non-interactive / force flags
for arg in "$@"; do
    case "$arg" in
        -y|--yes|-f|--force)
            FORCE=true
            ;;
        --keep-wg)
            REMOVE_WG=false
            ;;
        --keep-redis)
            PURGE_REDIS=false
            ;;
        --flush-redis)
            FLUSH_ALL_REDIS=true
            ;;
        --delete-certs)
            REMOVE_CERTS=true
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This uninstaller must be run as root (sudo).${NC}"
    exit 1
fi

has_tty=false
if [ -t 0 ] || [ -c /dev/tty ]; then
    has_tty=true
fi

prompt_input() {
    local prompt_text="$1"
    local default_val="$2"
    local user_val=""

    if [ "$FORCE" = "true" ] || [ "$has_tty" = "false" ]; then
        echo "$default_val"
        return
    fi

    if [ -t 0 ]; then
        read -rp "$prompt_text" user_val
    elif [ -c /dev/tty ]; then
        read -rp "$prompt_text" user_val </dev/tty
    fi

    if [ -z "$user_val" ]; then
        echo "$default_val"
    else
        echo "$user_val"
    fi
}

echo -e "${RED}${BOLD}"
echo "========================================================================"
echo "          GravityDNS - Complete System Uninstallation Utility           "
echo "========================================================================"
echo -e "${NC}"
echo -e "${YELLOW}This uninstaller will completely purge:${NC}"
echo "  - GravityDNS systemd service (gravity.service)"
echo "  - All compiled binaries (/usr/local/bin/gravity*)"
echo "  - All configuration files (/etc/gravity)"
echo "  - Web assets & data (/var/lib/gravity)"
echo "  - Query log files (/var/log/gravity)"
echo "  - Cloned installation sources (/opt/gravity-dns)"
echo "  - Certbot renewal deploy hooks (/etc/letsencrypt/renewal-hooks/deploy/gravitydns.sh)"
echo "  - Kernel sysctl tuning (/etc/sysctl.d/99-gravitydns.conf, 99-gravity-tuning.conf)"
echo "  - Associated firewall rules (ports 853, 8443, 443, 8080)"
echo "  - WireGuard tunnel services & configurations (/etc/wireguard, wg-quick@wg0)"
echo "  - GravityDNS keys & sessions in Redis"
echo ""

if [ "$FORCE" != "true" ]; then
    CONFIRM=$(prompt_input "Are you sure you want to completely uninstall GravityDNS? [y/N]: " "N")
    case "$CONFIRM" in
        [yY]|[yY][eE][sS])
            echo ""
            ;;
        *)
            echo -e "${CYAN}Uninstallation cancelled.${NC}"
            exit 0
            ;;
    esac

    # Ask about WireGuard
    if systemctl is-active --quiet wg-quick@wg0 2>/dev/null || [ -d "/etc/wireguard" ]; then
        WG_CONFIRM=$(prompt_input "WireGuard tunnel detected. Remove WireGuard configuration, keys & service too? [Y/n]: " "Y")
        case "$WG_CONFIRM" in
            [nN]|[nN][oO])
                REMOVE_WG=false
                ;;
            *)
                REMOVE_WG=true
                ;;
        esac
    fi

    # Ask about Redis
    if command -v redis-cli &>/dev/null; then
        REDIS_CONFIRM=$(prompt_input "Purge all GravityDNS user keys and sessions from Redis? [Y/n]: " "Y")
        case "$REDIS_CONFIRM" in
            [nN]|[nN][oO])
                PURGE_REDIS=false
                ;;
            *)
                PURGE_REDIS=true
                ;;
        esac
    fi

    # Ask about Let's Encrypt certificates
    if [ -d "/etc/letsencrypt/live" ]; then
        CERT_CONFIRM=$(prompt_input "Delete Let's Encrypt certificates associated with GravityDNS? [y/N]: " "N")
        case "$CERT_CONFIRM" in
            [yY]|[yY][eE][sS])
                REMOVE_CERTS=true
                ;;
            *)
                REMOVE_CERTS=false
                ;;
        esac
    fi
fi

# Detect configured domain and panel port before deleting configuration
CONFIGURED_PANEL_PORT="8080"
CONFIGURED_DOMAIN=""
if [ -f "/etc/gravity/gravity.yaml" ]; then
    CONFIG_LISTEN=$(grep -E '^[[:space:]]*listen:' /etc/gravity/gravity.yaml 2>/dev/null | tail -n1 | sed -E 's/^[[:space:]]*listen:[[:space:]]*//; s/[[:space:]]*#.*$//; s/^["\x27]//; s/["\x27]$//' | tr -d '[:space:]')
    if [ -n "$CONFIG_LISTEN" ]; then
        DETECTED_PORT=$(echo "$CONFIG_LISTEN" | awk -F: '{print $NF}' | tr -dc '0-9')
        if [ -n "$DETECTED_PORT" ]; then
            CONFIGURED_PANEL_PORT="$DETECTED_PORT"
        fi
    fi
    CONFIGURED_DOMAIN=$(grep -E '^[[:space:]]*domain:' /etc/gravity/gravity.yaml 2>/dev/null | tail -n1 | sed -E 's/^[[:space:]]*domain:[[:space:]]*//; s/[[:space:]]*#.*$//; s/^["\x27]//; s/["\x27]$//' | tr -d '[:space:]')
fi

# ==================== STEP 1: STOP SERVICES ====================
echo -e "\n${CYAN}Step 1: Stopping and disabling systemd services...${NC}"

# Stop and disable GravityDNS service
systemctl stop gravity.service 2>/dev/null || true
systemctl disable gravity.service 2>/dev/null || true

# Wireguard service if requested
if [ "$REMOVE_WG" = "true" ]; then
    systemctl stop wg-quick@wg0.service 2>/dev/null || true
    systemctl disable wg-quick@wg0.service 2>/dev/null || true
    systemctl stop "wg-quick@*.service" 2>/dev/null || true
fi

# Unlink and remove systemd service unit files
rm -f /etc/systemd/system/gravity.service
rm -f /etc/systemd/system/multi-user.target.wants/gravity.service
rm -f /etc/systemd/system/gravity*.service
rm -f /etc/systemd/system/multi-user.target.wants/gravity*.service
rm -f /lib/systemd/system/gravity.service 2>/dev/null || true
rm -f /usr/lib/systemd/system/gravity.service 2>/dev/null || true

if [ "$REMOVE_WG" = "true" ]; then
    rm -f /etc/systemd/system/wg-quick@wg0.service 2>/dev/null || true
    rm -f /etc/systemd/system/multi-user.target.wants/wg-quick@wg0.service 2>/dev/null || true
fi

systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true
echo -e "${GREEN}[OK] Services stopped, disabled, and unregistered.${NC}"

# ==================== STEP 2: KILL PROCESSES & BRING DOWN INTERFACES ====================
echo -e "\n${CYAN}Step 2: Terminating running processes and interfaces...${NC}"

# Wireguard interface down
if [ "$REMOVE_WG" = "true" ]; then
    wg-quick down wg0 2>/dev/null || true
    ip link delete dev wg0 2>/dev/null || true
    iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null || true
fi

# Kill all platform processes
pkill -9 -f "/usr/local/bin/gravity" 2>/dev/null || true
pkill -9 -f "gravity all" 2>/dev/null || true
pkill -9 -f "gravity-dns" 2>/dev/null || true
pkill -9 -f "gravity-sniproxy" 2>/dev/null || true
pkill -9 -f "gravity-panel" 2>/dev/null || true
pkill -9 -f "cf-auth-hook.sh" 2>/dev/null || true
pkill -9 -f "cf-cleanup-hook.sh" 2>/dev/null || true
pkill -9 -f "setup-wireguard.sh" 2>/dev/null || true
pkill -9 -f "issue-ssl.sh" 2>/dev/null || true
echo -e "${GREEN}[OK] All processes terminated and network interfaces released.${NC}"

# ==================== STEP 3: REMOVE COMPILED BINARIES ====================
echo -e "\n${CYAN}Step 3: Removing compiled binaries and utilities...${NC}"
rm -f /usr/local/bin/gravity
rm -f /usr/local/bin/gravity-dns
rm -f /usr/local/bin/gravity-sniproxy
rm -f /usr/local/bin/gravity-panel
rm -f /usr/local/bin/gravity-uninstall
rm -f /usr/local/bin/gravity*
rm -f /usr/bin/gravity* 2>/dev/null || true
echo -e "${GREEN}[OK] Binaries removed from system PATH.${NC}"

# ==================== STEP 4: REMOVE DIRECTORIES & CONFIGS ====================
echo -e "\n${CYAN}Step 4: Completely deleting application directories and configurations...${NC}"

# Ensure we are not inside /opt/gravity-dns before deleting it
cd /tmp

rm -rf /etc/gravity
rm -rf /var/lib/gravity
rm -rf /var/log/gravity
rm -rf /opt/gravity-dns

rm -f /etc/letsencrypt/renewal-hooks/deploy/gravitydns.sh
rm -f /etc/sysctl.d/99-gravitydns.conf
rm -f /etc/sysctl.d/99-gravity-tuning.conf

# Temporary files & credentials
rm -rf /tmp/gravity*
rm -f /tmp/gravity_acme_records
rm -f /root/.secrets/certbot/cloudflare.ini
rmdir /root/.secrets/certbot 2>/dev/null || true

# Old backups from previous runs
rm -f /root/gravity.yaml.bak 2>/dev/null || true
rm -f /root/gravity.yaml.uninstalled.bak 2>/dev/null || true
rm -rf /root/gravity_backup* 2>/dev/null || true

if [ "$REMOVE_WG" = "true" ]; then
    rm -f /etc/sysctl.d/99-wireguard.conf
    rm -rf /etc/wireguard
fi

if [ "$REMOVE_CERTS" = "true" ] && [ -n "$CONFIGURED_DOMAIN" ]; then
    echo "  - Removing Let's Encrypt certificates for ${CONFIGURED_DOMAIN}..."
    certbot delete --cert-name "${CONFIGURED_DOMAIN}" --non-interactive 2>/dev/null || true
    rm -rf "/etc/letsencrypt/live/${CONFIGURED_DOMAIN}"* 2>/dev/null || true
    rm -rf "/etc/letsencrypt/archive/${CONFIGURED_DOMAIN}"* 2>/dev/null || true
    rm -f "/etc/letsencrypt/renewal/${CONFIGURED_DOMAIN}"*.conf 2>/dev/null || true
fi

echo -e "${GREEN}[OK] Directories, configuration files, and state storage completely erased.${NC}"

# ==================== STEP 5: PURGE REDIS DATA ====================
if [ "$PURGE_REDIS" = "true" ] && command -v redis-cli &>/dev/null; then
    echo -e "\n${CYAN}Step 5: Purging GravityDNS keys from Redis...${NC}"
    if [ "$FLUSH_ALL_REDIS" = "true" ]; then
        redis-cli flushdb >/dev/null 2>&1 || true
        echo -e "${GREEN}[OK] Redis database flushed completely.${NC}"
    else
        PATTERNS=(
            'user:*'
            'users:*'
            'token:*'
            'tokens:*'
            'rule:*'
            'rules:*'
            'stats:*'
            'queries:*'
            'devices:*'
            'admin:*'
            'wg:*'
            'gravity:*'
        )
        for pat in "${PATTERNS[@]}"; do
            redis-cli --scan --pattern "$pat" 2>/dev/null | xargs -r redis-cli del >/dev/null 2>&1 || true
        done
        redis-cli del "admin:profile" "users:all" "rules:all" >/dev/null 2>&1 || true
        echo -e "${GREEN}[OK] GravityDNS keys purged from Redis.${NC}"
    fi
fi

# ==================== STEP 6: CLEAN FIREWALL RULES ====================
if command -v ufw &>/dev/null; then
    echo -e "\n${CYAN}Step 6: Cleaning UFW firewall rules...${NC}"
    ufw delete allow 853/tcp >/dev/null 2>&1 || true
    ufw delete allow 8443/tcp >/dev/null 2>&1 || true
    ufw delete allow 443/tcp >/dev/null 2>&1 || true
    ufw delete allow 8080/tcp >/dev/null 2>&1 || true
    if [ -n "$CONFIGURED_PANEL_PORT" ] && [ "$CONFIGURED_PANEL_PORT" != "8080" ]; then
        ufw delete allow "${CONFIGURED_PANEL_PORT}/tcp" >/dev/null 2>&1 || true
    fi
    if [ "$REMOVE_WG" = "true" ]; then
        ufw delete allow 51820/udp >/dev/null 2>&1 || true
    fi
    echo -e "${GREEN}[OK] Firewall rules cleaned (ports 853, 8443, 443, 8080, ${CONFIGURED_PANEL_PORT}, 51820 UDP).${NC}"
fi

# ==================== STEP 7: RESTORE KERNEL SYSCTL ====================
echo -e "\n${CYAN}Step 7: Re-applying system sysctl settings...${NC}"
sysctl --system >/dev/null 2>&1 || true
echo -e "${GREEN}[OK] Sysctl state reloaded to operating system defaults.${NC}"

# ==================== STEP 8: VERIFY PORT RELEASES ====================
echo -e "\n${CYAN}Step 8: Verifying port availability & cleanup...${NC}"
CHECK_PORTS=(853 8443 443 8080)
if [ -n "$CONFIGURED_PANEL_PORT" ] && [ "$CONFIGURED_PANEL_PORT" != "8080" ]; then
    CHECK_PORTS+=("$CONFIGURED_PANEL_PORT")
fi
if [ "$REMOVE_WG" = "true" ]; then
    CHECK_PORTS+=(51820)
fi

ALL_CLEAR=true
for PORT in "${CHECK_PORTS[@]}"; do
    if command -v ss &>/dev/null; then
        if ss -tulpn 2>/dev/null | grep -q ":${PORT} "; then
            echo -e "  - ${YELLOW}Warning: Port ${PORT} is still in use by another process:${NC}"
            ss -tulpn | grep ":${PORT} " || true
            ALL_CLEAR=false
        else
            echo -e "  - Port ${PORT}: ${GREEN}Free${NC}"
        fi
    fi
done

if [ "$ALL_CLEAR" = "true" ]; then
    echo -e "${GREEN}[OK] All platform ports released successfully.${NC}"
fi

echo -e "\n${GREEN}${BOLD}========================================================================${NC}"
echo -e "${GREEN}${BOLD}       GravityDNS has been completely uninstalled from this system!     ${NC}"
echo -e "${GREEN}${BOLD}========================================================================${NC}"
echo -e "  - All services stopped, disabled, and removed from systemd."
echo -e "  - All compiled binaries removed from PATH."
echo -e "  - Configuration, templates, logs, and /opt/gravity-dns erased."
echo -e "  - WireGuard tunnels & interfaces purged."
echo -e "  - Firewall ports & kernel sysctl settings restored."
echo -e "${GREEN}${BOLD}========================================================================${NC}\n"
