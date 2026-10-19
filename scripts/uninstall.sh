#!/usr/bin/env bash
# ==============================================================================
# GravityDNS - Complete Platform Uninstaller
# Safely tears down and removes all GravityDNS services, binaries, configs,
# Redis state, sysctl tuning, firewall rules, and optional WireGuard tunnels.
# ==============================================================================

set -euo pipefail

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

# Check for non-interactive / force flag
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
        --delete-certs)
            REMOVE_CERTS=true
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This uninstaller must be run as root (sudo).${NC}"
    exit 1
fi

echo -e "${RED}${BOLD}"
echo "========================================================================"
echo "          GravityDNS - Complete System Uninstallation Utility           "
echo "========================================================================"
echo -e "${NC}"
echo -e "${YELLOW}This script will permanently remove:${NC}"
echo "  - GravityDNS systemd service (gravity.service)"
echo "  - All compiled binaries (/usr/local/bin/gravity*)"
echo "  - Configuration directory (/etc/gravity)"
echo "  - Web assets & data (/var/lib/gravity)"
echo "  - Query log files (/var/log/gravity)"
echo "  - Cloned installation sources (/opt/gravity-dns)"
echo "  - Certbot renewal deploy hooks (/etc/letsencrypt/renewal-hooks/deploy/gravitydns.sh)"
echo "  - Kernel sysctl tuning (/etc/sysctl.d/99-gravitydns.conf)"
echo "  - Associated firewall rules (ports 853, 8443, 443, 8080)"
echo ""

if [ "$FORCE" != "true" ]; then
    read -rp "Are you sure you want to completely uninstall GravityDNS? [y/N]: " CONFIRM
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
    if systemctl is-active --quiet wg-quick@wg0 2>/dev/null || [ -f "/etc/wireguard/wg0.conf" ]; then
        read -rp "WireGuard tunnel detected. Do you want to remove WireGuard configuration & service too? [Y/n]: " WG_CONFIRM
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
        read -rp "Do you want to purge GravityDNS keys/sessions from Redis? [Y/n]: " REDIS_CONFIRM
        case "$REDIS_CONFIRM" in
            [nN]|[nN][oO])
                PURGE_REDIS=false
                ;;
            *)
                PURGE_REDIS=true
                ;;
        esac
    fi
fi

# ==================== STEP 1: STOP SERVICES ====================
echo -e "\n${CYAN}Step 1: Stopping and disabling systemd services...${NC}"

if systemctl is-active --quiet gravity.service 2>/dev/null; then
    echo "  - Stopping gravity.service..."
    systemctl stop gravity.service || true
fi
if systemctl is-enabled --quiet gravity.service 2>/dev/null; then
    echo "  - Disabling gravity.service..."
    systemctl disable gravity.service || true
fi
rm -f /etc/systemd/system/gravity.service

if [ "$REMOVE_WG" = "true" ]; then
    if systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
        echo "  - Stopping WireGuard wg-quick@wg0..."
        systemctl stop wg-quick@wg0 || true
    fi
    if systemctl is-enabled --quiet wg-quick@wg0 2>/dev/null; then
        echo "  - Disabling WireGuard wg-quick@wg0..."
        systemctl disable wg-quick@wg0 || true
    fi
fi

systemctl daemon-reload
echo -e "${GREEN}[OK] Services stopped and unregistered.${NC}"

# ==================== STEP 2: KILL ORPHAN PROCESSES ====================
echo -e "\n${CYAN}Step 2: Checking for running Gravity processes...${NC}"
pkill -9 -f "/usr/local/bin/gravity" 2>/dev/null || true
pkill -9 -f "gravity all" 2>/dev/null || true
pkill -9 -f "gravity-dns" 2>/dev/null || true
pkill -9 -f "gravity-sniproxy" 2>/dev/null || true
pkill -9 -f "gravity-panel" 2>/dev/null || true
echo -e "${GREEN}[OK] All processes terminated.${NC}"

# ==================== STEP 3: REMOVE COMPILED BINARIES ====================
echo -e "\n${CYAN}Step 3: Removing compiled binaries...${NC}"
rm -f /usr/local/bin/gravity
rm -f /usr/local/bin/gravity-dns
rm -f /usr/local/bin/gravity-sniproxy
rm -f /usr/local/bin/gravity-panel
echo -e "${GREEN}[OK] Binaries removed from /usr/local/bin/.${NC}"

# ==================== STEP 4: REMOVE DIRECTORIES & CONFIGS ====================
echo -e "\n${CYAN}Step 4: Deleting application directories and configurations...${NC}"

# Detect configured panel port before deleting configuration
CONFIGURED_PANEL_PORT="8080"
if [ -f "/etc/gravity/gravity.yaml" ]; then
    CONFIG_LISTEN=$(grep -E '^[[:space:]]*listen:' /etc/gravity/gravity.yaml 2>/dev/null | tail -n1 | sed -E 's/^[[:space:]]*listen:[[:space:]]*//; s/[[:space:]]*#.*$//; s/^["\x27]//; s/["\x27]$//' | tr -d '[:space:]')
    if [ -n "$CONFIG_LISTEN" ]; then
        DETECTED_PORT=$(echo "$CONFIG_LISTEN" | awk -F: '{print $NF}' | tr -dc '0-9')
        if [ -n "$DETECTED_PORT" ]; then
            CONFIGURED_PANEL_PORT="$DETECTED_PORT"
        fi
    fi
fi

# Backup config just in case if not in force mode
if [ -f "/etc/gravity/gravity.yaml" ] && [ "$FORCE" != "true" ]; then
    cp "/etc/gravity/gravity.yaml" "/root/gravity.yaml.uninstalled.bak" 2>/dev/null || true
    echo -e "  - A final safety backup was saved to: ${BOLD}/root/gravity.yaml.uninstalled.bak${NC}"
fi

rm -rf /etc/gravity
rm -rf /var/lib/gravity
rm -rf /var/log/gravity
rm -rf /opt/gravity-dns

rm -f /etc/letsencrypt/renewal-hooks/deploy/gravitydns.sh
rm -f /etc/sysctl.d/99-gravitydns.conf
rm -f /etc/sysctl.d/99-gravity-tuning.conf

if [ "$REMOVE_WG" = "true" ]; then
    rm -f /etc/sysctl.d/99-wireguard.conf
    rm -rf /etc/wireguard
fi

echo -e "${GREEN}[OK] Directories and configuration files removed.${NC}"

# ==================== STEP 5: PURGE REDIS DATA ====================
if [ "$PURGE_REDIS" = "true" ] && command -v redis-cli &>/dev/null; then
    echo -e "\n${CYAN}Step 5: Purging GravityDNS keys from Redis...${NC}"
    # Delete specific GravityDNS keys
    redis-cli --scan --pattern 'user:*' 2>/dev/null | xargs -r redis-cli del >/dev/null 2>&1 || true
    redis-cli --scan --pattern 'token:*' 2>/dev/null | xargs -r redis-cli del >/dev/null 2>&1 || true
    redis-cli --scan --pattern 'rule:*' 2>/dev/null | xargs -r redis-cli del >/dev/null 2>&1 || true
    redis-cli --scan --pattern 'stats:*' 2>/dev/null | xargs -r redis-cli del >/dev/null 2>&1 || true
    redis-cli --scan --pattern 'queries:*' 2>/dev/null | xargs -r redis-cli del >/dev/null 2>&1 || true
    redis-cli del "admin:profile" 2>/dev/null || true
    echo -e "${GREEN}[OK] GravityDNS keys purged from Redis.${NC}"
fi

# ==================== STEP 6: CLEAN FIREWALL RULES ====================
if command -v ufw &>/dev/null; then
    echo -e "\n${CYAN}Step 6: Cleaning UFW firewall rules...${NC}"
    ufw delete allow 853/tcp >/dev/null 2>&1 || true
    ufw delete allow 8443/tcp >/dev/null 2>&1 || true
    ufw delete allow 443/tcp >/dev/null 2>&1 || true
    ufw delete allow 8080/tcp >/dev/null 2>&1 || true
    if [ "$CONFIGURED_PANEL_PORT" != "8080" ]; then
        ufw delete allow "${CONFIGURED_PANEL_PORT}/tcp" >/dev/null 2>&1 || true
    fi
    if [ "$REMOVE_WG" = "true" ]; then
        ufw delete allow 51820/udp >/dev/null 2>&1 || true
    fi
    echo -e "${GREEN}[OK] Firewall rules cleaned (ports 853, 8443, 443, 8080, ${CONFIGURED_PANEL_PORT}).${NC}"
fi

# ==================== STEP 7: RESTORE KERNEL SYSCTL ====================
echo -e "\n${CYAN}Step 7: Re-applying system sysctl settings...${NC}"
sysctl --system >/dev/null 2>&1 || true
echo -e "${GREEN}[OK] Sysctl state reloaded.${NC}"

# ==================== STEP 8: VERIFY PORT RELEASES ====================
echo -e "\n${CYAN}Step 8: Verifying port availability...${NC}"
CHECK_PORTS=(853 8443 443 8080)
if [ "$CONFIGURED_PANEL_PORT" != "8080" ]; then
    CHECK_PORTS+=("$CONFIGURED_PANEL_PORT")
fi
for PORT in "${CHECK_PORTS[@]}"; do
    if command -v ss &>/dev/null; then
        if ss -tlnp | grep -q ":${PORT} "; then
            echo -e "  - ${YELLOW}Warning: Port ${PORT} still in use by another process:${NC}"
            ss -tlnp | grep ":${PORT} " || true
        else
            echo -e "  - Port ${PORT}: ${GREEN}Free${NC}"
        fi
    fi
done

echo -e "\n${GREEN}${BOLD}========================================================================${NC}"
echo -e "${GREEN}${BOLD}       GravityDNS has been completely uninstalled from this system!     ${NC}"
echo -e "${GREEN}${BOLD}========================================================================${NC}"
echo -e "  - All services stopped and deleted."
echo -e "  - All compiled binaries removed."
echo -e "  - Configuration, templates, and log directories erased."
echo -e "  - Firewall ports restored."
echo -e "${GREEN}${BOLD}========================================================================${NC}\n"
