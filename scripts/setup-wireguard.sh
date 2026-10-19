#!/usr/bin/env bash
# ==============================================================================
# GravityDNS - WireGuard Tunnel Provisioner for VoIP, SIP Trunks & UDP Traffic
# Fully automated: installs WireGuard, configures NAT, peers, and QR codes.
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

WG_DIR="/etc/wireguard"
WG_CONF="${WG_DIR}/wg0.conf"
CLIENTS_DIR="${WG_DIR}/clients"
WG_PORT=51820
WG_SUBNET="10.66.66"
SERVER_IP="${WG_SUBNET}.1"

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This tool must be run as root (sudo).${NC}"
    exit 1
fi

# Detect default interface
get_default_iface() {
    local iface
    iface=$(ip -4 route ls | grep default | head -n1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
    if [ -z "$iface" ]; then
        iface=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | head -n1 | tr -d '[:space:]')
    fi
    echo "${iface:-eth0}"
}

# Detect public IPv4
get_public_ip() {
    local ip=""
    # Check gravity.yaml first
    if [ -f "/etc/gravity/gravity.yaml" ]; then
        ip=$(grep -E '^[[:space:]]*public_ipv4:' /etc/gravity/gravity.yaml 2>/dev/null | head -n1 | sed -E 's/^[[:space:]]*public_ipv4:[[:space:]]*//; s/[[:space:]]*#.*$//; s/^["\x27]//; s/["\x27]$//' | tr -d '[:space:]')
    fi
    if [ -z "$ip" ] || [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ip=$(curl -4s --max-time 3 https://api.ipify.org || curl -4s --max-time 3 https://icanhazip.com || true)
    fi
    if [ -z "$ip" ]; then
        ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -n1)
    fi
    echo "$ip"
}

# Install WireGuard packages
install_packages() {
    echo -e "${CYAN}Checking and installing WireGuard packages...${NC}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y --no-install-recommends wireguard wireguard-tools iptables qrencode curl >/dev/null 2>&1
    echo -e "${GREEN}[OK] WireGuard packages installed successfully.${NC}"
}

# Enable IPv4 forwarding
enable_forwarding() {
    echo -e "${CYAN}Enabling kernel packet forwarding (sysctl)...${NC}"
    mkdir -p /etc/sysctl.d
    cat > /etc/sysctl.d/99-wireguard.conf << 'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
    sysctl --system >/dev/null 2>&1 || sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    echo -e "${GREEN}[OK] Packet forwarding enabled.${NC}"
}

# Initialize WireGuard Server
init_server() {
    mkdir -p "$WG_DIR" "$CLIENTS_DIR"
    chmod 700 "$WG_DIR" "$CLIENTS_DIR"

    if [ ! -f "${WG_DIR}/server_private.key" ]; then
        echo -e "${CYAN}Generating WireGuard Server Cryptographic Keys...${NC}"
        wg genkey | tee "${WG_DIR}/server_private.key" | wg pubkey > "${WG_DIR}/server_public.key"
        chmod 600 "${WG_DIR}/server_private.key"
    fi

    local server_priv
    server_priv=$(cat "${WG_DIR}/server_private.key")
    local iface
    iface=$(get_default_iface)

    if [ ! -f "$WG_CONF" ]; then
        echo -e "${CYAN}Creating Server Configuration (${WG_CONF})...${NC}"
        cat > "$WG_CONF" << EOF
[Interface]
Address = ${SERVER_IP}/24
ListenPort = ${WG_PORT}
PrivateKey = ${server_priv}
SaveConfig = false

# NAT firewall forwarding rules
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ${iface} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ${iface} -j MASQUERADE
EOF
        chmod 600 "$WG_CONF"
    fi

    # Enable and start service
    systemctl enable wg-quick@wg0 >/dev/null 2>&1 || true
    systemctl restart wg-quick@wg0 || systemctl start wg-quick@wg0 || true
    echo -e "${GREEN}[OK] WireGuard server running on UDP port ${WG_PORT}.${NC}"
}

# Find next available client IP address
get_next_client_ip() {
    local i=2
    while [ "$i" -lt 254 ]; do
        local candidate="${WG_SUBNET}.${i}"
        if ! grep -q "${candidate}/32" "$WG_CONF" 2>/dev/null; then
            echo "$candidate"
            return
        fi
        i=$((i + 1))
    done
    echo "${WG_SUBNET}.254"
}

# Add a new client peer
add_client() {
    local client_name="$1"
    client_name=$(echo "$client_name" | tr -dc 'a-zA-Z0-9_-')

    if [ -z "$client_name" ]; then
        echo -e "${RED}[ERROR] Client name cannot be empty.${NC}"
        return 1
    fi

    if [ -f "${CLIENTS_DIR}/${client_name}.conf" ]; then
        echo -e "${YELLOW}[WARNING] Client '${client_name}' already exists.${NC}"
        show_client "$client_name"
        return 0
    fi

    local client_ip
    client_ip=$(get_next_client_ip)

    local client_priv client_pub
    client_priv=$(wg genkey)
    client_pub=$(echo "$client_priv" | wg pubkey)

    local server_pub
    server_pub=$(cat "${WG_DIR}/server_public.key")

    local pub_ip
    pub_ip=$(get_public_ip)
    if [ -z "$pub_ip" ]; then
        pub_ip="YOUR_SERVER_IP"
    fi

    # Append peer to server wg0.conf
    cat >> "$WG_CONF" << EOF

# Client: ${client_name}
[Peer]
PublicKey = ${client_pub}
AllowedIPs = ${client_ip}/32
EOF

    # Generate client config file
    cat > "${CLIENTS_DIR}/${client_name}.conf" << EOF
[Interface]
PrivateKey = ${client_priv}
Address = ${client_ip}/32
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = ${server_pub}
Endpoint = ${pub_ip}:${WG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    chmod 600 "${CLIENTS_DIR}/${client_name}.conf"

    # Reload server live peers without terminating active connections
    wg syncconf wg0 <(wg-quick strip wg0) >/dev/null 2>&1 || systemctl restart wg-quick@wg0 || true

    echo -e "\n${GREEN}${BOLD}[SUCCESS] Client '${client_name}' created successfully!${NC}"
    echo -e "  Assigned Tunnel IP:  ${BOLD}${client_ip}${NC}"
    echo -e "  Config File Saved:   ${BOLD}${CLIENTS_DIR}/${client_name}.conf${NC}\n"

    show_client "$client_name"
}

# Display client config and QR code
show_client() {
    local client_name="$1"
    local conf_file="${CLIENTS_DIR}/${client_name}.conf"

    if [ ! -f "$conf_file" ]; then
        echo -e "${RED}[ERROR] Client config not found at ${conf_file}.${NC}"
        return 1
    fi

    echo -e "${CYAN}${BOLD}========================================================================${NC}"
    echo -e "${CYAN}${BOLD}       WireGuard Peer: ${client_name} (Scan QR with WireGuard App)       ${NC}"
    echo -e "${CYAN}${BOLD}========================================================================${NC}\n"

    if command -v qrencode >/dev/null 2>&1; then
        qrencode -t ansiutf8 < "$conf_file"
        echo ""
    fi

    echo -e "${BOLD}Client Configuration File: [ ${conf_file} ]${NC}"
    echo -e "${CYAN}------------------------------------------------------------------------${NC}"
    cat "$conf_file"
    echo -e "${CYAN}------------------------------------------------------------------------${NC}\n"
    echo -e "${YELLOW}VoIP / SIP Trunk Setup Tip:${NC}"
    echo "  1. If setting up on Android/iOS: Open WireGuard app -> '+' -> Scan QR Code."
    echo "  2. If using with Asterisk/FreePBX/PC: Import or copy ${conf_file}."
    echo "  3. 'PersistentKeepalive = 25' ensures calls and registrations stay connected."
    echo ""
}

# List all active peers
list_peers() {
    echo -e "\n${BOLD}=== Live WireGuard Tunnel Status & Connected Peers ===${NC}\n"
    wg show || true
    echo ""
    echo -e "${BOLD}Configured Client Files in ${CLIENTS_DIR}:${NC}"
    ls -1 "${CLIENTS_DIR}"/*.conf 2>/dev/null | xargs -n1 basename 2>/dev/null || echo "No client files yet."
    echo ""
}

# Remove a client peer
remove_client() {
    local client_name="$1"
    local conf_file="${CLIENTS_DIR}/${client_name}.conf"

    if [ ! -f "$conf_file" ]; then
        echo -e "${RED}[ERROR] Client '${client_name}' does not exist.${NC}"
        return 1
    fi

    local client_pub
    client_pub=$(grep -E '^[[:space:]]*PrivateKey' "$conf_file" | head -n1 | sed -E 's/^[[:space:]]*PrivateKey[[:space:]]*=[[:space:]]*//' | tr -d '[:space:]' | wg pubkey)

    # Remove from live wg interface
    wg set wg0 peer "$client_pub" remove >/dev/null 2>&1 || true

    # Remove block from wg0.conf
    # Using python/perl or sed to remove peer block
    sed -i "/# Client: ${client_name}/,/^$/d" "$WG_CONF" || true

    rm -f "$conf_file"
    echo -e "${GREEN}[OK] Client '${client_name}' removed successfully.${NC}"
}

# ==================== MAIN CLI MENU ====================

install_packages
enable_forwarding
init_server

# Check if at least one client exists, if not prompt to create one immediately
if [ ! -f "${CLIENTS_DIR}/sip-trunk.conf" ] && [ ! -f "${CLIENTS_DIR}/client1.conf" ]; then
    echo -e "\n${YELLOW}${BOLD}No client peers found. Creating your primary peer 'sip-trunk'...${NC}"
    add_client "sip-trunk"
fi

if [ "${1:-}" != "" ]; then
    case "$1" in
        add)
            add_client "${2:-client$RANDOM}"
            exit 0
            ;;
        show)
            show_client "${2:-sip-trunk}"
            exit 0
            ;;
        status|list)
            list_peers
            exit 0
            ;;
        remove|delete)
            remove_client "${2:-}"
            exit 0
            ;;
    esac
fi

while true; do
    echo -e "${CYAN}${BOLD}"
    echo "========================================================================"
    echo "   GravityDNS - WireGuard Tunnel Manager (VoIP / SIP / UDP / VPN)       "
    echo "========================================================================"
    echo -e "${NC}"
    echo "  1) Show Client Config & QR Code (for Phone / Asterisk / PBX)"
    echo "  2) Add New Client Peer (Generate New Key & QR)"
    echo "  3) List Live WireGuard Peers & Bandwidth Transfer"
    echo "  4) Delete a Client Peer"
    echo "  5) Restart WireGuard Service"
    echo "  6) Exit"
    echo ""
    read -rp "Select option [1-6]: " OPTION

    case "$OPTION" in
        1)
            echo -e "\n${BOLD}Available Clients:${NC}"
            ls -1 "${CLIENTS_DIR}"/*.conf 2>/dev/null | xargs -n1 basename | sed 's/\.conf$//' || echo "None"
            read -rp "Enter client name to view [default: sip-trunk]: " CNAME
            CNAME="${CNAME:-sip-trunk}"
            show_client "$CNAME"
            ;;
        2)
            read -rp "Enter new client name (e.g. phone, pbx, laptop): " NEWNAME
            add_client "$NEWNAME"
            ;;
        3)
            list_peers
            ;;
        4)
            echo -e "\n${BOLD}Available Clients:${NC}"
            ls -1 "${CLIENTS_DIR}"/*.conf 2>/dev/null | xargs -n1 basename | sed 's/\.conf$//' || echo "None"
            read -rp "Enter client name to delete: " DELNAME
            remove_client "$DELNAME"
            ;;
        5)
            echo -e "${CYAN}Restarting WireGuard service...${NC}"
            systemctl restart wg-quick@wg0
            echo -e "${GREEN}[OK] WireGuard service restarted.${NC}"
            ;;
        6|q|Q)
            echo -e "${GREEN}Goodbye!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid selection.${NC}"
            ;;
    esac
done
