#!/usr/bin/env bash
# ==============================================================================
# GravityDNS - Automated Let's Encrypt Wildcard SSL Certificate Provisioner
# Supports: Cloudflare DNS API (Automated) and Manual DNS Challenge
# Target Domains: <DOMAIN> and *.<DOMAIN> (for Private DNS DoT and DoH)
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This tool must be run as root (sudo).${NC}"
    exit 1
fi

CONFIG_FILE="/etc/gravity/gravity.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}[ERROR] Configuration not found at ${CONFIG_FILE}.${NC}"
    echo "Please run install.sh first."
    exit 1
fi

# Extract configured domain
DOMAIN=$(grep -E '^[[:space:]]*domain:' "$CONFIG_FILE" 2>/dev/null | head -n1 | sed -E 's/^[[:space:]]*domain:[[:space:]]*//; s/[[:space:]]*#.*$//; s/^["\x27]//; s/["\x27]$//' | tr -d '[:space:]')

if [ -z "$DOMAIN" ]; then
    echo -e "${YELLOW}Could not auto-detect domain from ${CONFIG_FILE}.${NC}"
    read -rp "Enter your Base Domain (e.g. dns.crazyhd.online): " DOMAIN
fi

DOMAIN=$(echo "$DOMAIN" | sed 's/^\.*//; s/\.*$//')

echo -e "${CYAN}${BOLD}"
echo "========================================================================"
echo "    GravityDNS - Let's Encrypt Wildcard Certificate Generator          "
echo "========================================================================"
echo -e "${NC}"
echo -e "Target Base Domain:    ${BOLD}${DOMAIN}${NC}"
echo -e "Wildcard Subdomains:   ${BOLD}*.${DOMAIN}${NC} (Required for <token>.${DOMAIN} DoT)"
echo ""
echo -e "${YELLOW}IMPORTANT:${NC} Android Private DNS and iOS Profile require a genuine, publicly trusted"
echo "certificate (Let's Encrypt). Cloudflare Origin CA or self-signed certs are rejected."
echo ""
echo "Select issuance method:"
echo "  1) Automated Cloudflare DNS API (Recommended - Auto-renews automatically)"
echo "  2) Manual DNS TXT Challenge (Enter TXT record in your DNS manager)"
echo "  3) Cancel"
echo ""

read -rp "Enter choice [1-3]: " CHOICE

case "$CHOICE" in
    1)
        echo -e "\n${BOLD}=== Automated Cloudflare DNS API ===${NC}"
        echo "You will need a Cloudflare API Token with permissions:"
        echo "  - Zone -> DNS -> Edit"
        echo "  - Zone Resources -> All zones (or select ${DOMAIN})"
        echo ""
        read -rp "Paste your Cloudflare API Token or Global API Key: " CF_TOKEN
        CF_TOKEN=$(echo "$CF_TOKEN" | tr -d '[:space:]')

        if [ -z "$CF_TOKEN" ]; then
            echo -e "${RED}[ERROR] Credential cannot be empty.${NC}"
            exit 1
        fi

        read -rp "Enter Cloudflare Account Email (Required if using Global API Key): " CF_EMAIL
        CF_EMAIL="${CF_EMAIL:-admin@${DOMAIN}}"

        echo -e "\n${CYAN}Installing Certbot Cloudflare DNS plugin & updating python-cloudflare...${NC}"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y
        apt-get install -y --no-install-recommends certbot python3-certbot-dns-cloudflare python3-pip
        pip3 install --upgrade --break-system-packages certbot certbot-dns-cloudflare "cloudflare>=2.3.1" >/dev/null 2>&1 || true

        mkdir -p /root/.secrets/certbot
        if echo "${CF_TOKEN}" | grep -Eq '^[0-9a-fA-F]{37}$'; then
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

        echo -e "\n${CYAN}Requesting Wildcard Certificate from Let's Encrypt for ${DOMAIN} and *.${DOMAIN}...${NC}"

        certbot certonly \
            --dns-cloudflare \
            --dns-cloudflare-credentials /root/.secrets/certbot/cloudflare.ini \
            --dns-cloudflare-propagation-seconds 30 \
            -d "${DOMAIN}" \
            -d "*.${DOMAIN}" \
            --email "${CF_EMAIL}" \
            --agree-tos \
            --no-eff-email \
            --non-interactive
        ;;

    2)
        echo -e "\n${BOLD}=== Manual DNS TXT Challenge ===${NC}"
        echo "Certbot will display a TXT record. Add it to your DNS host (Cloudflare dashboard) and wait."
        echo ""
        read -rp "Enter notification email address: " MANUAL_EMAIL
        MANUAL_EMAIL="${MANUAL_EMAIL:-admin@${DOMAIN}}"

        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y
        apt-get install -y --no-install-recommends certbot

        certbot certonly \
            --manual \
            --preferred-challenges dns \
            -d "${DOMAIN}" \
            -d "*.${DOMAIN}" \
            --email "${MANUAL_EMAIL}" \
            --agree-tos \
            --no-eff-email
        ;;

    *)
        echo -e "${YELLOW}Operation cancelled.${NC}"
        exit 0
        ;;
esac

CERT_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
KEY_PATH="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"

if [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
    echo -e "\n${GREEN}${BOLD}[SUCCESS] Let's Encrypt Wildcard Certificate Issued!${NC}"
    echo -e "  Certificate: ${BOLD}${CERT_PATH}${NC}"
    echo -e "  Private Key: ${BOLD}${KEY_PATH}${NC}"

    # Setup deploy hook for future automatic renewals
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/gravitydns.sh << 'HOOK_EOF'
#!/usr/bin/env bash
set -euo pipefail
if systemctl is-active --quiet gravity.service; then
    systemctl restart gravity.service
fi
HOOK_EOF
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/gravitydns.sh

    # Update gravity.yaml configuration
    sed -i -E "s|^([[:space:]]*tls_cert_file:).*|\1 \"${CERT_PATH}\"|" "$CONFIG_FILE"
    sed -i -E "s|^([[:space:]]*tls_key_file:).*|\1 \"${KEY_PATH}\"|" "$CONFIG_FILE"

    echo -e "\n${CYAN}Restarting GravityDNS service to load new certificates...${NC}"
    systemctl restart gravity.service || true

    echo -e "\n${GREEN}${BOLD}========================================================================${NC}"
    echo -e "${GREEN}${BOLD}   DoT (DNS-over-TLS) on port 853 is now active with Let's Encrypt!     ${NC}"
    echo -e "${GREEN}${BOLD}========================================================================${NC}"
    echo -e "  Android Private DNS Hostname:  ${BOLD}<token>.${DOMAIN}${NC}"
    echo -e "  DoH URL:                       ${BOLD}https://${DOMAIN}:8443/dns-query/<token>${NC}"
    echo -e "${GREEN}${BOLD}========================================================================${NC}\n"
else
    echo -e "\n${RED}[ERROR] Certificate files not found at ${CERT_PATH}.${NC}"
    exit 1
fi
