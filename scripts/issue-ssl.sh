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

        echo -e "\n${CYAN}Requesting Wildcard Certificate from Let's Encrypt for ${DOMAIN} and *.${DOMAIN}...${NC}"

        SCRIPT_DIR=""
        if [ -n "${BASH_SOURCE[0]:-}" ]; then
            SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
        fi
        SCRIPT_DIR="${SCRIPT_DIR:-/opt/gravity-dns/scripts}"
        mkdir -p /etc/gravity /var/lib/gravity
        APEX_DOMAIN=$(echo "${DOMAIN}" | awk -F. '{if (NF>1) print $(NF-1)"."$NF; else print $0}')
        IS_GLOBAL=false
        if echo "${CF_TOKEN}" | grep -Eq '^[0-9a-fA-F]{37}$'; then
            IS_GLOBAL=true
        fi

        cat > /etc/gravity/cf-creds.json << EOF
{
  "token": "${CF_TOKEN}",
  "email": "${CF_EMAIL}",
  "is_token": $([ "$IS_GLOBAL" = "true" ] && echo "false" || echo "true"),
  "apex": "${APEX_DOMAIN}"
}
EOF
        cp -f /etc/gravity/cf-creds.json /var/lib/gravity/cf-creds.json
        chmod 600 /etc/gravity/cf-creds.json /var/lib/gravity/cf-creds.json

        AUTH_HOOK="${SCRIPT_DIR}/cf-auth-hook.sh"
        CLEANUP_HOOK="${SCRIPT_DIR}/cf-cleanup-hook.sh"
        chmod +x "${AUTH_HOOK}" "${CLEANUP_HOOK}" 2>/dev/null || true

        ISSUE_OK=false
        for attempt in 1 2; do
            echo -e "\n${CYAN}Running Certbot ACME DNS-01 Challenge (Attempt ${attempt}/2)...${NC}"
            if certbot certonly \
                --manual \
                --preferred-challenges dns \
                --manual-auth-hook "${AUTH_HOOK}" \
                --manual-cleanup-hook "${CLEANUP_HOOK}" \
                --manual-public-ip-logging-ok \
                -d "${DOMAIN}" \
                -d "*.${DOMAIN}" \
                --email "${CF_EMAIL}" \
                --agree-tos \
                --no-eff-email \
                --non-interactive; then
                ISSUE_OK=true
                break
            else
                echo -e "\n${YELLOW}[WARNING] Attempt ${attempt} failed. Waiting 10 seconds before retry...${NC}"
                sleep 10
            fi
        done

        if [ "$ISSUE_OK" = "false" ]; then
            echo -e "\n${RED}[ERROR] Automated Cloudflare certificate issuance failed after retries.${NC}"
            echo -e "You can also use Option 2 (Manual DNS TXT Challenge) or the Web UI at Settings -> TLS Certificates."
            exit 1
        fi
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
