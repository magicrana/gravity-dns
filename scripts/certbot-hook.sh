#!/usr/bin/env bash
# ==============================================================================
# GravityDNS - Let's Encrypt Certbot Post-Renewal Deploy Hook
# Called automatically by certbot when certificates are successfully renewed
# Install to: /etc/letsencrypt/renewal-hooks/deploy/gravitydns.sh
# ==============================================================================

set -euo pipefail

echo "[GravityDNS] Certbot renewal hook triggered for domain: ${RENEWED_DOMAINS:-all}"

# Ensure permissions on renewed certificates for gravity service user
CERT_DIR="/etc/letsencrypt/live"
if [ -d "$CERT_DIR" ]; then
    chmod 755 /etc/letsencrypt/live || true
    chmod 755 /etc/letsencrypt/archive || true
fi

# Reload or restart GravityDNS services
if systemctl is-active --quiet gravity.service; then
    echo "[GravityDNS] Restarting unified gravity.service..."
    systemctl restart gravity.service
elif systemctl is-active --quiet gravity-dns.service; then
    echo "[GravityDNS] Restarting gravity-dns.service..."
    systemctl restart gravity-dns.service
fi

if systemctl is-active --quiet nginx; then
    echo "[GravityDNS] Reloading nginx stream..."
    systemctl reload nginx || true
fi

echo "[GravityDNS] Certificate renewal hook completed successfully."
