#!/usr/bin/env bash
# GravityDNS - Cloudflare ACME DNS-01 Auth Hook for Certbot
# Supports both Cloudflare Scoped API Tokens and Global API Keys.
# Avoids broken python3-certbot-dns-cloudflare packaging on Ubuntu.
set -euo pipefail

CREDS_FILE="${GRAVITY_CF_CREDS:-/etc/gravity/cf-creds.json}"
if [ ! -f "$CREDS_FILE" ]; then
    CREDS_FILE="/var/lib/gravity/cf-creds.json"
fi

if [ ! -f "$CREDS_FILE" ]; then
    echo "[ERROR] Cloudflare credentials file missing at $CREDS_FILE" >&2
    exit 1
fi

get_json_val() {
    local key="$1"
    local file="$2"
    if command -v python3 &>/dev/null; then
        python3 -c "import json, sys; d=json.load(open('$file')); print(d.get('$key',''))" 2>/dev/null && return
    fi
    grep -o "\"${key}\"[[:space:]]*:[[:space:]]*\"[^\"]*" "$file" 2>/dev/null | head -n1 | sed -E "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"//"
}

CF_TOKEN=$(get_json_val "token" "$CREDS_FILE")
CF_EMAIL=$(get_json_val "email" "$CREDS_FILE")
IS_TOKEN=$(get_json_val "is_token" "$CREDS_FILE")
APEX=$(get_json_val "apex" "$CREDS_FILE")

if [ -z "$CF_TOKEN" ]; then
    echo "[ERROR] Cloudflare token is empty in $CREDS_FILE" >&2
    exit 1
fi

if [ "$IS_TOKEN" = "false" ]; then
    AUTH_H1="X-Auth-Key: ${CF_TOKEN}"
    AUTH_H2="X-Auth-Email: ${CF_EMAIL}"
else
    AUTH_H1="Authorization: Bearer ${CF_TOKEN}"
    AUTH_H2=""
fi

# 1. Fetch Cloudflare Zone ID for Apex Domain
if [ -n "$AUTH_H2" ]; then
    ZONE_RES=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=${APEX}" \
        -H "${AUTH_H1}" \
        -H "${AUTH_H2}" \
        -H "Content-Type: application/json")
else
    ZONE_RES=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=${APEX}" \
        -H "${AUTH_H1}" \
        -H "Content-Type: application/json")
fi

ZONE_ID=$(echo "$ZONE_RES" | grep -o '"id":"[^"]*' | head -n1 | cut -d'"' -f4)
if [ -z "$ZONE_ID" ]; then
    echo "[ERROR] Could not resolve Cloudflare Zone ID for ${APEX}. Response: $ZONE_RES" >&2
    exit 1
fi

# Normalize domain name (strip leading *.)
CLEAN_DOMAIN=$(echo "${CERTBOT_DOMAIN}" | sed 's/^\*\.//')
RECORD_NAME="_acme-challenge.${CLEAN_DOMAIN}"

# 2. Create DNS TXT Challenge Record in Cloudflare
PAYLOAD="{\"type\":\"TXT\",\"name\":\"${RECORD_NAME}\",\"content\":\"${CERTBOT_VALIDATION}\",\"ttl\":60}"

if [ -n "$AUTH_H2" ]; then
    CREATE_RES=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" \
        -H "${AUTH_H1}" \
        -H "${AUTH_H2}" \
        -H "Content-Type: application/json" \
        --data "$PAYLOAD")
else
    CREATE_RES=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" \
        -H "${AUTH_H1}" \
        -H "Content-Type: application/json" \
        --data "$PAYLOAD")
fi

RECORD_ID=$(echo "$CREATE_RES" | grep -o '"id":"[^"]*' | head -n1 | cut -d'"' -f4)
if [ -z "$RECORD_ID" ]; then
    echo "[ERROR] Failed to create TXT record ${RECORD_NAME} in Cloudflare. Response: $CREATE_RES" >&2
    exit 1
fi

# Track record for cleanup
TRACK_DIR="/tmp/gravity_acme_records"
mkdir -p "$TRACK_DIR"
echo "${ZONE_ID}:${RECORD_ID}" >> "${TRACK_DIR}/${CERTBOT_VALIDATION}"

echo "[GravityDNS] Created Cloudflare TXT record for ${RECORD_NAME} (ID: ${RECORD_ID}). Propagating 15s..."
sleep 15
