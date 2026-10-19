#!/usr/bin/env bash
# GravityDNS - Cloudflare ACME DNS-01 Cleanup Hook for Certbot
set -euo pipefail

CREDS_FILE="${GRAVITY_CF_CREDS:-/etc/gravity/cf-creds.json}"
if [ ! -f "$CREDS_FILE" ]; then
    CREDS_FILE="/var/lib/gravity/cf-creds.json"
fi

if [ ! -f "$CREDS_FILE" ]; then
    exit 0
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

if [ -z "$CF_TOKEN" ]; then
    exit 0
fi

if [ "$IS_TOKEN" = "false" ]; then
    AUTH_H1="X-Auth-Key: ${CF_TOKEN}"
    AUTH_H2="X-Auth-Email: ${CF_EMAIL}"
else
    AUTH_H1="Authorization: Bearer ${CF_TOKEN}"
    AUTH_H2=""
fi

REC_FILE="/tmp/gravity_acme_records/${CERTBOT_VALIDATION:-}"
if [ -f "$REC_FILE" ]; then
    while IFS=: read -r ZONE_ID RECORD_ID; do
        if [ -n "$ZONE_ID" ] && [ -n "$RECORD_ID" ]; then
            if [ -n "$AUTH_H2" ]; then
                curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${RECORD_ID}" \
                    -H "${AUTH_H1}" \
                    -H "${AUTH_H2}" \
                    -H "Content-Type: application/json" >/dev/null 2>&1 || true
            else
                curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${RECORD_ID}" \
                    -H "${AUTH_H1}" \
                    -H "Content-Type: application/json" >/dev/null 2>&1 || true
            fi
        fi
    done < "$REC_FILE"
    rm -f "$REC_FILE"
fi
