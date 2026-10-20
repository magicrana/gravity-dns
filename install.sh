#!/usr/bin/env bash
# GravityDNS - Root One-Liner Installer Entrypoint
# Repository: https://github.com/magicrana/gravity-dns.git
#
# Quick run:
#   curl -fsSL https://raw.githubusercontent.com/magicrana/gravity-dns/main/install.sh | bash
# or:
#   bash <(curl -fsSL https://raw.githubusercontent.com/magicrana/gravity-dns/main/install.sh)

set -euo pipefail

SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
fi

CACHE_BUSTER="$(date +%s)"

# Route uninstallation request
if [ "${1:-}" = "uninstall" ] || [ "${1:-}" = "--uninstall" ]; then
    shift
    if [ -n "$SCRIPT_DIR" ] && [ -f "${SCRIPT_DIR}/scripts/uninstall.sh" ]; then
        exec bash "${SCRIPT_DIR}/scripts/uninstall.sh" "$@"
    elif [ -f "/opt/gravity-dns/scripts/uninstall.sh" ]; then
        exec bash "/opt/gravity-dns/scripts/uninstall.sh" "$@"
    else
        exec bash <(curl -fsSL -H "Cache-Control: no-cache" -H "Pragma: no-cache" "https://raw.githubusercontent.com/magicrana/gravity-dns/main/scripts/uninstall.sh?t=${CACHE_BUSTER}") "$@"
    fi
fi

if [ -n "$SCRIPT_DIR" ] && [ -f "${SCRIPT_DIR}/scripts/install.sh" ]; then
    exec bash "${SCRIPT_DIR}/scripts/install.sh" "$@"
elif [ -f "/opt/gravity-dns/scripts/install.sh" ]; then
    exec bash "/opt/gravity-dns/scripts/install.sh" "$@"
else
    # Piped execution: download and execute scripts/install.sh directly with cache-busting
    exec bash <(curl -fsSL -H "Cache-Control: no-cache" -H "Pragma: no-cache" "https://raw.githubusercontent.com/magicrana/gravity-dns/main/scripts/install.sh?t=${CACHE_BUSTER}") "$@"
fi
