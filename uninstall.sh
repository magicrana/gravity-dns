#!/usr/bin/env bash
# ==============================================================================
# GravityDNS - Root Uninstallation Entrypoint
# Repository: https://github.com/magicrana/gravity-dns.git
#
# Quick run:
#   curl -fsSL https://raw.githubusercontent.com/magicrana/gravity-dns/main/uninstall.sh | bash
# or:
#   sudo bash /opt/gravity-dns/uninstall.sh
# ==============================================================================

set -euo pipefail

SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
fi

CACHE_BUSTER="$(date +%s)"

if [ -n "$SCRIPT_DIR" ] && [ -f "${SCRIPT_DIR}/scripts/uninstall.sh" ]; then
    exec bash "${SCRIPT_DIR}/scripts/uninstall.sh" "$@"
elif [ -f "/opt/gravity-dns/scripts/uninstall.sh" ]; then
    exec bash "/opt/gravity-dns/scripts/uninstall.sh" "$@"
else
    exec bash <(curl -fsSL -H "Cache-Control: no-cache" -H "Pragma: no-cache" "https://raw.githubusercontent.com/magicrana/gravity-dns/main/scripts/uninstall.sh?t=${CACHE_BUSTER}") "$@"
fi
