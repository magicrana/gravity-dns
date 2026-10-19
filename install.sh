#!/usr/bin/env bash
# GravityDNS - Root One-Liner Installer Entrypoint
# Repository: https://github.com/magicrana/gravity-dns.git
#
# Quick run:
#   curl -fsSL https://raw.githubusercontent.com/magicrana/gravity-dns/main/install.sh | bash
# or:
#   bash <(curl -fsSL https://raw.githubusercontent.com/magicrana/gravity-dns/main/install.sh)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "${SCRIPT_DIR}/scripts/install.sh" ]; then
    exec bash "${SCRIPT_DIR}/scripts/install.sh" "$@"
else
    # Piped execution: download and execute scripts/install.sh directly
    exec bash <(curl -fsSL "https://raw.githubusercontent.com/magicrana/gravity-dns/main/scripts/install.sh") "$@"
fi
