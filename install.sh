#!/usr/bin/env bash
# Wrapper script to run the interactive installer
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Error: Installer must be run as root (sudo ./install.sh)" >&2
  exit 1
fi

echo "Starting BSDM-Proxy interactive installer..."
exec "${ROOT_DIR}/scripts/interactive-install.sh" "$@"
