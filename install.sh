#!/usr/bin/env bash
# Entry point for the BSDM-Proxy interactive installer.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER="${ROOT_DIR}/scripts/interactive-install.sh"

[[ -x "$INSTALLER" ]] || {
  echo "Error: interactive installer is missing or not executable: ${INSTALLER}" >&2
  exit 1
}

exec "$INSTALLER" "$@"
