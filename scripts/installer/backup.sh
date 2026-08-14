#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

backup_installation() {
  local etc_dir="$1"
  local certs_dir="$2"
  local backup_root="${3:-/var/backups/bsdm-proxy}"
  local timestamp destination

  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  destination="${backup_root}/${timestamp}"

  if [[ ! -d "$etc_dir" && ! -d "$certs_dir" ]]; then
    info "No existing installation state to back up"
    return 0
  fi

  install -d -m 0700 "$destination"

  if [[ -d "$etc_dir" ]]; then
    cp -a -- "$etc_dir" "${destination}/etc"
  fi
  if [[ -d "$certs_dir" ]]; then
    cp -a -- "$certs_dir" "${destination}/certs"
  fi

  info "Installation backup created at ${destination}"
  printf '%s\n' "$destination"
}
