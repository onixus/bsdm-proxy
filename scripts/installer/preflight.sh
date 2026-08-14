#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

preflight() {
  require_root

  for cmd in curl openssl install awk mv; do
    require_cmd "$cmd"
  done

  if command -v systemctl >/dev/null 2>&1; then
    info "systemd detected"
  else
    warn "systemd not detected; native service install unavailable"
  fi

  if command -v docker >/dev/null 2>&1; then
    info "docker detected"
  else
    warn "docker not detected; compose mode unavailable"
  fi

  case "$(uname -m)" in
    x86_64|aarch64|arm64)
      info "supported architecture: $(uname -m)"
      ;;
    *)
      die "Unsupported architecture: $(uname -m)"
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  preflight
fi
