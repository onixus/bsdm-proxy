#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

check_architecture() {
  case "$(uname -m)" in
    x86_64|aarch64|arm64)
      info "Supported architecture: $(uname -m)"
      ;;
    *)
      die "Unsupported architecture: $(uname -m)"
      ;;
  esac
}

preflight_common() {
  for cmd in curl openssl awk mv install; do
    require_cmd "$cmd"
  done
  check_architecture
}

preflight_native() {
  preflight_common
  require_root
  [[ "$(uname -s)" == "Linux" ]] || die "Native systemd installation is supported on Linux only"
  require_cmd cargo
  require_cmd systemctl
  require_cmd sha256sum
  systemctl --version >/dev/null 2>&1 || die "systemd is required for native installation"
  info "Native installation prerequisites passed"
}

preflight_docker() {
  preflight_common
  require_cmd docker
  docker compose version >/dev/null 2>&1 || die "Docker Compose plugin is required"
  info "Docker installation prerequisites passed"
}

preflight() {
  local mode="${1:-}"
  case "$mode" in
    native) preflight_native ;;
    docker) preflight_docker ;;
    *) die "Unknown preflight mode: ${mode:-<empty>}" ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  preflight "${1:-}"
fi
