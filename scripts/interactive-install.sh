#!/usr/bin/env bash
# BSDM-Proxy Interactive Installer
# UI layer only. Installation logic lives under scripts/installer.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER_DIR="${SCRIPT_DIR}/installer"

source "${INSTALLER_DIR}/common.sh"
source "${INSTALLER_DIR}/preflight.sh"

MODE=""
PREFIX="/opt/bsdm-proxy"
ETC_DIR="/etc/bsdm-proxy"
HTTP_PORT="3128"
METRICS_PORT="9090"

banner() {
  clear 2>/dev/null || true
  echo "BSDM-Proxy Interactive Installer"
  echo "Safe deployment wizard"
}

select_mode() {
  echo
  echo "1) Docker Compose pilot"
  echo "2) Native proxy service"
  read -r -p "Select mode [1-2]: " choice

  case "${choice:-1}" in
    2) MODE=native ;;
    *) MODE=docker ;;
  esac
}

configure() {
  prompt_input "Installation prefix" "$PREFIX" PREFIX
  prompt_input "Configuration directory" "$ETC_DIR" ETC_DIR
  prompt_port "HTTP proxy port" "$HTTP_PORT" HTTP_PORT
  prompt_port "Metrics port" "$METRICS_PORT" METRICS_PORT

  echo
  echo "Installation plan"
  echo "Mode: ${MODE}"
  echo "Prefix: ${PREFIX}"
  echo "Config: ${ETC_DIR}"
  echo "Proxy port: ${HTTP_PORT}"
  echo "Metrics port: ${METRICS_PORT}"
}

install_docker() {
  require_cmd docker
  require_cmd docker

  cd "${SCRIPT_DIR}/.."
  [[ -f docker-compose.yml ]] || die "docker-compose.yml not found"

  docker compose config >/dev/null
  docker compose up -d
}

install_native() {
  local root
  root="$(cd "${SCRIPT_DIR}/.." && pwd)"

  [[ -x "${root}/packaging/install.sh" ]] || die "Canonical packaging installer missing"

  echo "Native installation delegates to packaging/install.sh"
  "${root}/packaging/install.sh"
}

main() {
  banner
  preflight
  select_mode
  configure

  read -r -p "Continue? [Y/n]: " confirm
  case "${confirm:-y}" in
    n|N) exit 0 ;;
  esac

  case "$MODE" in
    docker) install_docker ;;
    native) install_native ;;
  esac

  info "Installation completed, running validation next"
  "${INSTALLER_DIR}/validation.sh"
}

main "$@"
