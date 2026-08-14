#!/usr/bin/env bash
# BSDM-Proxy Interactive Installer
# UI layer only. Installation logic lives under scripts/installer.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER_DIR="${SCRIPT_DIR}/installer"

source "${INSTALLER_DIR}/common.sh"
source "${INSTALLER_DIR}/preflight.sh"

MODE="docker"
PREFIX="/opt/bsdm-proxy"
HTTP_PORT="3128"
METRICS_PORT="9090"
ACL_ENABLED="false"

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
  prompt_port "HTTP proxy port" "$HTTP_PORT" HTTP_PORT
  prompt_port "Metrics port" "$METRICS_PORT" METRICS_PORT
  prompt_yn "Enable ACL" "$ACL_ENABLED" ACL_ENABLED

  echo
  echo "Installation plan"
  echo "Mode: ${MODE}"
  echo "Prefix: ${PREFIX}"
  echo "Proxy port: ${HTTP_PORT}"
  echo "Metrics port: ${METRICS_PORT}"
  echo "ACL: ${ACL_ENABLED}"
}

main() {
  banner
  select_mode
  preflight "$MODE"
  configure

  read -r -p "Continue? [Y/n]: " confirm
  case "${confirm:-y}" in
    n|N) exit 0 ;;
  esac

  local root
  root="$(cd "${SCRIPT_DIR}/.." && pwd)"

  case "$MODE" in
    docker)
      "${INSTALLER_DIR}/docker.sh" "$root"
      ;;
    native)
      "${INSTALLER_DIR}/native.sh" "$root" "$PREFIX" "$HTTP_PORT" "$METRICS_PORT" "$ACL_ENABLED"
      ;;
  esac

  info "Installation completed, running validation next"
  "${INSTALLER_DIR}/validation.sh"
}

main "$@"
