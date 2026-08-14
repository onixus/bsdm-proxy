#!/usr/bin/env bash
# BSDM-Proxy binary installer.
# See release packages for the canonical installation flow.
set -euo pipefail

REPO="onixus/bsdm-proxy"
PREFIX="/opt/bsdm-proxy"
ETC_DIR="/etc/bsdm-proxy"
CERTS_DIR="/certs"

check_root() {
  [[ "$(id -u)" -eq 0 ]] || {
    echo "Installer must run as root" >&2
    exit 1
  }
}

main() {
  check_root
  echo "BSDM-Proxy binary installer"
  echo "Default proxy endpoint: http://127.0.0.1:3128"
  echo "Metrics endpoint: http://127.0.0.1:9090"
  echo "Repository: ${REPO}"
  echo "Install prefix: ${PREFIX}"
  echo "Config: ${ETC_DIR}"
  echo "Certificates: ${CERTS_DIR}"
}

main "$@"
