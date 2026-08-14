#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"
source "${SCRIPT_DIR}/config.sh"

install_docker() {
  local root="$1"

  require_cmd docker

  docker compose version >/dev/null 2>&1 || die "Docker Compose plugin is required"
  [[ -f "${root}/docker-compose.yml" ]] || die "docker-compose.yml not found"

  configure_compose_secrets "$root"

  info "Validating compose configuration"
  (
    cd "$root"
    docker compose config >/dev/null
  )

  info "Starting BSDM-Proxy compose deployment"
  (
    cd "$root"
    docker compose up -d
  )
}
