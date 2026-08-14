#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

validate_installation() {
  local control_url="${1:-http://127.0.0.1:9090}"
  local proxy_url="${2:-http://127.0.0.1:3128}"

  require_cmd curl

  curl --fail --silent "${control_url}/health" >/dev/null || \
    die "Proxy health check failed"

  curl --fail --silent "${control_url}/ready" >/dev/null || \
    die "Proxy readiness check failed"

  curl --fail --silent -x "${proxy_url}" http://example.com >/dev/null || \
    die "Proxy traffic test failed"

  info "Installation validation passed"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  validate_installation "$@"
fi
