#!/usr/bin/env bash
# Fleet silent wrapper for Linux MDM / config management.
# Env (required): CONTROL_PLANE_URL
# Env (recommended): CONTROL_API_TOKEN, AGENT_ENROLL_TOKEN, DEVICE_ID, BSDM_AGENT_BIN
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
BIN="${BSDM_AGENT_BIN:-}"
ARGS=(--silent --enable)
[[ -n "${BIN}" ]] && ARGS+=(--bin "${BIN}")
[[ -n "${CONTROL_PLANE_URL:-}" ]] && ARGS+=(--control-plane-url "${CONTROL_PLANE_URL}")
[[ -n "${CONTROL_API_TOKEN:-}" ]] && ARGS+=(--control-token "${CONTROL_API_TOKEN}")
[[ -n "${AGENT_ENROLL_TOKEN:-}" ]] && ARGS+=(--enroll-token "${AGENT_ENROLL_TOKEN}")
[[ -n "${DEVICE_ID:-}" ]] && ARGS+=(--device-id "${DEVICE_ID}")
[[ -n "${DEVICE_NAME:-}" ]] && ARGS+=(--device-name "${DEVICE_NAME}")
[[ -n "${SYSTEM_PROXY_HOST:-}" ]] && ARGS+=(--system-proxy-host "${SYSTEM_PROXY_HOST}")
[[ -n "${SYSTEM_PROXY_PORT:-}" ]] && ARGS+=(--system-proxy-port "${SYSTEM_PROXY_PORT}")
if [[ "${SET_SYSTEM_PROXY:-0}" == "1" ]]; then
  ARGS+=(--set-system-proxy)
fi
exec "${ROOT}/packaging/agent/install-linux.sh" "${ARGS[@]}"
