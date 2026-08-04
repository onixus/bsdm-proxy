#!/usr/bin/env bash
# Smoke: Agent Contract policy pull + agent-spike once-mode + devices registry.
#
# Prerequisites: proxy control plane healthy on CONTROL_PLANE_URL (default :9090).
# Production/pilot: CONTROL_API_TOKEN must match the proxy.
#
# Usage:
#   CONTROL_PLANE_URL=http://127.0.0.1:9090 \
#   CONTROL_API_TOKEN=replace-me \
#   ./scripts/run-agent-pilot-smoke.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CONTROL_PLANE_URL="${CONTROL_PLANE_URL:-http://127.0.0.1:9090}"
CONTROL_PLANE_URL="${CONTROL_PLANE_URL%/}"
CONTROL_API_TOKEN="${CONTROL_API_TOKEN:-}"
DEVICE_ID="${DEVICE_ID:-smoke-agent-001}"
TIMEOUT="${TIMEOUT:-15}"
AUTH_HEADER=()
if [[ -n "${CONTROL_API_TOKEN}" ]]; then
  AUTH_HEADER=(-H "Authorization: Bearer ${CONTROL_API_TOKEN}")
fi

echo "============================================================"
echo " Agent pilot smoke (Phase C spike)"
echo " Control:  ${CONTROL_PLANE_URL}"
echo " Device:   ${DEVICE_ID}"
echo "============================================================"

if ! curl -fsS --max-time "$TIMEOUT" "${CONTROL_PLANE_URL}/health" >/dev/null 2>&1; then
  echo "❌ Proxy not healthy at ${CONTROL_PLANE_URL}/health" >&2
  echo "   Start pilot stack, then re-run." >&2
  exit 1
fi
echo "✅ Control plane health"

policy_json="$(
  curl -fsS --max-time "$TIMEOUT" "${AUTH_HEADER[@]}" \
    "${CONTROL_PLANE_URL}/api/v1/agent/policy" || true
)"
if [[ -z "${policy_json}" ]]; then
  echo "❌ GET /api/v1/agent/policy failed (check CONTROL_API_TOKEN / ALLOW_INSECURE)" >&2
  exit 1
fi
if ! echo "${policy_json}" | grep -q 'policy_mode'; then
  echo "❌ Policy payload missing policy_mode: ${policy_json}" >&2
  exit 1
fi
if ! echo "${policy_json}" | grep -qE 'sni_deny_patterns|sni_rules'; then
  echo "❌ Policy payload missing SNI deny fields: ${policy_json}" >&2
  exit 1
fi
echo "✅ GET /api/v1/agent/policy"

export CONTROL_PLANE_URL
export CONTROL_API_TOKEN
export DEVICE_ID
export DEVICE_NAME="${DEVICE_NAME:-Smoke Agent}"
export DEVICE_TYPE="${DEVICE_TYPE:-desktop}"
export AGENT_ONCE=1

if ! cargo run -q -p agent-spike -- --once; then
  echo "❌ agent-spike --once failed" >&2
  exit 1
fi
echo "✅ agent-spike once-mode (policy pull + heartbeat)"

devices_json="$(
  curl -fsS --max-time "$TIMEOUT" "${AUTH_HEADER[@]}" \
    "${CONTROL_PLANE_URL}/api/v1/devices" || true
)"
if [[ -z "${devices_json}" ]]; then
  echo "❌ GET /api/v1/devices failed" >&2
  exit 1
fi
if ! echo "${devices_json}" | grep -q "${DEVICE_ID}"; then
  echo "❌ Device ${DEVICE_ID} not listed in /api/v1/devices: ${devices_json}" >&2
  exit 1
fi
echo "✅ Device registered in GET /api/v1/devices"

echo "============================================================"
echo " Agent pilot smoke PASSED"
echo "============================================================"
