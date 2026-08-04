#!/usr/bin/env bash
# Smoke: proxy Basic auth 407 without credentials, 200 with valid Proxy-Authorization.
#
# Prerequisites: proxy healthy with AUTH_ENABLED=true and BASIC_AUTH_USERS_FILE loaded.
#
# Usage:
#   PROXY=http://127.0.0.1:3128 \
#   AUTH_USER=pilot AUTH_PASS=pilot-secret \
#   UPSTREAM=http://httpbin.org/get \
#   ./scripts/run-auth-pilot-smoke.sh
set -euo pipefail

PROXY="${PROXY:-http://127.0.0.1:3128}"
METRICS_URL="${METRICS_URL:-http://127.0.0.1:9090}"
AUTH_USER="${AUTH_USER:-pilot}"
AUTH_PASS="${AUTH_PASS:-pilot-secret}"
UPSTREAM="${UPSTREAM:-http://httpbin.org/get}"
TIMEOUT="${TIMEOUT:-10}"

echo "============================================================"
echo " Auth pilot smoke (Basic)"
echo " Proxy:    ${PROXY}"
echo " User:     ${AUTH_USER}"
echo " Upstream: ${UPSTREAM}"
echo "============================================================"

if ! curl -fsS --max-time "$TIMEOUT" "${METRICS_URL}/health" >/dev/null 2>&1; then
  echo "❌ Proxy not healthy at ${METRICS_URL}/health" >&2
  echo "   Start with AUTH_ENABLED=true BASIC_AUTH_USERS_FILE=..." >&2
  exit 1
fi

code_unauth="$(
  curl -sS -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" \
    -x "$PROXY" "$UPSTREAM" || true
)"
# 407 Proxy Authentication Required (some stacks surface 407 via proxy)
if [[ "$code_unauth" != "407" && "$code_unauth" != "401" ]]; then
  echo "❌ Expected 407/401 without credentials, got HTTP ${code_unauth}" >&2
  exit 1
fi
echo "✅ Unauthenticated request → HTTP ${code_unauth}"

code_auth="$(
  curl -sS -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" \
    -x "$PROXY" -U "${AUTH_USER}:${AUTH_PASS}" "$UPSTREAM" || true
)"
if [[ "$code_auth" != "200" && "$code_auth" != "301" && "$code_auth" != "302" ]]; then
  echo "❌ Expected success with credentials, got HTTP ${code_auth}" >&2
  echo "   Check BASIC_AUTH_USERS_FILE hashes (SHA-256 of password)." >&2
  exit 1
fi
echo "✅ Authenticated request → HTTP ${code_auth}"

code_bad="$(
  curl -sS -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" \
    -x "$PROXY" -U "${AUTH_USER}:wrong-password" "$UPSTREAM" || true
)"
if [[ "$code_bad" != "407" && "$code_bad" != "401" ]]; then
  echo "❌ Expected 407/401 with wrong password, got HTTP ${code_bad}" >&2
  exit 1
fi
echo "✅ Wrong password → HTTP ${code_bad}"

echo "============================================================"
echo " Auth pilot smoke PASSED"
echo "============================================================"
