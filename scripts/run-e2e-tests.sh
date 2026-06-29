#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EXTERNAL=false
if [[ "${1:-}" == "--external" ]]; then
  EXTERNAL=true
fi

if [[ "$EXTERNAL" == "false" ]]; then
  echo "Building proxy binary..."
  cargo build -p bsdm-proxy --bin proxy
  echo "Running in-process E2E tests..."
  cargo test -p bsdm-proxy-e2e
else
  echo "Running E2E checks against docker-compose.test.yml stack..."
  PROXY_URL="${PROXY_URL:-http://127.0.0.1:1488}"
  METRICS_URL="${METRICS_URL:-http://127.0.0.1:9090}"

  curl -fsS "${METRICS_URL}/health" | grep -q '"status":"ok"'

  # Cache HIT: repeat request and look for x-cache-status header.
  TARGET="https://httpbin.org/cache/200"
  curl -fsSI -x "${PROXY_URL}" "${TARGET}" | tee /tmp/e2e-first.headers >/dev/null
  curl -fsSI -x "${PROXY_URL}" "${TARGET}" | tee /tmp/e2e-second.headers >/dev/null
  grep -qi 'x-cache-status: HIT' /tmp/e2e-second.headers

  echo "External E2E checks passed."
fi
