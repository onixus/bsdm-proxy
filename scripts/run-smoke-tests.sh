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
  echo "Running in-process smoke tests..."
  cargo test -p bsdm-proxy-e2e --test smoke -- --nocapture
else
  echo "Running smoke tests against docker-compose.test.yml stack..."
  PROXY_URL="${PROXY_URL:-http://127.0.0.1:1488}"
  METRICS_URL="${METRICS_URL:-http://127.0.0.1:9090}"

  curl -fsS "${METRICS_URL}/health" | grep -q '"status":"ok"'
  curl -fsS "${METRICS_URL}/ready" | grep -q '"status":"ready"'
  curl -fsS "${METRICS_URL}/metrics" | grep -q 'bsdm_proxy_requests_total'

  # Forward through proxy to public endpoint (no local upstream in external mode).
  curl -fsS -x "${PROXY_URL}" https://httpbin.org/status/200 >/dev/null
  echo "External smoke checks passed."
fi
