#!/usr/bin/env bash
# Capture CPU profile during wrk L1 HIT against BSDM-Proxy.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROXY_PORT="${PROXY_PORT:-12788}"
METRICS_PORT="${METRICS_PORT:-19190}"
DURATION="${WRK_DURATION:-30s}"
CONNECTIONS="${WRK_CONN_HIT:-150}"
OUTPUT="${OUTPUT:-/tmp/bsdm-perf.data}"

if ! command -v perf >/dev/null 2>&1; then
  echo "perf not installed — install linux-tools or perf package" >&2
  exit 1
fi

if ! curl -sf "http://127.0.0.1:${METRICS_PORT}/health" >/dev/null 2>&1; then
  echo "Proxy not running on metrics port ${METRICS_PORT}" >&2
  exit 1
fi

if ! curl -sf http://127.0.0.1:18080/ping >/dev/null 2>&1; then
  echo "Upstream mock not running on :18080 — start scripts/mock-upstream-threaded.py" >&2
  exit 1
fi

PROXY="http://127.0.0.1:${PROXY_PORT}"
HIT_URL="http://127.0.0.1:18080/bench-perf-hit"
curl -fsS -x "${PROXY}" "${HIT_URL}" >/dev/null 2>&1 || true

PID="$(pgrep -n -f 'target/release/proxy' || true)"
if [[ -z "${PID}" ]]; then
  echo "release proxy process not found" >&2
  exit 1
fi

echo "Profiling PID ${PID} for ${DURATION} (wrk ${CONNECTIONS} conn)..."
sudo perf record -F 997 -g -p "${PID}" -o "${OUTPUT}" -- sleep "${DURATION%%s*}" &
PERF_PID=$!

WRK_TARGET_URL="${HIT_URL}" WRK_MISS_MODE=0 \
  wrk -t4 -c"${CONNECTIONS}" -d"${DURATION}" \
    -s "${ROOT}/scripts/wrk-proxy.lua" "${PROXY}" >/tmp/wrk-perf.txt 2>&1 || true

wait "${PERF_PID}" || true
grep -E 'Requests/sec|Latency' /tmp/wrk-perf.txt || true
echo "Profile saved: ${OUTPUT}"
echo "Report: sudo perf report -i ${OUTPUT}"
