#!/usr/bin/env bash
# Run identical wrk/curl benchmarks against a forward proxy.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROXY_HOSTPORT="${1:?usage: run-proxy-benchmark.sh HOST:PORT LABEL}"
LABEL="${2:-$PROXY_HOSTPORT}"
UPSTREAM="${UPSTREAM:-http://127.0.0.1:18080}"
WRK_CONN_HIT="${WRK_CONN_HIT:-150}"
WRK_CONN_MISS="${WRK_CONN_MISS:-100}"
WRK_DURATION="${WRK_DURATION:-30s}"
CURL_REQUESTS="${CURL_REQUESTS:-10000}"
CURL_WORKERS="${CURL_WORKERS:-80}"

PROXY="http://${PROXY_HOSTPORT}"
HIT_URL="${UPSTREAM}/bench-${LABEL}-hit"
MISS_URL="${UPSTREAM}/bench-${LABEL}-miss"

unset NO_COLOR FORCE_COLOR

echo "############################################"
echo "# ${LABEL} @ ${PROXY}"
echo "############################################"

curl -fsS -x "${PROXY}" "${HIT_URL}" >/dev/null 2>&1 || true

echo ""
echo "==> wrk L1 HIT (${WRK_DURATION}, ${WRK_CONN_HIT} conn)"
WRK_TARGET_URL="${HIT_URL}" WRK_MISS_MODE=0 \
  wrk -t4 -c"${WRK_CONN_HIT}" -d"${WRK_DURATION}" \
    -s "${ROOT}/scripts/wrk-proxy.lua" "${PROXY}" 2>&1 \
  | grep -E 'Requests/sec|Latency|Non-2xx|Socket errors' || true

echo ""
echo "==> wrk L1 MISS (${WRK_DURATION}, ${WRK_CONN_MISS} conn)"
WRK_TARGET_URL="${HIT_URL}" WRK_MISS_MODE=1 \
  wrk -t4 -c"${WRK_CONN_MISS}" -d"${WRK_DURATION}" \
    -s "${ROOT}/scripts/wrk-proxy.lua" "${PROXY}" 2>&1 \
  | grep -E 'Requests/sec|Latency|Non-2xx|Socket errors' || true

echo ""
echo "==> curl HIT (${CURL_REQUESTS} req, ${CURL_WORKERS} workers)"
curl -fsS -x "${PROXY}" "${HIT_URL}" >/dev/null 2>&1 || true
start=$(date +%s.%N)
seq 1 "${CURL_REQUESTS}" | xargs -P "${CURL_WORKERS}" -I{} \
  curl -sf -o /dev/null -x "${PROXY}" "${HIT_URL}" || true
end=$(date +%s.%N)
rps=$(awk -v n="${CURL_REQUESTS}" -v s="$start" -v e="$end" 'BEGIN{printf "%.0f", n/(e-s)}')
echo "    ~${rps} req/s"

echo ""
echo "==> curl MISS (${CURL_REQUESTS} req, ${CURL_WORKERS} workers)"
start=$(date +%s.%N)
export PROXY
seq 1 "${CURL_REQUESTS}" | xargs -P "${CURL_WORKERS}" -I{} \
  bash -c 'curl -sf -o /dev/null -x "$PROXY" "$1/$2$RANDOM$RANDOM"' _ "${MISS_URL}" x || true
end=$(date +%s.%N)
rps=$(awk -v n="${CURL_REQUESTS}" -v s="$start" -v e="$end" 'BEGIN{printf "%.0f", n/(e-s)}')
echo "    ~${rps} req/s"
