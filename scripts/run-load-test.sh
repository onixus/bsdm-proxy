#!/usr/bin/env bash
# HTTP load test for BSDM-Proxy: parallel curl + optional wrk.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROXY="${PROXY:-http://127.0.0.1:12788}"
METRICS_URL="${METRICS_URL:-http://127.0.0.1:19190}"
UPSTREAM="${UPSTREAM:-http://127.0.0.1:18080}"
REQUESTS="${REQUESTS:-50000}"
WORKERS="${WORKERS:-80}"
WRK_THREADS="${WRK_THREADS:-4}"
WRK_CONNECTIONS="${WRK_CONNECTIONS:-100}"
WRK_DURATION="${WRK_DURATION:-30s}"
RUN_WRK="${RUN_WRK:-1}"

metric() {
  curl -fsS "${METRICS_URL}/metrics" 2>/dev/null | awk -v n="$1" '$1 == n {print $2; exit}'
}

run_curl_scenario() {
  local name="$1"
  local url="$2"
  local warm="${3:-true}"

  echo ""
  echo "==> ${name} [curl]"
  echo "    URL: ${url}"

  if [[ "$warm" == "true" ]]; then
    curl -fsS -x "${PROXY}" "${url}" >/dev/null
  fi

  local hits_before miss_before
  hits_before=$(metric bsdm_proxy_cache_hits_total)
  miss_before=$(metric bsdm_proxy_cache_misses_total)

  local start end elapsed
  start=$(date +%s.%N)

  if [[ "$url" == *"{}"* ]]; then
    local base="${url%\{\}}"
    export PROXY
    seq 1 "${REQUESTS}" | xargs -P "${WORKERS}" -I{} \
      bash -c 'curl -sf -o /dev/null -x "$PROXY" "$1/$2$RANDOM$RANDOM"' _ "${base}" miss \
      || true
  else
    seq 1 "${REQUESTS}" | xargs -P "${WORKERS}" -I{} \
      curl -sf -o /dev/null -x "${PROXY}" "${url}" \
      || true
  fi

  end=$(date +%s.%N)
  elapsed=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

  local hits_after miss_after hit_delta miss_delta rps
  hits_after=$(metric bsdm_proxy_cache_hits_total)
  miss_after=$(metric bsdm_proxy_cache_misses_total)
  hit_delta=$((hits_after - hits_before))
  miss_delta=$((miss_after - miss_before))
  rps=$(awk -v n="${REQUESTS}" -v t="$elapsed" 'BEGIN{printf "%.0f", n/t}')

  echo "    Duration:     ${elapsed}s"
  echo "    Throughput:   ~${rps} req/s (sent ${REQUESTS})"
  echo "    Cache HITs:   +${hit_delta}"
  echo "    Cache MISSes: +${miss_delta}"
}

run_wrk_scenario() {
  local name="$1"
  local target_url="$2"
  local miss_mode="${3:-0}"

  if [[ "$RUN_WRK" != "1" ]] || ! command -v wrk >/dev/null 2>&1; then
    return 0
  fi

  local proxy_hp="${PROXY#http://}"
  proxy_hp="${proxy_hp#https://}"

  echo ""
  echo "==> ${name} [wrk ${WRK_DURATION}, ${WRK_CONNECTIONS} conn]"
  echo "    Target: ${target_url}"

  curl -fsS -x "${PROXY}" "${target_url}" >/dev/null 2>&1 || true

  local hits_before miss_before
  hits_before=$(metric bsdm_proxy_cache_hits_total)
  miss_before=$(metric bsdm_proxy_cache_misses_total)

  unset NO_COLOR FORCE_COLOR
  WRK_TARGET_URL="${target_url}" WRK_MISS_MODE="${miss_mode}" \
    wrk -t"${WRK_THREADS}" -c"${WRK_CONNECTIONS}" -d"${WRK_DURATION}" \
      -s "${ROOT}/scripts/wrk-proxy.lua" \
      "http://${proxy_hp}" \
    | tee "/tmp/wrk-${name// /-}.txt" | tail -12

  local hits_after miss_after hit_delta miss_delta
  hits_after=$(metric bsdm_proxy_cache_hits_total)
  miss_after=$(metric bsdm_proxy_cache_misses_total)
  hit_delta=$((hits_after - hits_before))
  miss_delta=$((miss_after - miss_before))

  echo "    Proxy cache HITs:   +${hit_delta}"
  echo "    Proxy cache MISSes: +${miss_delta}"
}

ensure_stack() {
  if ! curl -fsS "${METRICS_URL}/health" >/dev/null 2>&1; then
    echo "Proxy not healthy at ${METRICS_URL}. Start it first."
    exit 1
  fi
  if ! curl -fsS "${UPSTREAM}/ping" >/dev/null 2>&1; then
    echo "Upstream not reachable at ${UPSTREAM}. Start scripts/mock-upstream-threaded.py"
    exit 1
  fi
}

echo "==> BSDM-Proxy load test (extended)"
echo "    Proxy:      ${PROXY}"
echo "    Metrics:    ${METRICS_URL}"
echo "    Upstream:   ${UPSTREAM}"
echo "    curl:       ${REQUESTS} req x ${WORKERS} workers"
echo "    wrk:        ${WRK_DURATION}, ${WRK_CONNECTIONS} conn, ${WRK_THREADS} threads"

ensure_stack

HIT_URL="${UPSTREAM}/loadtest-static"

run_curl_scenario "Scenario 1: L1 cache HIT" "${HIT_URL}"
run_wrk_scenario "Scenario 1b: L1 cache HIT" "${HIT_URL}" 0

run_curl_scenario "Scenario 2: L1 cache MISS" "${UPSTREAM}/miss/{}" false
run_wrk_scenario "Scenario 2b: L1 cache MISS" "${HIT_URL}" 1

if curl -fsS http://127.0.0.1:19490/health >/dev/null 2>&1; then
  HIER_URL="${UPSTREAM}/hier-load-static"
  curl -fsS -x http://127.0.0.1:12588 "${HIER_URL}" >/dev/null 2>&1 || true
  curl -fsS -x http://127.0.0.1:12688 "${HIER_URL}" >/dev/null 2>&1 || true
  PROXY=http://127.0.0.1:12688 METRICS_URL=http://127.0.0.1:19490 \
    run_curl_scenario "Scenario 3: Hierarchy child" "${HIER_URL}"
  PROXY=http://127.0.0.1:12688 METRICS_URL=http://127.0.0.1:19490 \
    run_wrk_scenario "Scenario 3b: Hierarchy child" "${HIER_URL}" 0
fi

echo ""
echo "Load test finished."
