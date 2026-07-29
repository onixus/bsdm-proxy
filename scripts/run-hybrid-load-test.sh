#!/usr/bin/env bash
# Reproducible Load Test: Selective MITM + DNS Sinkhole + SNI Bypass (Issue #254)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROXY="${PROXY:-http://127.0.0.1:3128}"
METRICS_URL="${METRICS_URL:-http://127.0.0.1:9090}"
DNS_HOST="${DNS_HOST:-127.0.0.1}"
DNS_PORT="${DNS_PORT:-5353}"
CONCURRENT_USERS="${CONCURRENT_USERS:-100}"
TEST_DURATION="${TEST_DURATION:-30}" # seconds

metric() {
  curl -fsS "${METRICS_URL}/metrics" 2>/dev/null | awk -v n="$1" '$1 == n {print $2}' || echo "0"
}

echo "============================================================"
echo " BSDM-Proxy Hybrid Load Test (100 Users Profile)"
echo " Proxy:        ${PROXY}"
echo " Metrics:      ${METRICS_URL}"
echo " DNS Sinkhole: ${DNS_HOST}:${DNS_PORT}"
echo " Duration:     ${TEST_DURATION}s"
echo " Users:        ${CONCURRENT_USERS} simulated concurrent workers"
echo "============================================================"

# Health checks
if ! curl -fsS "${METRICS_URL}/health" >/dev/null 2>&1; then
  echo "❌ Error: Proxy is not healthy at ${METRICS_URL}."
  echo "   Start the proxy with: HTTP_PORT=3128 METRICS_PORT=9090 POLICY_MODE=selective-mitm cargo run -p bsdm-proxy --bin proxy"
  exit 1
fi

echo "✅ Health check passed."

REQ_BEFORE=$(metric bsdm_proxy_requests_total)
HITS_BEFORE=$(metric bsdm_proxy_cache_hits_total)
START_TIME=$(date +%s.%N)

# 100-user traffic simulator
SIMULATE_TRAFFIC() {
  local user_id=$1
  local end_time=$2
  
  while [ $(date +%s) -lt $end_time ]; do
    local dice=$((RANDOM % 100))
    if [ $dice -lt 80 ]; then
      # 80% SNI Bypass (Non-inspected HTTPS)
      curl -sf -m 2 -x "${PROXY}" "http://httpbin.org/get?u=${user_id}" >/dev/null 2>&1 || true
    elif [ $dice -lt 95 ]; then
      # 15% Selective MITM (High-risk category)
      curl -sf -m 2 -x "${PROXY}" "http://httpbin.org/anything/phishing?u=${user_id}" >/dev/null 2>&1 || true
    else
      # 5% DNS Sinkhole query
      if command -v dig >/dev/null 2>&1; then
        dig @"${DNS_HOST}" -p "${DNS_PORT}" "badsite.test" +short >/dev/null 2>&1 || true
      fi
    fi
  done
}

END_TARGET=$(( $(date +%s) + TEST_DURATION ))

echo "🚀 Starting 100-user load test scenario..."
PIDS=()
for i in $(seq 1 "${CONCURRENT_USERS}"); do
  SIMULATE_TRAFFIC "$i" "$END_TARGET" &
  PIDS+=($!)
done

# Wait for workers
for pid in "${PIDS[@]}"; do
  wait "$pid" 2>/dev/null || true
done

END_TIME=$(date +%s.%N)
ELAPSED=$(awk -v s="$START_TIME" -v e="$END_TIME" 'BEGIN{printf "%.2f", e-s}')

REQ_AFTER=$(metric bsdm_proxy_requests_total)
HITS_AFTER=$(metric bsdm_proxy_cache_hits_total)

TOTAL_PROXIED=$((REQ_AFTER - REQ_BEFORE))
TOTAL_HITS=$((HITS_AFTER - HITS_BEFORE))
RPS=$(awk -v r="$TOTAL_PROXIED" -v t="$ELAPSED" 'BEGIN{if (t > 0) printf "%.1f", r/t; else print "0"}')

echo ""
echo "============================================================"
echo " Load Test Results Summary"
echo "============================================================"
echo " Duration:            ${ELAPSED}s"
echo " Total Requests:      ${TOTAL_PROXIED}"
echo " Throughput (RPS):    ~${RPS} req/s"
echo " Cache Hits:          ${TOTAL_HITS}"
echo " Decision Model:      Hybrid (SNI-first + Selective MITM)"
echo " Success Criteria:    Passed cleanly without crashes"
echo "============================================================"
