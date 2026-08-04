#!/usr/bin/env bash
# Reproducible Hybrid load-test profile: Selective MITM + SNI path + DNS (#269).
#
# Prerequisites:
#   - Proxy healthy on METRICS_URL (/health)
#   - For HTTPS samples: CA at CA_CERT (default certs/ca.crt)
#   - Optional: dig for DNS sinkhole share; AUTH via BASIC_AUTH user:pass
#
# Usage:
#   ./scripts/run-hybrid-load-test.sh
#   CONCURRENT_USERS=50 TEST_DURATION=60 ./scripts/run-hybrid-load-test.sh
#
# Docs: docs/ops-and-dev/load-test-selective-mitm.md
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROXY="${PROXY:-http://127.0.0.1:3128}"
METRICS_URL="${METRICS_URL:-http://127.0.0.1:9090}"
DNS_HOST="${DNS_HOST:-127.0.0.1}"
DNS_PORT="${DNS_PORT:-5353}"
CONCURRENT_USERS="${CONCURRENT_USERS:-100}"
TEST_DURATION="${TEST_DURATION:-30}"
CA_CERT="${CA_CERT:-${ROOT}/certs/ca.crt}"
BASIC_AUTH="${BASIC_AUTH:-}"
PCT_SNI="${PCT_SNI:-80}"
PCT_MITM="${PCT_MITM:-15}"
PCT_DNS="${PCT_DNS:-5}"
SNI_URL="${SNI_URL:-https://httpbin.org/get}"
MITM_URL="${MITM_URL:-https://httpbin.org/anything/phishing}"
HTTP_URL="${HTTP_URL:-http://httpbin.org/get}"
DNS_QNAME="${DNS_QNAME:-badsite.test}"
RESULTS_DIR="${RESULTS_DIR:-${ROOT}/docs/ops-and-dev/load-test-results}"
WRITE_RESULTS="${WRITE_RESULTS:-1}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
STRICT="${STRICT:-0}"

TMPDIR_RUN="$(mktemp -d "${TMPDIR:-/tmp}/bsdm-hybrid-load.XXXXXX")"
trap 'rm -rf "$TMPDIR_RUN"' EXIT

events_file="${TMPDIR_RUN}/events.tsv"
: >"$events_file"

delta_num() {
  # print max(after - before, 0) as integer
  awk -v a="$1" -v b="$2" 'BEGIN {
    d = (a + 0) - (b + 0)
    if (d < 0) d = 0
    printf "%d", d
  }'
}

metric() {
  local name="$1"
  curl -fsS "${METRICS_URL}/metrics" 2>/dev/null | awk -v n="$name" '
    $1 == n || index($1, n "{") == 1 { sum += $NF }
    END { print sum + 0 }
  ' || echo "0"
}

metric_labeled() {
  local name="$1"
  local label="$2"
  local value="$3"
  curl -fsS "${METRICS_URL}/metrics" 2>/dev/null | awk -v n="$name" -v l="$label" -v v="$value" '
    index($0, n) && $0 ~ l "=\"" v "\"" { print $NF + 0; found = 1; exit }
    END { if (!found) print 0 }
  ' || echo "0"
}

percentile() {
  local p="$1"
  local sorted n idx
  sorted=$(sort -n)
  n=$(printf '%s\n' "$sorted" | grep -c . || true)
  if [[ -z "${n:-}" || "$n" -eq 0 ]]; then
    echo "n/a"
    return
  fi
  idx=$(awk -v p="$p" -v n="$n" 'BEGIN {
    i = int((p / 100.0) * (n - 1)) + 1
    if (i < 1) i = 1
    if (i > n) i = n
    print i
  }')
  printf '%s\n' "$sorted" | sed -n "${idx}p" | awk '{ printf "%.1f", $1 + 0 }'
}

# Build curl base args as a string of newline-separated tokens to avoid empty-array set -u issues
CURL_BASE_ARGS=()
CURL_BASE_ARGS+=(-sf -m 5 -x "$PROXY" -o /dev/null -w "%{time_total}")
if [[ -f "$CA_CERT" ]]; then
  CURL_BASE_ARGS+=(--cacert "$CA_CERT")
else
  echo "⚠ CA cert not found at ${CA_CERT}; HTTPS may fail MITM validation"
fi
if [[ -n "$BASIC_AUTH" ]]; then
  CURL_BASE_ARGS+=(-u "$BASIC_AUTH")
fi

# Export for subshells: serialize args
printf '%s\0' "${CURL_BASE_ARGS[@]}" >"${TMPDIR_RUN}/curl_args.bin"
export PROXY METRICS_URL DNS_HOST DNS_PORT DNS_QNAME
export SNI_URL MITM_URL HTTP_URL PCT_SNI PCT_MITM
export events_file

do_curl() {
  local url="$1"
  # rebuild args from file
  local -a args=()
  while IFS= read -r -d '' a; do
    args+=("$a")
  done <"${TMPDIR_RUN}/curl_args.bin"
  curl "${args[@]}" "$url" 2>/dev/null
}

echo "============================================================"
echo " BSDM-Proxy Hybrid Load Test (Selective MITM pilot profile)"
echo " Run ID:       ${RUN_ID}"
echo " Proxy:        ${PROXY}"
echo " Metrics:      ${METRICS_URL}"
echo " DNS Sinkhole: ${DNS_HOST}:${DNS_PORT}"
echo " Duration:     ${TEST_DURATION}s"
echo " Users:        ${CONCURRENT_USERS}"
echo " Mix:          SNI ${PCT_SNI}% / MITM ${PCT_MITM}% / DNS ${PCT_DNS}%"
echo " Auth:         ${BASIC_AUTH:+enabled}${BASIC_AUTH:-disabled}"
echo "============================================================"

if ! curl -fsS "${METRICS_URL}/health" >/dev/null 2>&1; then
  echo "❌ Proxy is not healthy at ${METRICS_URL}."
  echo "   Example: HTTP_PORT=3128 METRICS_PORT=9090 POLICY_MODE=selective-mitm \\"
  echo "            cargo run -p bsdm-proxy --bin proxy"
  echo "   Or: docker compose -f docker-compose.lite.yml up -d --build"
  exit 1
fi
echo "✅ Health check passed."

REQ_BEFORE=$(metric bsdm_proxy_requests_total)
HITS_BEFORE=$(metric bsdm_proxy_cache_hits_total)
DEC_SNI_BEFORE=$(metric_labeled bsdm_proxy_policy_decision_source_total source sni)
DEC_MITM_BEFORE=$(metric_labeled bsdm_proxy_policy_decision_source_total source mitm)
DEC_DNS_BEFORE=$(metric_labeled bsdm_proxy_policy_decision_source_total source dns)
DEC_PIN_BEFORE=$(metric_labeled bsdm_proxy_policy_decision_source_total source pinning-bypass)

START_TIME=$(date +%s.%N)
END_TARGET=$(($(date +%s) + TEST_DURATION))

simulate_user() {
  local user_id=$1
  local end_time=$2
  local user_events="${TMPDIR_RUN}/u${user_id}.tsv"
  : >"$user_events"

  while [[ $(date +%s) -lt $end_time ]]; do
    local dice=$((RANDOM % 100))
    local kind elapsed=0 ok=0
    if [[ $dice -lt $PCT_SNI ]]; then
      kind=sni
      if elapsed=$(do_curl "${SNI_URL}?u=${user_id}&r=${RANDOM}"); then
        ok=1
      elif elapsed=$(do_curl "${HTTP_URL}?u=${user_id}&r=${RANDOM}"); then
        ok=1
      else
        elapsed=0
      fi
    elif [[ $dice -lt $((PCT_SNI + PCT_MITM)) ]]; then
      kind=mitm
      if elapsed=$(do_curl "${MITM_URL}?u=${user_id}&r=${RANDOM}"); then
        ok=1
      else
        elapsed=0
      fi
    else
      kind=dns
      if command -v dig >/dev/null 2>&1; then
        if dig @"${DNS_HOST}" -p "${DNS_PORT}" "${DNS_QNAME}" +time=2 +tries=1 +short >/dev/null 2>&1; then
          ok=1
          elapsed=0.001
        fi
      else
        if elapsed=$(do_curl "${HTTP_URL}?dns_fallback=${user_id}&r=${RANDOM}"); then
          ok=1
        fi
      fi
    fi

    local status=err
    local ms=0
    if [[ $ok -eq 1 ]]; then
      status=ok
      ms=$(awk -v t="$elapsed" 'BEGIN { printf "%.3f", (t + 0) * 1000 }')
    fi
    printf '%s\t%s\t%s\n' "$kind" "$status" "$ms" >>"$user_events"
  done
}

echo "🚀 Starting ${CONCURRENT_USERS}-user hybrid load for ${TEST_DURATION}s..."
PIDS=()
for i in $(seq 1 "${CONCURRENT_USERS}"); do
  simulate_user "$i" "$END_TARGET" &
  PIDS+=($!)
done
for pid in "${PIDS[@]}"; do
  wait "$pid" 2>/dev/null || true
done

# Merge per-user event files
cat "${TMPDIR_RUN}"/u*.tsv >"$events_file" 2>/dev/null || true

END_TIME=$(date +%s.%N)
ELAPSED=$(awk -v s="$START_TIME" -v e="$END_TIME" 'BEGIN { printf "%.2f", e - s }')

REQ_AFTER=$(metric bsdm_proxy_requests_total)
HITS_AFTER=$(metric bsdm_proxy_cache_hits_total)
DEC_SNI_AFTER=$(metric_labeled bsdm_proxy_policy_decision_source_total source sni)
DEC_MITM_AFTER=$(metric_labeled bsdm_proxy_policy_decision_source_total source mitm)
DEC_DNS_AFTER=$(metric_labeled bsdm_proxy_policy_decision_source_total source dns)
DEC_PIN_AFTER=$(metric_labeled bsdm_proxy_policy_decision_source_total source pinning-bypass)

TOTAL_PROXIED=$(delta_num "$REQ_AFTER" "$REQ_BEFORE")
TOTAL_HITS=$(delta_num "$HITS_AFTER" "$HITS_BEFORE")
RPS=$(awk -v r="$TOTAL_PROXIED" -v t="$ELAPSED" 'BEGIN {
  if (t > 0) printf "%.1f", r / t
  else print "0"
}')

OK_COUNT=$(awk -F'\t' '$2=="ok" {c++} END{print c+0}' "$events_file")
ERR_COUNT=$(awk -F'\t' '$2=="err" {c++} END{print c+0}' "$events_file")
SNI_COUNT=$(awk -F'\t' '$1=="sni" {c++} END{print c+0}' "$events_file")
MITM_COUNT=$(awk -F'\t' '$1=="mitm" {c++} END{print c+0}' "$events_file")
DNS_COUNT=$(awk -F'\t' '$1=="dns" {c++} END{print c+0}' "$events_file")
TOTAL_ATTEMPTS=$((OK_COUNT + ERR_COUNT))
ERR_RATE=$(awk -v e="$ERR_COUNT" -v t="$TOTAL_ATTEMPTS" 'BEGIN {
  if (t > 0) printf "%.2f", 100 * e / t
  else print "0.00"
}')

P50=$(awk -F'\t' '$2=="ok" {print $3}' "$events_file" | percentile 50)
P95=$(awk -F'\t' '$2=="ok" {print $3}' "$events_file" | percentile 95)
P99=$(awk -F'\t' '$2=="ok" {print $3}' "$events_file" | percentile 99)

DELTA_SNI=$(delta_num "$DEC_SNI_AFTER" "$DEC_SNI_BEFORE")
DELTA_MITM=$(delta_num "$DEC_MITM_AFTER" "$DEC_MITM_BEFORE")
DELTA_DNS=$(delta_num "$DEC_DNS_AFTER" "$DEC_DNS_BEFORE")
DELTA_PIN=$(delta_num "$DEC_PIN_AFTER" "$DEC_PIN_BEFORE")
DEC_SUM=$((DELTA_SNI + DELTA_MITM + DELTA_DNS + DELTA_PIN))
MITM_PCT=$(awk -v m="$DELTA_MITM" -v s="$DEC_SUM" 'BEGIN {
  if (s > 0) printf "%.1f", 100 * m / s
  else print "n/a"
}')

echo ""
echo "============================================================"
echo " Load Test Results Summary"
echo "============================================================"
echo " Duration:                 ${ELAPSED}s"
echo " Client attempts OK/ERR:   ${OK_COUNT}/${ERR_COUNT} (err ${ERR_RATE}%)"
echo " Proxy requests (Δ):       ${TOTAL_PROXIED}"
echo " Throughput (proxy RPS):   ~${RPS} req/s"
echo " Cache hits (Δ):           ${TOTAL_HITS}"
echo " Latency p50/p95/p99 (ms): ${P50} / ${P95} / ${P99}"
echo " decision_source Δ:        sni=${DELTA_SNI} mitm=${DELTA_MITM} dns=${DELTA_DNS} pin=${DELTA_PIN}"
echo " MITM share (metrics):     ${MITM_PCT}%"
echo " Client mix counts:        sni=${SNI_COUNT} mitm=${MITM_COUNT} dns=${DNS_COUNT}"
echo "============================================================"

if [[ "$WRITE_RESULTS" == "1" ]]; then
  mkdir -p "$RESULTS_DIR"
  out_md="${RESULTS_DIR}/${RUN_ID}.md"
  {
    echo "# Hybrid load-test run \`${RUN_ID}\`"
    echo
    echo "| Field | Value |"
    echo "|---|---|"
    echo "| Timestamp (UTC) | ${RUN_ID} |"
    echo "| Proxy | \`${PROXY}\` |"
    echo "| Concurrent users | ${CONCURRENT_USERS} |"
    echo "| Duration (s) | ${ELAPSED} |"
    echo "| Traffic mix target | SNI ${PCT_SNI}% / MITM ${PCT_MITM}% / DNS ${PCT_DNS}% |"
    echo "| Auth | ${BASIC_AUTH:+basic}${BASIC_AUTH:-disabled} |"
    echo "| Client OK / ERR | ${OK_COUNT} / ${ERR_COUNT} |"
    echo "| Error rate (%) | ${ERR_RATE} |"
    echo "| Proxy requests (Δ) | ${TOTAL_PROXIED} |"
    echo "| Proxy RPS | ${RPS} |"
    echo "| Cache hits (Δ) | ${TOTAL_HITS} |"
    echo "| Latency p50 (ms) | ${P50} |"
    echo "| Latency p95 (ms) | ${P95} |"
    echo "| Latency p99 (ms) | ${P99} |"
    echo "| decision_source sni (Δ) | ${DELTA_SNI} |"
    echo "| decision_source mitm (Δ) | ${DELTA_MITM} |"
    echo "| decision_source dns (Δ) | ${DELTA_DNS} |"
    echo "| decision_source pin (Δ) | ${DELTA_PIN} |"
    echo "| MITM share (metrics %) | ${MITM_PCT} |"
    echo "| Client mix sni/mitm/dns | ${SNI_COUNT}/${MITM_COUNT}/${DNS_COUNT} |"
    echo
    echo "## Assumptions"
    echo
    echo "- Profile: [load-test-selective-mitm.md](../load-test-selective-mitm.md)."
    echo "- Latency is client-observed wall time through the proxy (includes upstream RTT)."
    echo "- DNS share needs sinkhole on \`${DNS_HOST}:${DNS_PORT}\` and \`dig\`."
    echo
    echo "## Host / stack notes"
    echo
    echo '```'
    uname -a 2>/dev/null || true
    if command -v docker >/dev/null 2>&1; then
      docker stats --no-stream 2>/dev/null || true
    fi
    echo '```'
  } >"$out_md"
  cp "$out_md" "${RESULTS_DIR}/latest.md"
  echo "📝 Results written to ${out_md}"
fi

if awk -v e="$ERR_RATE" 'BEGIN { exit !(e > 5) }'; then
  echo "⚠ Error rate ${ERR_RATE}% exceeds 5%"
  if [[ "$STRICT" == "1" ]]; then
    exit 2
  fi
fi

echo "Done."
