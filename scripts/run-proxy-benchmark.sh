#!/usr/bin/env bash
# Run wrk + oha (keep-alive) benchmarks against a forward proxy.
#
# oha replaces the old curl+xargs harness which capped both BSDM and Squid at ~1k
# req/s due to per-request process spawn. oha uses persistent connections (browser-like).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROXY_HOSTPORT="${1:?usage: run-proxy-benchmark.sh HOST:PORT LABEL}"
LABEL="${2:-$PROXY_HOSTPORT}"
UPSTREAM="${UPSTREAM:-http://127.0.0.1:18080}"
WRK_CONN_HIT="${WRK_CONN_HIT:-150}"
WRK_CONN_MISS="${WRK_CONN_MISS:-100}"
WRK_DURATION="${WRK_DURATION:-30s}"
OHA_CONN_HIT="${OHA_CONN_HIT:-${WRK_CONN_HIT}}"
OHA_CONN_MISS="${OHA_CONN_MISS:-${WRK_CONN_MISS}}"
OHA_DURATION="${OHA_DURATION:-${WRK_DURATION}}"
# Legacy curl harness (optional, for regression comparison only)
CURL_REQUESTS="${CURL_REQUESTS:-10000}"
CURL_WORKERS="${CURL_WORKERS:-80}"
BENCH_LEGACY_CURL="${BENCH_LEGACY_CURL:-0}"

PROXY="http://${PROXY_HOSTPORT}"
HIT_URL="${UPSTREAM}/bench-${LABEL}-hit"
MISS_URL="${UPSTREAM}/bench-${LABEL}-miss"

if ! command -v wrk >/dev/null 2>&1; then
  echo "wrk not found (apt install wrk)" >&2
  exit 1
fi
if [[ "$BENCH_LEGACY_CURL" != "1" ]] && ! command -v oha >/dev/null 2>&1; then
  echo "oha not found; install with: cargo install oha" >&2
  echo "Or set BENCH_LEGACY_CURL=1 to use the old curl+xargs harness." >&2
  exit 1
fi

unset NO_COLOR FORCE_COLOR CLICOLOR

# Optional proxy auth (corporate profile): WRK_PROXY_AUTH_HEADER or CURL_PROXY_USER=user:pass
bench_proxy_auth_args() {
  BENCH_PROXY_AUTH_ARGS=()
  if [[ -n "${WRK_PROXY_AUTH_HEADER:-}" ]]; then
    BENCH_PROXY_AUTH_ARGS=(-H "${WRK_PROXY_AUTH_HEADER}")
    BENCH_OHA_PROXY_HEADER=(--proxy-header "${WRK_PROXY_AUTH_HEADER}")
  elif [[ -n "${CURL_PROXY_USER:-}" ]]; then
    local hdr="Proxy-Authorization: Basic $(printf '%s' "${CURL_PROXY_USER}" | base64 -w0)"
    BENCH_PROXY_AUTH_ARGS=(-H "${hdr}")
    BENCH_OHA_PROXY_HEADER=(--proxy-header "${hdr}")
  else
    BENCH_OHA_PROXY_HEADER=()
  fi
}

bench_warm_hit() {
  if [[ -n "${CURL_PROXY_USER:-}" ]]; then
    curl -fsS -x "${PROXY}" -U "${CURL_PROXY_USER}" "${HIT_URL}" >/dev/null 2>&1 || true
  else
    curl -fsS -x "${PROXY}" "${HIT_URL}" >/dev/null 2>&1 || true
  fi
}

run_oha() {
  local mode="$1"
  local conn="$2"
  local -a cmd=(oha -c "${conn}" -z "${OHA_DURATION}" --no-tui -x "${PROXY}")
  if ((${#BENCH_OHA_PROXY_HEADER[@]})); then
    cmd+=("${BENCH_OHA_PROXY_HEADER[@]}")
  fi
  if [[ "$mode" == "miss" ]]; then
    # Unique path per request → cache MISS (dots in host are literal in rand_regex)
    cmd+=(--rand-regex-url "${MISS_URL}/[0-9]{12}")
    "${cmd[@]}" 2>&1
  else
    "${cmd[@]}" "${HIT_URL}" 2>&1
  fi
}

print_oha_summary() {
  grep -E '^(  Success rate:|  Requests/sec:|  Average:|  Slowest:)' || true
}

run_legacy_curl_hit() {
  echo ""
  echo "==> curl HIT [legacy] (${CURL_REQUESTS} req, ${CURL_WORKERS} workers, no keep-alive)"
  bench_warm_hit
  local -a auth=()
  [[ -n "${CURL_PROXY_USER:-}" ]] && auth=(-U "${CURL_PROXY_USER}")
  local start end rps
  start=$(date +%s.%N)
  seq 1 "${CURL_REQUESTS}" | xargs -P "${CURL_WORKERS}" -I{} \
    curl -sf -o /dev/null -x "${PROXY}" "${auth[@]}" "${HIT_URL}" || true
  end=$(date +%s.%N)
  rps=$(awk -v n="${CURL_REQUESTS}" -v s="$start" -v e="$end" 'BEGIN{printf "%.0f", n/(e-s)}')
  echo "    ~${rps} req/s"
}

run_legacy_curl_miss() {
  echo ""
  echo "==> curl MISS [legacy] (${CURL_REQUESTS} req, ${CURL_WORKERS} workers)"
  local start end rps
  start=$(date +%s.%N)
  export PROXY CURL_PROXY_USER
  seq 1 "${CURL_REQUESTS}" | xargs -P "${CURL_WORKERS}" -I{} \
    bash -c 'args=(-sf -o /dev/null -x "$PROXY"); [[ -n "${CURL_PROXY_USER:-}" ]] && args+=(-U "$CURL_PROXY_USER"); curl "${args[@]}" "$1/$2$RANDOM$RANDOM"' _ "${MISS_URL}" x || true
  end=$(date +%s.%N)
  rps=$(awk -v n="${CURL_REQUESTS}" -v s="$start" -v e="$end" 'BEGIN{printf "%.0f", n/(e-s)}')
  echo "    ~${rps} req/s"
}

bench_proxy_auth_args

echo "############################################"
echo "# ${LABEL} @ ${PROXY}"
echo "############################################"

bench_warm_hit

echo ""
echo "==> wrk L1 HIT (${WRK_DURATION}, ${WRK_CONN_HIT} conn)"
WRK_TARGET_URL="${HIT_URL}" WRK_MISS_MODE=0 \
  wrk -t4 -c"${WRK_CONN_HIT}" -d"${WRK_DURATION}" \
    "${BENCH_PROXY_AUTH_ARGS[@]}" \
    -s "${ROOT}/scripts/wrk-proxy.lua" "${PROXY}" 2>&1 \
  | grep -E 'Requests/sec|Latency|Non-2xx|Socket errors|wrk status' || true

echo ""
echo "==> wrk L1 MISS (${WRK_DURATION}, ${WRK_CONN_MISS} conn)"
WRK_TARGET_URL="${HIT_URL}" WRK_MISS_MODE=1 \
  wrk -t4 -c"${WRK_CONN_MISS}" -d"${WRK_DURATION}" \
    "${BENCH_PROXY_AUTH_ARGS[@]}" \
    -s "${ROOT}/scripts/wrk-proxy.lua" "${PROXY}" 2>&1 \
  | grep -E 'Requests/sec|Latency|Non-2xx|Socket errors|wrk status' || true

echo ""
echo "==> oha L1 HIT (${OHA_DURATION}, ${OHA_CONN_HIT} conn, keep-alive)"
run_oha hit "${OHA_CONN_HIT}" | print_oha_summary

echo ""
echo "==> oha L1 MISS (${OHA_DURATION}, ${OHA_CONN_MISS} conn, unique URLs)"
run_oha miss "${OHA_CONN_MISS}" | print_oha_summary

if [[ "$BENCH_LEGACY_CURL" == "1" ]]; then
  run_legacy_curl_hit
  run_legacy_curl_miss
fi
