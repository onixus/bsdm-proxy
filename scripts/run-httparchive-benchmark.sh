#!/usr/bin/env bash
# Benchmark BSDM-Proxy with HTTP Archive Top 1k median page loads.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROXY_PORT="${PROXY_PORT:-12788}"
METRICS_PORT="${METRICS_PORT:-19190}"
MOCK_PORT="${MOCK_PORT:-18080}"
DEVICE="${HTTPARCHIVE_DEVICE:-desktop}"
PROXY="http://127.0.0.1:${PROXY_PORT}"
UPSTREAM="http://127.0.0.1:${MOCK_PORT}"
LABEL="${1:-httparchive-${DEVICE}}"
BSDM_BIN="${BSDM_BIN:-$ROOT/target/release/proxy}"
PAGE_CONCURRENCY="${PAGE_CONCURRENCY:-12}"
BENCH_SITES="${BENCH_SITES:-70}"
BENCH_WARM_REPEATS="${BENCH_WARM_REPEATS:-20}"
BENCH_SITE_SEED="${BENCH_SITE_SEED:-42}"

kill_all() {
  tmux -f /exec-daemon/tmux.portal.conf kill-session -t ha-bench-proxy 2>/dev/null || true
  tmux -f /exec-daemon/tmux.portal.conf kill-session -t ha-bench-mock 2>/dev/null || true
  tmux -f /exec-daemon/tmux.portal.conf kill-session -t load-mock 2>/dev/null || true
  pkill -f 'mock-upstream-httparchive.py' 2>/dev/null || true
  pkill -f 'mock-upstream-threaded.py' 2>/dev/null || true
  pkill -f 'target/release/proxy' 2>/dev/null || true
  sleep 1
}

start_mock() {
  tmux -f /exec-daemon/tmux.portal.conf kill-session -t ha-bench-mock 2>/dev/null || true
  tmux -f /exec-daemon/tmux.portal.conf kill-session -t load-mock 2>/dev/null || true
  pkill -f 'mock-upstream-threaded.py' 2>/dev/null || true
  sleep 1
  tmux -f /exec-daemon/tmux.portal.conf new-session -d -s ha-bench-mock \
    "${SHELL:-bash}" -lc \
    "HTTPARCHIVE_DEVICE=${DEVICE} MOCK_PORT=${MOCK_PORT} python3 ${ROOT}/scripts/mock-upstream-httparchive.py"
  for _ in 1 2 3 4 5; do
    if curl -sf "${UPSTREAM}/ping" >/dev/null 2>&1 \
      && curl -sf -r 0-15 "${UPSTREAM}/httparchive/site/0001/${DEVICE}/page.html" -o /dev/null; then
      echo "HTTP Archive mock ready (${DEVICE})"
      return 0
    fi
    sleep 1
  done
  echo "HTTP Archive mock failed to start" >&2
  exit 1
}

start_proxy() {
  tmux -f /exec-daemon/tmux.portal.conf kill-session -t ha-bench-proxy 2>/dev/null || true
  local env_cmd="MITM_ENABLED=false HIERARCHY_ENABLED=false RUST_LOG=warn"
  env_cmd+=" PERF_FAST_CACHE_HIT=${PERF_FAST_CACHE_HIT:-true}"
  env_cmd+=" WORKER_COUNT=${WORKER_COUNT:-4}"
  env_cmd+=" METRICS_SAMPLE_RATE=${METRICS_SAMPLE_RATE:-100}"
  env_cmd+=" HTTP_PRESERVE_HEADER_CASE=${HTTP_PRESERVE_HEADER_CASE:-false}"
  tmux -f /exec-daemon/tmux.portal.conf new-session -d -s ha-bench-proxy -c "$ROOT" -- \
    "${SHELL:-bash}" -lc \
    "${env_cmd} HTTP_PORT=${PROXY_PORT} METRICS_PORT=${METRICS_PORT} ${BSDM_BIN}"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -sf "http://127.0.0.1:${METRICS_PORT}/health" >/dev/null 2>&1; then
      echo "Proxy ready on ${PROXY}"
      return 0
    fi
    sleep 1
  done
  echo "Proxy failed to start" >&2
  exit 1
}

validate_profile() {
  python3 "${ROOT}/scripts/httparchive_profile.py"
}

run_sites_bench() {
  echo ""
  echo "==> sites bench (sites=${BENCH_SITES}, concurrency=${PAGE_CONCURRENCY}, warm=${BENCH_WARM_REPEATS})"
  python3 "${ROOT}/scripts/httparchive-sites-bench.py" \
    --proxy "${PROXY}" \
    --upstream "${UPSTREAM}" \
    --device "${DEVICE}" \
    --sites "${BENCH_SITES}" \
    --concurrency "${PAGE_CONCURRENCY}" \
    --warm-repeats "${BENCH_WARM_REPEATS}" \
    --seed "${BENCH_SITE_SEED}" \
    ${CURL_PROXY_USER:+--proxy-user "${CURL_PROXY_USER}"}
}

trap kill_all EXIT

validate_profile
cargo build --release -p bsdm-proxy --bin proxy 2>&1 | tail -2
kill_all
start_mock
start_proxy

echo "############################################"
echo "# HTTP Archive benchmark: ${LABEL}"
echo "# lens=top1k device=${DEVICE}"
echo "# sites=${BENCH_SITES} concurrency=${PAGE_CONCURRENCY} warm=${BENCH_WARM_REPEATS}"
echo "############################################"

run_sites_bench

echo ""
echo "Done (${LABEL})"
