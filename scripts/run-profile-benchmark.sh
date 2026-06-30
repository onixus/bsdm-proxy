#!/usr/bin/env bash
# Benchmark baseline / perf / corporate proxy profiles.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PROXY_PORT=12788
METRICS_PORT=19190
BSDM_BIN="$ROOT/target/release/proxy"

kill_proxy() {
  tmux -f /exec-daemon/tmux.portal.conf kill-session -t bench-proxy 2>/dev/null || true
  pkill -f 'target/release/proxy' 2>/dev/null || true
  sleep 1
}

start_proxy() {
  local name="$1"
  shift
  kill_proxy
  local env_cmd=""
  for kv in "$@"; do env_cmd+="$kv "; done
  tmux -f /exec-daemon/tmux.portal.conf new-session -d -s bench-proxy -c "$ROOT" -- \
    "${SHELL:-bash}" -lc "${env_cmd} HTTP_PORT=${PROXY_PORT} METRICS_PORT=${METRICS_PORT} ${BSDM_BIN}"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -sf "http://127.0.0.1:${METRICS_PORT}/health" >/dev/null 2>&1; then
      echo "Proxy [$name] ready"
      return 0
    fi
    sleep 1
  done
  echo "Proxy [$name] failed to start" >&2
  exit 1
}

ensure_upstream() {
  if ! curl -sf http://127.0.0.1:18080/ping >/dev/null 2>&1; then
    tmux -f /exec-daemon/tmux.portal.conf kill-session -t load-mock 2>/dev/null || true
    tmux -f /exec-daemon/tmux.portal.conf new-session -d -s load-mock \
      "python3 ${ROOT}/scripts/mock-upstream-threaded.py"
    sleep 1
  fi
}

run_bench() {
  local label="$1"
  unset WRK_PROXY_AUTH_HEADER CURL_PROXY_USER
  if [[ -n "${2:-}" ]]; then
    export WRK_PROXY_AUTH_HEADER="$2"
    export CURL_PROXY_USER="${3:-}"
  fi
  "$ROOT/scripts/run-proxy-benchmark.sh" "127.0.0.1:${PROXY_PORT}" "$label" \
    | tee "/tmp/bench-${label}.txt"
}

cargo build --release -p bsdm-proxy --bin proxy 2>&1 | tail -2
ensure_upstream

COMMON="MITM_ENABLED=false HIERARCHY_ENABLED=false RUST_LOG=warn"

echo ""
echo "========== PROFILE: baseline =========="
start_proxy baseline "$COMMON"
run_bench baseline-minimal

echo ""
echo "========== PROFILE: perf (PERF_FAST_CACHE_HIT) =========="
start_proxy perf \
  "$COMMON PERF_FAST_CACHE_HIT=true WORKER_COUNT=1 METRICS_SAMPLE_RATE=100 HTTP_PRESERVE_HEADER_CASE=false"
run_bench perf-fast

echo ""
echo "========== PROFILE: corporate (ACL + categorization + auth) =========="
CORP_AUTH_HDR="Proxy-Authorization: Basic $(printf '%s' 'corpuser:corppass' | base64 -w0)"
start_proxy corporate \
  "$COMMON ACL_ENABLED=true ACL_RULES_PATH=${ROOT}/config/acl-rules.example.json ACL_DEFAULT_ACTION=allow CATEGORIZATION_ENABLED=true AUTH_ENABLED=true AUTH_REALM=Corporate PERF_FAST_CACHE_HIT=false HTTP_PRESERVE_HEADER_CASE=true WORKER_COUNT=1"
curl -fsS -x "http://127.0.0.1:${PROXY_PORT}" -U 'corpuser:corppass' \
  "http://127.0.0.1:18080/bench-corporate-full-hit" >/dev/null
run_bench corporate-full "$CORP_AUTH_HDR" 'corpuser:corppass'

kill_proxy
echo "Done. Results in /tmp/bench-*.txt"
