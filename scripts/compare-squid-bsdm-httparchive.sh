#!/usr/bin/env bash
# Squid vs BSDM — HTTP Archive Top 1k sites (70 random, 12 conn, 20 warm repeats).
#
# Bench profiles (see scripts/bench-profile.sh):
#   BENCH_PROFILE=warm  WORKER_COUNT=1  — warm-heavy goodput (default)
#   BENCH_PROFILE=cold  WORKER_COUNT=4  — cold/MISS parallelism
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck source=bench-profile.sh
source "${ROOT}/scripts/bench-profile.sh"
apply_bench_profile

SQUID_CONF="${SQUID_CONF:-${ROOT}/scripts/squid-benchmark-tuned.conf}"
SQUID_PORT=13128
BSDM_PORT=12788
BSDM_METRICS=19190
MOCK_PORT=18080
DEVICE="${HTTPARCHIVE_DEVICE:-desktop}"
UPSTREAM="http://127.0.0.1:${MOCK_PORT}"
PAGE_CONCURRENCY="${PAGE_CONCURRENCY:-12}"
BENCH_SITES="${BENCH_SITES:-70}"
BENCH_WARM_REPEATS="${BENCH_WARM_REPEATS:-20}"
BENCH_SITE_SEED="${BENCH_SITE_SEED:-42}"
BSDM_BIN="${BSDM_BIN:-$ROOT/target/release/proxy}"

BENCH_ARGS=(
  --upstream "${UPSTREAM}"
  --device "${DEVICE}"
  --sites "${BENCH_SITES}"
  --concurrency "${PAGE_CONCURRENCY}"
  --warm-repeats "${BENCH_WARM_REPEATS}"
  --seed "${BENCH_SITE_SEED}"
)

stop_squid() {
  sudo killall squid 2>/dev/null || true
  sudo rm -f /run/squid.pid
  sleep 1
}

start_squid() {
  stop_squid
  sudo mkdir -p /var/spool/squid /var/log/squid
  sudo chown proxy:proxy /var/spool/squid /var/log/squid 2>/dev/null \
    || sudo chown squid:squid /var/spool/squid /var/log/squid
  # Optional rock dir (only used if conf has cache_dir rock)
  sudo mkdir -p /var/spool/squid-rock
  sudo chown proxy:proxy /var/spool/squid-rock 2>/dev/null || true
  sudo squid -k parse -f "$SQUID_CONF"
  if grep -qE '^[[:space:]]*cache_dir[[:space:]]' "$SQUID_CONF"; then
    sudo squid -z -f "$SQUID_CONF" 2>&1 | tail -3
    sleep 2
    sudo killall squid 2>/dev/null || true
    sudo rm -f /run/squid.pid
    sleep 1
  fi
  sudo squid -f "$SQUID_CONF"
  for _ in $(seq 1 30); do
    if curl -sf -x "http://127.0.0.1:${SQUID_PORT}" "${UPSTREAM}/ping" >/dev/null 2>&1; then
      echo "Squid ready (${SQUID_PORT}), workers: $(pgrep -c -x squid || echo ?)"
      return 0
    fi
    sleep 1
  done
  echo "Squid failed to start" >&2
  sudo tail -40 /var/log/squid/cache.log 2>/dev/null || true
  exit 1
}

start_mock() {
  tmux -f /exec-daemon/tmux.portal.conf kill-session -t ha-compare-mock 2>/dev/null || true
  tmux -f /exec-daemon/tmux.portal.conf kill-session -t load-mock 2>/dev/null || true
  pkill -f 'mock-upstream-threaded.py' 2>/dev/null || true
  pkill -f 'mock-upstream-httparchive.py' 2>/dev/null || true
  sleep 1
  tmux -f /exec-daemon/tmux.portal.conf new-session -d -s ha-compare-mock \
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
  echo "HTTP Archive mock failed" >&2
  exit 1
}

start_bsdm() {
  tmux -f /exec-daemon/tmux.portal.conf kill-session -t ha-compare-bsdm 2>/dev/null || true
  pkill -f 'target/release/proxy' 2>/dev/null || true
  sleep 1
  local env_cmd="MITM_ENABLED=false HIERARCHY_ENABLED=false RUST_LOG=warn"
  env_cmd+=" PERF_FAST_CACHE_HIT=${PERF_FAST_CACHE_HIT}"
  env_cmd+=" WORKER_COUNT=${WORKER_COUNT}"
  env_cmd+=" CACHE_SHARDS=${CACHE_SHARDS}"
  env_cmd+=" METRICS_SAMPLE_RATE=${METRICS_SAMPLE_RATE}"
  env_cmd+=" HTTP_PRESERVE_HEADER_CASE=${HTTP_PRESERVE_HEADER_CASE}"
  tmux -f /exec-daemon/tmux.portal.conf new-session -d -s ha-compare-bsdm -c "$ROOT" -- \
    "${SHELL:-bash}" -lc \
    "${env_cmd} HTTP_PORT=${BSDM_PORT} METRICS_PORT=${BSDM_METRICS} ${BSDM_BIN}"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -sf "http://127.0.0.1:${BSDM_METRICS}/health" >/dev/null 2>&1; then
      echo "BSDM ready (${BSDM_PORT})"
      return 0
    fi
    sleep 1
  done
  echo "BSDM failed to start" >&2
  exit 1
}

run_sites_bench() {
  local label="$1"
  local proxy="$2"
  local outfile="$3"
  {
    echo "############################################"
    echo "# ${label} @ ${proxy}"
    echo "# profile: $(print_bench_profile)"
    echo "# sites=${BENCH_SITES} concurrency=${PAGE_CONCURRENCY} warm=${BENCH_WARM_REPEATS} seed=${BENCH_SITE_SEED}"
    echo "############################################"
    python3 "${ROOT}/scripts/httparchive-sites-bench.py" \
      --proxy "${proxy}" \
      "${BENCH_ARGS[@]}"
  } | tee "${outfile}"
}

cleanup() {
  stop_squid
  tmux -f /exec-daemon/tmux.portal.conf kill-session -t ha-compare-mock 2>/dev/null || true
  tmux -f /exec-daemon/tmux.portal.conf kill-session -t ha-compare-bsdm 2>/dev/null || true
  pkill -f 'mock-upstream-httparchive.py' 2>/dev/null || true
  pkill -f 'target/release/proxy' 2>/dev/null || true
}
trap cleanup EXIT

python3 "${ROOT}/scripts/httparchive_profile.py"
cargo build --release -p bsdm-proxy --bin proxy 2>&1 | tail -2

echo "Bench profile: $(print_bench_profile)"

start_mock

echo ""
echo "========== SQUID (HTTP Archive sites) =========="
start_squid
run_sites_bench "squid-tuned" "http://127.0.0.1:${SQUID_PORT}" /tmp/bench-httparchive-squid.txt
stop_squid

echo ""
echo "========== BSDM (HTTP Archive sites) =========="
start_bsdm
BSDM_OUT="/tmp/bench-httparchive-bsdm-${BENCH_PROFILE}.txt"
run_sites_bench "bsdm-${BENCH_PROFILE}" "http://127.0.0.1:${BSDM_PORT}" "${BSDM_OUT}"

echo ""
echo "Done."
echo "  Squid: /tmp/bench-httparchive-squid.txt"
echo "  BSDM:  ${BSDM_OUT} ($(print_bench_profile))"
