#!/usr/bin/env bash
# Squid (tuned) vs BSDM-Proxy — same wrk/curl scenarios.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SQUID_CONF="${ROOT}/scripts/squid-benchmark-tuned.conf"
SQUID_PORT=13128
BSDM_PORT=12788
BSDM_METRICS=19190

stop_squid() {
  sudo killall squid 2>/dev/null || true
  sudo rm -f /run/squid.pid
  sleep 1
}

start_squid() {
  stop_squid
  sudo mkdir -p /var/spool/squid-rock
  sudo chown proxy:proxy /var/spool/squid-rock 2>/dev/null || sudo chown squid:squid /var/spool/squid-rock
  sudo squid -k parse -f "$SQUID_CONF"
  sudo squid -z -f "$SQUID_CONF" 2>&1 | tail -3
  sudo squid -f "$SQUID_CONF"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -sf -x "http://127.0.0.1:${SQUID_PORT}" http://127.0.0.1:18080/squid-ready >/dev/null 2>&1; then
      echo "Squid ready (${SQUID_PORT}), workers: $(pgrep -c -x squid || echo ?)"
      return 0
    fi
    sleep 1
  done
  echo "Squid failed to start" >&2
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

ensure_bsdm() {
  if ! curl -sf "http://127.0.0.1:${BSDM_METRICS}/health" >/dev/null 2>&1; then
    tmux -f /exec-daemon/tmux.portal.conf kill-session -t load-proxy 2>/dev/null || true
    tmux -f /exec-daemon/tmux.portal.conf new-session -d -s load-proxy \
      "cd ${ROOT} && HTTP_PORT=${BSDM_PORT} METRICS_PORT=${BSDM_METRICS} MITM_ENABLED=false HIERARCHY_ENABLED=false RUST_LOG=warn PERF_FAST_CACHE_HIT=true WORKER_COUNT=1 METRICS_SAMPLE_RATE=100 HTTP_PRESERVE_HEADER_CASE=false ./target/release/proxy"
    sleep 2
  fi
  curl -fsS "http://127.0.0.1:${BSDM_METRICS}/health" | grep -q ok
}

ensure_upstream
ensure_bsdm
start_squid

chmod +x "${ROOT}/scripts/run-proxy-benchmark.sh"

echo ""
"${ROOT}/scripts/run-proxy-benchmark.sh" "127.0.0.1:${SQUID_PORT}" "squid-tuned" | tee /tmp/bench-squid-tuned.txt

echo ""
"${ROOT}/scripts/run-proxy-benchmark.sh" "127.0.0.1:${BSDM_PORT}" "bsdm" | tee /tmp/bench-bsdm-tuned.txt

echo ""
echo "Done. Results: /tmp/bench-squid-tuned.txt /tmp/bench-bsdm-tuned.txt"
