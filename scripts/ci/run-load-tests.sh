#!/usr/bin/env bash
# Reproducible Docker-based load-test stage for Jenkins and GitHub Actions.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.lite.yml}"
RESULTS_DIR="${RESULTS_DIR:-${ROOT}/load-test-results}"
COMPOSE=(docker compose -f "$COMPOSE_FILE")

for command_name in docker curl wrk; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required command is not available: ${command_name}" >&2
    exit 1
  fi
done
docker compose version >/dev/null
docker buildx version >/dev/null

cleanup() {
  "${COMPOSE[@]}" down -v || true
}

on_exit() {
  local status=$?
  trap - EXIT
  if (( status != 0 )); then
    show_logs
  fi
  cleanup
  exit "$status"
}

show_logs() {
  "${COMPOSE[@]}" ps || true
  "${COMPOSE[@]}" logs --no-color proxy cache-indexer mock-upstream || true
}

wait_for_http() {
  local name="$1"
  local url="$2"
  local attempt
  for attempt in $(seq 1 60); do
    if curl --fail --silent --show-error --head "$url" >/dev/null; then
      echo "${name} is ready"
      return 0
    fi
    sleep 1
  done
  echo "${name} did not become ready: ${url}" >&2
  show_logs
  return 1
}

trap on_exit EXIT
trap 'exit 130' INT TERM

./scripts/gen-ca.sh
if ! "${COMPOSE[@]}" up -d --build mock-upstream; then
  echo "failed to start the lite load-test stack" >&2
  exit 1
fi
wait_for_http "proxy" "http://127.0.0.1:9090/health"
wait_for_http "mock upstream" "http://127.0.0.1:18080/ping"

PROXY="http://127.0.0.1:3128" \
METRICS_URL="http://127.0.0.1:9090" \
UPSTREAM="http://127.0.0.1:18080" \
  ./scripts/run-load-test.sh

CONCURRENT_USERS="${CONCURRENT_USERS:-20}" \
TEST_DURATION="${TEST_DURATION:-20}" \
PROXY="http://127.0.0.1:3128" \
METRICS_URL="http://127.0.0.1:9090" \
SNI_URL="http://127.0.0.1:18080/get" \
MITM_URL="http://127.0.0.1:18080/get" \
HTTP_URL="http://127.0.0.1:18080/get" \
WRITE_RESULTS=1 \
RESULTS_DIR="$RESULTS_DIR" \
  ./scripts/run-hybrid-load-test.sh

cat "${RESULTS_DIR}/latest.md"
wrk -t"${WRK_THREADS:-2}" -c"${WRK_CONNECTIONS:-100}" \
  -d"${WRK_DURATION:-30s}" -s ./scripts/wrk-proxy.lua http://127.0.0.1:3128
docker stats --no-stream
