#!/usr/bin/env bash
# Reproducible Docker-based load-test stage for Jenkins and GitHub Actions.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.lite.yml}"
RESULTS_DIR="${RESULTS_DIR:-${ROOT}/load-test-results}"
CERT_DIR="${CERT_DIR:-${ROOT}/certs}"
CA_RUNTIME_UID="${CA_RUNTIME_UID:-1000}"
CA_RUNTIME_GID="${CA_RUNTIME_GID:-1000}"
COMPOSE=(docker compose -f "$COMPOSE_FILE")

CA_DIR_ORIGINAL_OWNER=""
CA_KEY_ORIGINAL_OWNER=""
CA_CERT_ORIGINAL_OWNER=""
CA_OWNERSHIP_CHANGED=0

if [[ ! "$CA_RUNTIME_UID" =~ ^[0-9]+$ || ! "$CA_RUNTIME_GID" =~ ^[0-9]+$ ]]; then
  echo "CA_RUNTIME_UID and CA_RUNTIME_GID must be numeric" >&2
  exit 2
fi

for command_name in docker curl wrk; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required command is not available: ${command_name}" >&2
    exit 1
  fi
done
docker compose version >/dev/null
docker buildx version >/dev/null

run_privileged() {
  if (( EUID == 0 )); then
    "$@"
    return
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo -n "$@"
    return
  fi
  return 1
}

prepare_ca_ownership() {
  local runtime_owner="${CA_RUNTIME_UID}:${CA_RUNTIME_GID}"
  local current_dir_owner current_key_owner current_cert_owner

  for path in "$CERT_DIR" "$CERT_DIR/ca.key" "$CERT_DIR/ca.crt"; do
    if [[ ! -e "$path" ]]; then
      echo "generated CA path is missing: ${path}" >&2
      return 1
    fi
  done

  current_dir_owner="$(stat -c '%u:%g' "$CERT_DIR")"
  current_key_owner="$(stat -c '%u:%g' "$CERT_DIR/ca.key")"
  current_cert_owner="$(stat -c '%u:%g' "$CERT_DIR/ca.crt")"
  CA_DIR_ORIGINAL_OWNER="$current_dir_owner"
  CA_KEY_ORIGINAL_OWNER="$current_key_owner"
  CA_CERT_ORIGINAL_OWNER="$current_cert_owner"

  if [[ "$current_dir_owner" == "$runtime_owner" &&
        "$current_key_owner" == "$runtime_owner" &&
        "$current_cert_owner" == "$runtime_owner" ]]; then
    return 0
  fi

  if ! run_privileged chown \
    "$runtime_owner" "$CERT_DIR" "$CERT_DIR/ca.key" "$CERT_DIR/ca.crt"; then
    echo "cannot assign the generated CA to container owner ${runtime_owner}" >&2
    echo "run the Docker agent as that UID/GID or allow passwordless sudo chown" >&2
    return 1
  fi
  CA_OWNERSHIP_CHANGED=1
}

restore_ca_ownership() {
  if (( CA_OWNERSHIP_CHANGED == 0 )); then
    return 0
  fi

  if ! run_privileged chown "$CA_DIR_ORIGINAL_OWNER" "$CERT_DIR" ||
     ! run_privileged chown "$CA_KEY_ORIGINAL_OWNER" "$CERT_DIR/ca.key" ||
     ! run_privileged chown "$CA_CERT_ORIGINAL_OWNER" "$CERT_DIR/ca.crt"; then
    echo "warning: failed to restore generated CA ownership in ${CERT_DIR}" >&2
    return 1
  fi
  CA_OWNERSHIP_CHANGED=0
}

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
  restore_ca_ownership || true
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
prepare_ca_ownership
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
