#!/usr/bin/env bash
# Install BSDM Local Policy Agent on Linux (pilot / lab / fleet silent).
# Usage:
#   sudo ./packaging/agent/install-linux.sh [--prefix /opt/bsdm-agent] [--bin path/to/bsdm-agent]
#   sudo ./packaging/agent/install-linux.sh --set-system-proxy
# Fleet (MDM / Ansible):
#   sudo ./packaging/agent/install-linux.sh --silent \
#     --control-plane-url https://control.example:9090 \
#     --control-token "$CONTROL_API_TOKEN" \
#     --enroll-token "$AGENT_ENROLL_TOKEN" \
#     --device-id "$(hostname -s)" \
#     --enable --set-system-proxy
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREFIX="${PREFIX:-/opt/bsdm-agent}"
ETC_DIR="${ETC_DIR:-/etc/bsdm-agent}"
BIN_SRC=""
SET_PROXY=false
CLEAR_PROXY=false
SKIP_USER=false
SILENT=false
ENABLE_SERVICE=false
CONTROL_PLANE_URL="${CONTROL_PLANE_URL:-}"
CONTROL_API_TOKEN="${CONTROL_API_TOKEN:-}"
AGENT_ENROLL_TOKEN="${AGENT_ENROLL_TOKEN:-}"
DEVICE_ID="${DEVICE_ID:-}"
DEVICE_NAME="${DEVICE_NAME:-}"
SYSTEM_PROXY_HOST="${SYSTEM_PROXY_HOST:-}"
SYSTEM_PROXY_PORT="${SYSTEM_PROXY_PORT:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --etc) ETC_DIR="$2"; shift 2 ;;
    --bin) BIN_SRC="$2"; shift 2 ;;
    --set-system-proxy) SET_PROXY=true; shift ;;
    --clear-system-proxy) CLEAR_PROXY=true; shift ;;
    --skip-user) SKIP_USER=true; shift ;;
    --silent) SILENT=true; shift ;;
    --enable) ENABLE_SERVICE=true; shift ;;
    --control-plane-url) CONTROL_PLANE_URL="$2"; shift 2 ;;
    --control-token) CONTROL_API_TOKEN="$2"; shift 2 ;;
    --enroll-token) AGENT_ENROLL_TOKEN="$2"; shift 2 ;;
    --device-id) DEVICE_ID="$2"; shift 2 ;;
    --device-name) DEVICE_NAME="$2"; shift 2 ;;
    --system-proxy-host) SYSTEM_PROXY_HOST="$2"; shift 2 ;;
    --system-proxy-port) SYSTEM_PROXY_PORT="$2"; shift 2 ;;
    -h|--help)
      sed -n '1,20p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "error: run as root (sudo)" >&2
  exit 1
fi

if [[ -z "${BIN_SRC}" ]]; then
  if [[ -x "${ROOT}/target/release/bsdm-agent" ]]; then
    BIN_SRC="${ROOT}/target/release/bsdm-agent"
  elif [[ -x "${ROOT}/target/release/agent-spike" ]]; then
    BIN_SRC="${ROOT}/target/release/agent-spike"
  else
    echo "Building bsdm-agent (release)..."
    (cd "${ROOT}" && cargo build -p agent-spike --release --bin bsdm-agent)
    BIN_SRC="${ROOT}/target/release/bsdm-agent"
  fi
fi

if [[ "${SILENT}" == true && -z "${CONTROL_PLANE_URL}" ]]; then
  echo "error: --silent requires --control-plane-url (or CONTROL_PLANE_URL env)" >&2
  exit 2
fi

install -d -m 0755 "${PREFIX}/bin"
install -m 0755 "${BIN_SRC}" "${PREFIX}/bin/bsdm-agent"
install -d -m 0755 "${ETC_DIR}"
if [[ ! -f "${ETC_DIR}/agent.env" ]]; then
  install -m 0640 "${ROOT}/packaging/agent/agent.env.example" "${ETC_DIR}/agent.env"
  [[ "${SILENT}" == true ]] || echo "Wrote ${ETC_DIR}/agent.env — edit CONTROL_PLANE_URL / tokens"
fi

# Fleet: merge CLI/env into agent.env (upsert keys; do not dump secrets to stdout).
upsert_env() {
  local key="$1" val="$2" file="$3"
  [[ -n "${val}" ]] || return 0
  if grep -qE "^${key}=" "${file}" 2>/dev/null; then
    # portable-ish: rewrite file without the key, then append
    local tmp
    tmp="$(mktemp)"
    grep -vE "^${key}=" "${file}" >"${tmp}" || true
    printf '%s=%s\n' "${key}" "${val}" >>"${tmp}"
    cat "${tmp}" >"${file}"
    rm -f "${tmp}"
  else
    printf '%s=%s\n' "${key}" "${val}" >>"${file}"
  fi
}
upsert_env CONTROL_PLANE_URL "${CONTROL_PLANE_URL}" "${ETC_DIR}/agent.env"
upsert_env CONTROL_API_TOKEN "${CONTROL_API_TOKEN}" "${ETC_DIR}/agent.env"
upsert_env AGENT_ENROLL_TOKEN "${AGENT_ENROLL_TOKEN}" "${ETC_DIR}/agent.env"
upsert_env DEVICE_ID "${DEVICE_ID}" "${ETC_DIR}/agent.env"
upsert_env DEVICE_NAME "${DEVICE_NAME:-${DEVICE_ID}}" "${ETC_DIR}/agent.env"
upsert_env SYSTEM_PROXY_HOST "${SYSTEM_PROXY_HOST}" "${ETC_DIR}/agent.env"
upsert_env SYSTEM_PROXY_PORT "${SYSTEM_PROXY_PORT}" "${ETC_DIR}/agent.env"
chmod 0640 "${ETC_DIR}/agent.env" || true

if [[ "${SKIP_USER}" != true ]]; then
  if ! id bsdm-agent &>/dev/null; then
    useradd --system --home /var/lib/bsdm-agent --shell /usr/sbin/nologin bsdm-agent || true
  fi
  install -d -m 0750 -o bsdm-agent -g bsdm-agent /var/lib/bsdm-agent
  chown root:bsdm-agent "${ETC_DIR}/agent.env" || true
fi

if [[ -d /etc/systemd/system ]]; then
  install -m 0644 "${ROOT}/packaging/agent/systemd/bsdm-agent.service" /etc/systemd/system/bsdm-agent.service
  systemctl daemon-reload
  if [[ "${ENABLE_SERVICE}" == true ]]; then
    systemctl enable --now bsdm-agent
  else
    [[ "${SILENT}" == true ]] || echo "systemd unit installed: systemctl enable --now bsdm-agent"
  fi
fi

AGENT_BIN="${PREFIX}/bin/bsdm-agent"
if [[ "${SET_PROXY}" == true ]]; then
  # shellcheck disable=SC1091
  set -a; source "${ETC_DIR}/agent.env" 2>/dev/null || true; set +a
  if ! "${AGENT_BIN}" --set-system-proxy; then
    [[ "${SILENT}" == true ]] && exit 1
    echo "warning: system proxy set failed (desktop session?)"
  fi
fi
if [[ "${CLEAR_PROXY}" == true ]]; then
  "${AGENT_BIN}" --clear-system-proxy || true
fi

if [[ "${SILENT}" != true ]]; then
  echo "Installed bsdm-agent → ${PREFIX}/bin/bsdm-agent"
  echo "Config → ${ETC_DIR}/agent.env"
  echo "Next: edit env, then: systemctl enable --now bsdm-agent"
  echo "System proxy: ${AGENT_BIN} --set-system-proxy | --clear-system-proxy"
fi
