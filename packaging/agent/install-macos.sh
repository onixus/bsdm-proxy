#!/usr/bin/env bash
# Install BSDM Local Policy Agent on macOS (pilot / lab / fleet silent).
# Usage:
#   sudo ./packaging/agent/install-macos.sh [--prefix /usr/local/bsdm-agent]
#   sudo ./packaging/agent/install-macos.sh --set-system-proxy
# Fleet (Jamf / MDM script):
#   sudo ./packaging/agent/install-macos.sh --silent \
#     --control-plane-url https://control.example:9090 \
#     --control-token "$CONTROL_API_TOKEN" --enroll-token "$AGENT_ENROLL_TOKEN" \
#     --device-id "$(scutil --get LocalHostName)" --set-system-proxy
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREFIX="${PREFIX:-/usr/local/bsdm-agent}"
ETC_DIR="${ETC_DIR:-/usr/local/etc/bsdm-agent}"
BIN_SRC=""
SET_PROXY=false
CLEAR_PROXY=false
INSTALL_LAUNCHD=true
SILENT=false
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
    --no-launchd) INSTALL_LAUNCHD=false; shift ;;
    --silent) SILENT=true; shift ;;
    --control-plane-url) CONTROL_PLANE_URL="$2"; shift 2 ;;
    --control-token) CONTROL_API_TOKEN="$2"; shift 2 ;;
    --enroll-token) AGENT_ENROLL_TOKEN="$2"; shift 2 ;;
    --device-id) DEVICE_ID="$2"; shift 2 ;;
    --device-name) DEVICE_NAME="$2"; shift 2 ;;
    --system-proxy-host) SYSTEM_PROXY_HOST="$2"; shift 2 ;;
    --system-proxy-port) SYSTEM_PROXY_PORT="$2"; shift 2 ;;
    -h|--help)
      sed -n '1,16p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "error: run as root (sudo) for /usr/local install" >&2
  exit 1
fi

if [[ -z "${BIN_SRC}" ]]; then
  if [[ -x "${ROOT}/target/release/agent-spike" ]]; then
    BIN_SRC="${ROOT}/target/release/agent-spike"
  else
    echo "Building agent-spike (release)..."
    (cd "${ROOT}" && cargo build -p agent-spike --release)
    BIN_SRC="${ROOT}/target/release/agent-spike"
  fi
fi

if [[ "${SILENT}" == true && -z "${CONTROL_PLANE_URL}" ]]; then
  echo "error: --silent requires --control-plane-url (or CONTROL_PLANE_URL env)" >&2
  exit 2
fi

install -d -m 0755 "${PREFIX}/bin"
install -m 0755 "${BIN_SRC}" "${PREFIX}/bin/bsdm-agent"
install -d -m 0755 "${ETC_DIR}"
install -d -m 0755 /usr/local/var/log
if [[ ! -f "${ETC_DIR}/agent.env" ]]; then
  install -m 0644 "${ROOT}/packaging/agent/agent.env.example" "${ETC_DIR}/agent.env"
  [[ "${SILENT}" == true ]] || echo "Wrote ${ETC_DIR}/agent.env — edit CONTROL_PLANE_URL / tokens"
fi

upsert_env() {
  local key="$1" val="$2" file="$3"
  [[ -n "${val}" ]] || return 0
  if grep -qE "^${key}=" "${file}" 2>/dev/null; then
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

# LaunchAgent for current console user when possible; else system LaunchDaemon path note.
if [[ "${INSTALL_LAUNCHD}" == true ]]; then
  PLIST_SRC="${ROOT}/packaging/agent/launchd/com.bsdm.agent.plist"
  # Inject env file via wrapper
  WRAP="${PREFIX}/bin/bsdm-agent-launch"
  cat > "${WRAP}" <<EOF
#!/bin/bash
set -a
[[ -f ${ETC_DIR}/agent.env ]] && source ${ETC_DIR}/agent.env
set +a
exec ${PREFIX}/bin/bsdm-agent "\$@"
EOF
  chmod 0755 "${WRAP}"
  install -m 0644 "${PLIST_SRC}" /Library/LaunchDaemons/com.bsdm.agent.plist
  # Point ProgramArguments at wrapper
  /usr/libexec/PlistBuddy -c "Set :ProgramArguments:0 ${WRAP}" /Library/LaunchDaemons/com.bsdm.agent.plist 2>/dev/null \
    || true
  launchctl bootout system/com.bsdm.agent 2>/dev/null || true
  if ! launchctl bootstrap system /Library/LaunchDaemons/com.bsdm.agent.plist 2>/dev/null \
    && ! launchctl load -w /Library/LaunchDaemons/com.bsdm.agent.plist 2>/dev/null; then
    if [[ "${SILENT}" == true ]]; then
      echo "error: failed to load LaunchDaemon com.bsdm.agent" >&2
      exit 1
    fi
    echo "note: load LaunchDaemon manually after editing ${ETC_DIR}/agent.env"
  fi
fi

AGENT_BIN="${PREFIX}/bin/bsdm-agent"
if [[ "${SET_PROXY}" == true ]]; then
  set -a; source "${ETC_DIR}/agent.env" 2>/dev/null || true; set +a
  if ! "${AGENT_BIN}" --set-system-proxy; then
    [[ "${SILENT}" == true ]] && exit 1
    echo "warning: networksetup may need an interactive admin"
  fi
fi
if [[ "${CLEAR_PROXY}" == true ]]; then
  "${AGENT_BIN}" --clear-system-proxy || true
fi

if [[ "${SILENT}" != true ]]; then
  echo "Installed bsdm-agent → ${PREFIX}/bin/bsdm-agent"
  echo "Config → ${ETC_DIR}/agent.env"
  echo "System proxy: ${AGENT_BIN} --set-system-proxy | --clear-system-proxy"
fi
