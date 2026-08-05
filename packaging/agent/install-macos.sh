#!/usr/bin/env bash
# Install BSDM Local Policy Agent on macOS (pilot / lab).
# Usage:
#   sudo ./packaging/agent/install-macos.sh [--prefix /usr/local/bsdm-agent]
#   sudo ./packaging/agent/install-macos.sh --set-system-proxy
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREFIX="${PREFIX:-/usr/local/bsdm-agent}"
ETC_DIR="${ETC_DIR:-/usr/local/etc/bsdm-agent}"
BIN_SRC=""
SET_PROXY=false
CLEAR_PROXY=false
INSTALL_LAUNCHD=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --etc) ETC_DIR="$2"; shift 2 ;;
    --bin) BIN_SRC="$2"; shift 2 ;;
    --set-system-proxy) SET_PROXY=true; shift ;;
    --clear-system-proxy) CLEAR_PROXY=true; shift ;;
    --no-launchd) INSTALL_LAUNCHD=false; shift ;;
    -h|--help)
      sed -n '1,10p' "$0"
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

install -d -m 0755 "${PREFIX}/bin"
install -m 0755 "${BIN_SRC}" "${PREFIX}/bin/bsdm-agent"
install -d -m 0755 "${ETC_DIR}"
install -d -m 0755 /usr/local/var/log
if [[ ! -f "${ETC_DIR}/agent.env" ]]; then
  install -m 0644 "${ROOT}/packaging/agent/agent.env.example" "${ETC_DIR}/agent.env"
  echo "Wrote ${ETC_DIR}/agent.env — edit CONTROL_PLANE_URL / tokens"
fi

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
  launchctl bootstrap system /Library/LaunchDaemons/com.bsdm.agent.plist 2>/dev/null \
    || launchctl load -w /Library/LaunchDaemons/com.bsdm.agent.plist 2>/dev/null \
    || echo "note: load LaunchDaemon manually after editing ${ETC_DIR}/agent.env"
fi

AGENT_BIN="${PREFIX}/bin/bsdm-agent"
if [[ "${SET_PROXY}" == true ]]; then
  set -a; source "${ETC_DIR}/agent.env" 2>/dev/null || true; set +a
  "${AGENT_BIN}" --set-system-proxy || echo "warning: networksetup may need an interactive admin"
fi
if [[ "${CLEAR_PROXY}" == true ]]; then
  "${AGENT_BIN}" --clear-system-proxy || true
fi

echo "Installed bsdm-agent → ${PREFIX}/bin/bsdm-agent"
echo "Config → ${ETC_DIR}/agent.env"
echo "System proxy: ${AGENT_BIN} --set-system-proxy | --clear-system-proxy"
