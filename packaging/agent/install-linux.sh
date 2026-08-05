#!/usr/bin/env bash
# Install BSDM Local Policy Agent on Linux (pilot / lab).
# Usage:
#   sudo ./packaging/agent/install-linux.sh [--prefix /opt/bsdm-agent] [--bin path/to/bsdm-agent]
#   sudo ./packaging/agent/install-linux.sh --set-system-proxy
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREFIX="${PREFIX:-/opt/bsdm-agent}"
ETC_DIR="${ETC_DIR:-/etc/bsdm-agent}"
BIN_SRC=""
SET_PROXY=false
CLEAR_PROXY=false
SKIP_USER=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --etc) ETC_DIR="$2"; shift 2 ;;
    --bin) BIN_SRC="$2"; shift 2 ;;
    --set-system-proxy) SET_PROXY=true; shift ;;
    --clear-system-proxy) CLEAR_PROXY=true; shift ;;
    --skip-user) SKIP_USER=true; shift ;;
    -h|--help)
      sed -n '1,12p' "$0"
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
if [[ ! -f "${ETC_DIR}/agent.env" ]]; then
  install -m 0640 "${ROOT}/packaging/agent/agent.env.example" "${ETC_DIR}/agent.env"
  echo "Wrote ${ETC_DIR}/agent.env — edit CONTROL_PLANE_URL / tokens"
fi

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
  echo "systemd unit installed: systemctl enable --now bsdm-agent"
fi

AGENT_BIN="${PREFIX}/bin/bsdm-agent"
if [[ "${SET_PROXY}" == true ]]; then
  # shellcheck disable=SC1091
  set -a; source "${ETC_DIR}/agent.env" 2>/dev/null || true; set +a
  "${AGENT_BIN}" --set-system-proxy || echo "warning: system proxy set failed (desktop session?)"
fi
if [[ "${CLEAR_PROXY}" == true ]]; then
  "${AGENT_BIN}" --clear-system-proxy || true
fi

echo "Installed bsdm-agent → ${PREFIX}/bin/bsdm-agent"
echo "Config → ${ETC_DIR}/agent.env"
echo "Next: edit env, then: systemctl enable --now bsdm-agent"
echo "System proxy: ${AGENT_BIN} --set-system-proxy | --clear-system-proxy"
