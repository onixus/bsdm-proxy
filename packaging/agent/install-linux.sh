#!/usr/bin/env bash
# Install BSDM Local Policy Agent on Linux (pilot / lab / fleet silent).
# Usage:
#   sudo ./packaging/agent/install-linux.sh [--prefix /opt/bsdm-agent] [--bin path/to/bsdm-agent]
#   sudo ./packaging/agent/install-linux.sh --set-system-proxy
# Fleet (MDM / Ansible) — pass tokens WITHOUT putting them in argv:
#   CONTROL_API_TOKEN=... AGENT_ENROLL_TOKEN=... \
#     sudo -E ./packaging/agent/install-linux.sh --silent \
#       --control-plane-url https://control.example:9090 \
#       --device-id "$(hostname -s)" --enable --set-system-proxy
#   # or from 0600 files (best for MDM that drops secrets on disk):
#   sudo ./packaging/agent/install-linux.sh --silent \
#     --control-token-file /run/secrets/bsdm-control-token \
#     --enroll-token-file /run/secrets/bsdm-enroll-token ...
# --control-token/--enroll-token still work but are deprecated: argv is visible
# to every local user via ps(1) and lands in process accounting / audit logs.
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

# Every "--opt VALUE" goes through this so that a missing value produces a
# readable error instead of `shift 2` blowing up (or, worse, the next option
# being consumed as the value). Mirrors scripts/gen-ca.sh / rotate-ca.sh.
need_value() {
  [[ "$2" -ge 2 ]] || { echo "error: $1 requires a value" >&2; exit 2; }
}

read_secret_file() {
  # read_secret_file <path> ; prints the first line, refuses group/world access.
  local path="$1" mode
  [[ -f "$path" ]] || { echo "error: token file not found: ${path}" >&2; exit 2; }
  mode="$(stat -c '%a' "$path" 2>/dev/null || echo '')"
  if [[ -n "$mode" && "$mode" != "600" && "$mode" != "400" ]]; then
    echo "error: ${path} must be 0600 or 0400 (found 0${mode})" >&2
    exit 2
  fi
  IFS= read -r line < "$path" || true
  printf '%s' "$line"
}

warn_argv_token() {
  echo "warning: $1 puts the token in argv, visible to any local user via ps(1)." >&2
  echo "         Prefer the ${2} environment variable or ${1}-file." >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) need_value "$1" "$#"; PREFIX="$2"; shift 2 ;;
    --etc) need_value "$1" "$#"; ETC_DIR="$2"; shift 2 ;;
    --bin) need_value "$1" "$#"; BIN_SRC="$2"; shift 2 ;;
    --set-system-proxy) SET_PROXY=true; shift ;;
    --clear-system-proxy) CLEAR_PROXY=true; shift ;;
    --skip-user) SKIP_USER=true; shift ;;
    --silent) SILENT=true; shift ;;
    --enable) ENABLE_SERVICE=true; shift ;;
    --control-plane-url) need_value "$1" "$#"; CONTROL_PLANE_URL="$2"; shift 2 ;;
    --control-token)
      need_value "$1" "$#"
      warn_argv_token --control-token CONTROL_API_TOKEN
      CONTROL_API_TOKEN="$2"; shift 2 ;;
    --control-token-file)
      need_value "$1" "$#"
      CONTROL_API_TOKEN="$(read_secret_file "$2")"; shift 2 ;;
    --enroll-token)
      need_value "$1" "$#"
      warn_argv_token --enroll-token AGENT_ENROLL_TOKEN
      AGENT_ENROLL_TOKEN="$2"; shift 2 ;;
    --enroll-token-file)
      need_value "$1" "$#"
      AGENT_ENROLL_TOKEN="$(read_secret_file "$2")"; shift 2 ;;
    --device-id) need_value "$1" "$#"; DEVICE_ID="$2"; shift 2 ;;
    --device-name) need_value "$1" "$#"; DEVICE_NAME="$2"; shift 2 ;;
    --system-proxy-host) need_value "$1" "$#"; SYSTEM_PROXY_HOST="$2"; shift 2 ;;
    --system-proxy-port) need_value "$1" "$#"; SYSTEM_PROXY_PORT="$2"; shift 2 ;;
    -h|--help)
      awk '/^set -euo pipefail$/ { exit } NR > 1' "$0"
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
# No `|| true`: agent.env holds CONTROL_API_TOKEN / AGENT_ENROLL_TOKEN. If the
# permissions cannot be tightened, aborting is strictly better than leaving a
# world-readable token behind and reporting success.
chmod 0640 "${ETC_DIR}/agent.env"

if [[ "${SKIP_USER}" != true ]]; then
  if ! id bsdm-agent &>/dev/null; then
    # No `|| true`: a swallowed useradd failure used to surface much later as
    # "install -o bsdm-agent: invalid user" or a unit that never starts.
    useradd --system --home /var/lib/bsdm-agent --shell /usr/sbin/nologin bsdm-agent
  fi
  id bsdm-agent >/dev/null 2>&1 || {
    echo "error: system user bsdm-agent does not exist after useradd" >&2
    exit 1
  }
  install -d -m 0750 -o bsdm-agent -g bsdm-agent /var/lib/bsdm-agent
  chown root:bsdm-agent "${ETC_DIR}/agent.env"
fi

if [[ -d /etc/systemd/system ]]; then
  # The unit now hard-requires EnvironmentFile=/etc/bsdm-agent/agent.env (no
  # leading '-'), so a non-default --prefix/--etc has to be reflected in it,
  # otherwise the service fails to start instead of silently enrolling against
  # the built-in default control plane.
  for p in "$PREFIX" "$ETC_DIR"; do
    [[ "$p" == /* && "$p" != *".."* && "$p" =~ ^[A-Za-z0-9._/-]+$ ]] || {
      echo "error: --prefix/--etc must be absolute paths without '..' or shell/sed metacharacters: ${p}" >&2
      exit 2
    }
  done
  unit_tmp="$(mktemp)"
  sed -e "s|/opt/bsdm-agent|${PREFIX}|g" \
    -e "s|/etc/bsdm-agent|${ETC_DIR}|g" \
    "${ROOT}/packaging/agent/systemd/bsdm-agent.service" \
    >"${unit_tmp}"
  install -m 0644 "${unit_tmp}" /etc/systemd/system/bsdm-agent.service
  rm -f "${unit_tmp}"
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
