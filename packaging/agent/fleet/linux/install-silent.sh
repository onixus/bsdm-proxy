#!/usr/bin/env bash
# Fleet silent wrapper for Linux MDM / config management.
# Env (required): CONTROL_PLANE_URL
# Env (recommended): CONTROL_API_TOKEN, AGENT_ENROLL_TOKEN, DEVICE_ID, BSDM_AGENT_BIN
#
# Secrets: tokens are forwarded to install-linux.sh through 0600 temp files, not
# through argv — anything in argv is readable by every local user via ps(1) and
# is captured by process accounting / auditd on managed fleets.
# CONTROL_API_TOKEN_FILE / AGENT_ENROLL_TOKEN_FILE (0600, MDM-dropped) are used
# directly when set and take precedence over the environment variables.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
BIN="${BSDM_AGENT_BIN:-}"
ARGS=(--silent --enable)

TMP_SECRETS=""
cleanup() {
  if [[ -n "${TMP_SECRETS}" ]]; then
    rm -rf -- "${TMP_SECRETS}"
  fi
}
trap cleanup EXIT

secret_file_for() {
  # secret_file_for <value> -> path to a 0600 file holding it.
  # NOTE: called inside $( ), i.e. in a subshell — TMP_SECRETS must already be
  # set by the parent shell, otherwise the directory leaks past the EXIT trap.
  local f
  f="$(mktemp "${TMP_SECRETS}/tok.XXXXXX")"
  chmod 0600 "${f}"
  printf '%s\n' "$1" >"${f}"
  printf '%s' "${f}"
}

[[ -n "${BIN}" ]] && ARGS+=(--bin "${BIN}")
[[ -n "${CONTROL_PLANE_URL:-}" ]] && ARGS+=(--control-plane-url "${CONTROL_PLANE_URL}")

if [[ -n "${CONTROL_API_TOKEN:-}${AGENT_ENROLL_TOKEN:-}" ]]; then
  TMP_SECRETS="$(mktemp -d)"
  chmod 0700 "${TMP_SECRETS}"
fi

if [[ -n "${CONTROL_API_TOKEN_FILE:-}" ]]; then
  ARGS+=(--control-token-file "${CONTROL_API_TOKEN_FILE}")
elif [[ -n "${CONTROL_API_TOKEN:-}" ]]; then
  ARGS+=(--control-token-file "$(secret_file_for "${CONTROL_API_TOKEN}")")
fi

if [[ -n "${AGENT_ENROLL_TOKEN_FILE:-}" ]]; then
  ARGS+=(--enroll-token-file "${AGENT_ENROLL_TOKEN_FILE}")
elif [[ -n "${AGENT_ENROLL_TOKEN:-}" ]]; then
  ARGS+=(--enroll-token-file "$(secret_file_for "${AGENT_ENROLL_TOKEN}")")
fi

[[ -n "${DEVICE_ID:-}" ]] && ARGS+=(--device-id "${DEVICE_ID}")
[[ -n "${DEVICE_NAME:-}" ]] && ARGS+=(--device-name "${DEVICE_NAME}")
[[ -n "${SYSTEM_PROXY_HOST:-}" ]] && ARGS+=(--system-proxy-host "${SYSTEM_PROXY_HOST}")
[[ -n "${SYSTEM_PROXY_PORT:-}" ]] && ARGS+=(--system-proxy-port "${SYSTEM_PROXY_PORT}")
if [[ "${SET_SYSTEM_PROXY:-0}" == "1" ]]; then
  ARGS+=(--set-system-proxy)
fi

# Not exec: the EXIT trap must still fire to shred the temp token files.
"${ROOT}/packaging/agent/install-linux.sh" "${ARGS[@]}"
