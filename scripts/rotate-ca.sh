#!/usr/bin/env bash
# Prepare, validate, and activate BSDM MITM CA keypairs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${ROOT}/certs"
COMMON_NAME="BSDM Root CA"
# 2 years, not 10: bounds the exposure window of a leaked ca.key and keeps the
# rotation procedure a routine, exercised operation. Override with --days.
DAYS="${CA_DAYS:-730}"

usage() {
  cat <<'EOF'
Usage:
  rotate-ca.sh prepare [--cert-dir PATH] [--common-name NAME] [--days N]
  rotate-ca.sh verify [PATH] [--cert-dir PATH]
  rotate-ca.sh activate STAGED_PATH [--cert-dir PATH]

prepare   Generate a new restricted CA pair under CERT_DIR/rotation/
          (default 730 days, CA:TRUE pathlen:0, keyUsage keyCertSign+cRLSign).
verify    Validate a CA pair and reject group/world-readable private keys.
activate  Archive the current pair, then install a validated staged pair.

Stop the proxy before activation. Distribute the staged ca.crt to clients before
activation so clients trust both the current and new roots during the swap.
EOF
}

file_mode() {
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

fingerprint() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2
}

validate_pair() {
  local pair_dir="$1"
  local key="${pair_dir}/ca.key"
  local cert="${pair_dir}/ca.crt"
  local mode key_pub cert_pub

  [[ -f "${key}" ]] || { echo "error: missing ${key}" >&2; return 1; }
  [[ -f "${cert}" ]] || { echo "error: missing ${cert}" >&2; return 1; }

  mode="$(file_mode "${key}")"
  [[ "${mode}" =~ ^[0-7]{3,4}$ ]] || { echo "error: cannot validate key mode: ${mode}" >&2; return 1; }
  if (( (8#${mode} & 077) != 0 )); then
    echo "error: ${key} must not be readable, writable, or executable by group/other (mode ${mode})" >&2
    return 1
  fi

  openssl pkey -in "${key}" -noout -check >/dev/null
  openssl x509 -in "${cert}" -noout -checkend 0 >/dev/null
  openssl x509 -in "${cert}" -noout -text | grep -q 'CA:TRUE'

  key_pub="$(openssl pkey -in "${key}" -pubout -outform PEM 2>/dev/null | openssl sha256)"
  cert_pub="$(openssl x509 -in "${cert}" -pubkey -noout | openssl sha256)"
  [[ "${key_pub}" == "${cert_pub}" ]] || { echo "error: CA key and certificate do not match" >&2; return 1; }

  echo "Valid CA: $(fingerprint "${cert}")"
}

[[ $# -gt 0 ]] || { usage; exit 2; }
COMMAND="$1"
shift
POSITIONAL=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cert-dir)
      [[ $# -ge 2 ]] || { echo "error: --cert-dir requires a path" >&2; exit 2; }
      CERT_DIR="$2"
      shift
      ;;
    --common-name)
      [[ $# -ge 2 ]] || { echo "error: --common-name requires a value" >&2; exit 2; }
      COMMON_NAME="$2"
      shift
      ;;
    --days)
      [[ $# -ge 2 ]] || { echo "error: --days requires a value" >&2; exit 2; }
      DAYS="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) POSITIONAL+=("$1") ;;
  esac
  shift
done

command -v openssl >/dev/null 2>&1 || { echo "error: openssl is required" >&2; exit 1; }
[[ "${DAYS}" =~ ^[1-9][0-9]*$ ]] || { echo "error: --days must be a positive integer" >&2; exit 2; }
[[ "${COMMON_NAME}" != *"/"* && "${COMMON_NAME}" != *$'\n'* ]] || {
  echo "error: --common-name must not contain '/' or a newline" >&2
  exit 2
}

case "${COMMAND}" in
  -h|--help)
    usage
    ;;
  prepare)
    [[ ${#POSITIONAL[@]} -eq 0 ]] || { usage; exit 2; }
    umask 077
    mkdir -p "${CERT_DIR}/rotation"
    chmod 700 "${CERT_DIR}" "${CERT_DIR}/rotation"
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    stage_dir="${CERT_DIR}/rotation/${timestamp}"
    [[ ! -e "${stage_dir}" ]] || stage_dir="${stage_dir}-$$"
    mkdir "${stage_dir}"
    # Extensions come from a config file rather than `-addext` so the script also
    # runs on OpenSSL 1.0.2 (RHEL 7 / older SLES), where `-addext` does not exist.
    ext_conf="$(mktemp "${TMPDIR:-/tmp}/bsdm-ca-ext.XXXXXX")"
    trap 'rm -f "${ext_conf}"' EXIT
    cat >"${ext_conf}" <<'EOF'
[req]
distinguished_name = ca_dn
prompt = no
x509_extensions = v3_ca

[ca_dn]
CN = BSDM Root CA

[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
    openssl genrsa -out "${stage_dir}/ca.key" 4096
    openssl req -new -x509 -days "${DAYS}" -key "${stage_dir}/ca.key" -out "${stage_dir}/ca.crt" \
      -config "${ext_conf}" \
      -subj "/O=BSDM/CN=${COMMON_NAME}"
    rm -f "${ext_conf}"
    trap - EXIT
    chmod 600 "${stage_dir}/ca.key"
    chmod 644 "${stage_dir}/ca.crt"
    validate_pair "${stage_dir}"
    echo "Prepared CA: ${stage_dir}"
    echo "Distribute ${stage_dir}/ca.crt before activation. Keep ca.key private."
    ;;
  verify)
    [[ ${#POSITIONAL[@]} -le 1 ]] || { usage; exit 2; }
    validate_pair "${POSITIONAL[0]:-${CERT_DIR}}"
    ;;
  activate)
    [[ ${#POSITIONAL[@]} -eq 1 ]] || { usage; exit 2; }
    stage_dir="${POSITIONAL[0]}"
    validate_pair "${stage_dir}"
    [[ -f "${CERT_DIR}/ca.key" && -f "${CERT_DIR}/ca.crt" ]] || {
      echo "error: active CA pair is incomplete or missing; use gen-ca.sh for initial setup" >&2
      exit 1
    }
    validate_pair "${CERT_DIR}"
    [[ "$(fingerprint "${stage_dir}/ca.crt")" != "$(fingerprint "${CERT_DIR}/ca.crt")" ]] || {
      echo "error: staged and active CA certificates are identical" >&2
      exit 1
    }

    umask 077
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    archive_dir="${CERT_DIR}/archive/${timestamp}"
    [[ ! -e "${archive_dir}" ]] || archive_dir="${archive_dir}-$$"
    mkdir -p "${archive_dir}"
    chmod 700 "${CERT_DIR}" "${CERT_DIR}/archive" "${archive_dir}"
    install -m 600 "${CERT_DIR}/ca.key" "${archive_dir}/ca.key"
    install -m 644 "${CERT_DIR}/ca.crt" "${archive_dir}/ca.crt"

    activation_complete=false
    rollback_activation() {
      local exit_code=$?
      trap - ERR
      rm -f "${CERT_DIR}/.ca.key.new" "${CERT_DIR}/.ca.crt.new"
      if [[ "${activation_complete}" != true ]]; then
        install -m 600 "${archive_dir}/ca.key" "${CERT_DIR}/ca.key"
        install -m 644 "${archive_dir}/ca.crt" "${CERT_DIR}/ca.crt"
        echo "error: activation failed; restored archived CA" >&2
      fi
      exit "${exit_code}"
    }
    trap rollback_activation ERR

    install -m 600 "${stage_dir}/ca.key" "${CERT_DIR}/.ca.key.new"
    install -m 644 "${stage_dir}/ca.crt" "${CERT_DIR}/.ca.crt.new"
    mv "${CERT_DIR}/.ca.key.new" "${CERT_DIR}/ca.key"
    mv "${CERT_DIR}/.ca.crt.new" "${CERT_DIR}/ca.crt"
    validate_pair "${CERT_DIR}"
    activation_complete=true
    trap - ERR
    rm -f "${stage_dir}/ca.key"

    echo "Activated CA: $(fingerprint "${CERT_DIR}/ca.crt")"
    echo "Archived previous CA: ${archive_dir}"
    echo "Restart the proxy, verify HTTPS, then remove the old client trust root."
    ;;
  *)
    echo "error: unknown command: ${COMMAND}" >&2
    usage
    exit 2
    ;;
esac
