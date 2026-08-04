#!/usr/bin/env bash
# Offline rotation drill used locally and by CI.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DRILL_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bsdm-ca-drill.XXXXXX")"
trap 'rm -rf "${DRILL_DIR}"' EXIT
CERT_DIR="${DRILL_DIR}/certs"

mkdir -p "${DRILL_DIR}/incomplete"
touch "${DRILL_DIR}/incomplete/ca.key"
if "${ROOT}/scripts/gen-ca.sh" --cert-dir "${DRILL_DIR}/incomplete" >/dev/null 2>&1; then
  echo "CA generator accepted an incomplete existing pair" >&2
  exit 1
fi

"${ROOT}/scripts/gen-ca.sh" --cert-dir "${CERT_DIR}" >/dev/null
old_fingerprint="$(openssl x509 -in "${CERT_DIR}/ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)"

prepare_output="$("${ROOT}/scripts/rotate-ca.sh" prepare --cert-dir "${CERT_DIR}" --common-name "BSDM Rotation Drill")"
stage_dir="$(printf '%s\n' "${prepare_output}" | sed -n 's/^Prepared CA: //p')"
[[ -n "${stage_dir}" && -d "${stage_dir}" ]]

"${ROOT}/scripts/rotate-ca.sh" verify "${stage_dir}" >/dev/null
chmod 644 "${stage_dir}/ca.key"
if "${ROOT}/scripts/rotate-ca.sh" verify "${stage_dir}" >/dev/null 2>&1; then
  echo "rotation verifier accepted a world-readable private key" >&2
  exit 1
fi
chmod 600 "${stage_dir}/ca.key"
"${ROOT}/scripts/rotate-ca.sh" activate "${stage_dir}" --cert-dir "${CERT_DIR}" >/dev/null
"${ROOT}/scripts/rotate-ca.sh" verify --cert-dir "${CERT_DIR}" >/dev/null

new_fingerprint="$(openssl x509 -in "${CERT_DIR}/ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
[[ "${old_fingerprint}" != "${new_fingerprint}" ]]
[[ ! -f "${stage_dir}/ca.key" ]]
[[ "$(find "${CERT_DIR}/archive" -name ca.key -type f | wc -l | tr -d ' ')" == "1" ]]

if stat -f '%Lp' "${CERT_DIR}/ca.key" >/dev/null 2>&1; then
  key_mode="$(stat -f '%Lp' "${CERT_DIR}/ca.key")"
else
  key_mode="$(stat -c '%a' "${CERT_DIR}/ca.key")"
fi
[[ "${key_mode}" == "600" ]]

echo "CA rotation drill passed"
echo "Old SHA-256: ${old_fingerprint}"
echo "New SHA-256: ${new_fingerprint}"
