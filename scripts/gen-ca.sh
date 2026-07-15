#!/usr/bin/env bash
# Generate MITM CA keypair under ./certs/ (idempotent unless --force).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${ROOT}/certs"
FORCE=false

for arg in "$@"; do
  case "$arg" in
    --force|-f) FORCE=true ;;
    -h|--help)
      echo "Usage: $0 [--force]"
      echo "  Writes ${CERT_DIR}/ca.key and ca.crt (4096-bit RSA, 10y)."
      exit 0
      ;;
  esac
done

mkdir -p "${CERT_DIR}"

if [[ -f "${CERT_DIR}/ca.key" && -f "${CERT_DIR}/ca.crt" && "${FORCE}" != true ]]; then
  echo "CA already exists at ${CERT_DIR}/ (use --force to regenerate)"
  exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "error: openssl is required" >&2
  exit 1
fi

umask 077
openssl genrsa -out "${CERT_DIR}/ca.key" 4096
openssl req -new -x509 -days 3650 -key "${CERT_DIR}/ca.key" -out "${CERT_DIR}/ca.crt" \
  -subj "/C=RU/ST=Moscow/L=Moscow/O=BSDM/CN=BSDM Root CA"
chmod 600 "${CERT_DIR}/ca.key"
chmod 644 "${CERT_DIR}/ca.crt"

echo "Wrote ${CERT_DIR}/ca.key and ${CERT_DIR}/ca.crt"
echo "Trust ca.crt on clients for HTTPS MITM, or use: curl --cacert certs/ca.crt ..."
