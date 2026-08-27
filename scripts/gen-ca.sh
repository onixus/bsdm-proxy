#!/usr/bin/env bash
# Generate MITM CA keypair under ./certs/ (idempotent unless --force).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${ROOT}/certs"
FORCE=false
# 2 years, not 10: a shorter-lived root bounds the damage window if ca.key leaks
# and forces the rotation drill (scripts/rotate-ca.sh) to be exercised regularly.
DAYS="${CA_DAYS:-730}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force|-f) FORCE=true ;;
    --days)
      [[ $# -ge 2 ]] || { echo "error: --days requires a value" >&2; exit 2; }
      DAYS="$2"
      shift
      ;;
    --cert-dir)
      [[ $# -ge 2 ]] || { echo "error: --cert-dir requires a path" >&2; exit 2; }
      CERT_DIR="$2"
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--force] [--cert-dir PATH] [--days N]"
      echo "  Writes ${CERT_DIR}/ca.key and ca.crt (4096-bit RSA, ${DAYS}d,"
      echo "  CA:TRUE pathlen:0, keyUsage keyCertSign+cRLSign)."
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      exit 2
      ;;
  esac
  shift
done

[[ "${DAYS}" =~ ^[1-9][0-9]*$ ]] || { echo "error: --days must be a positive integer" >&2; exit 2; }

umask 077
mkdir -p "${CERT_DIR}"
chmod 700 "${CERT_DIR}"

if [[ -e "${CERT_DIR}/ca.key" || -e "${CERT_DIR}/ca.crt" ]]; then
  if [[ -f "${CERT_DIR}/ca.key" && -f "${CERT_DIR}/ca.crt" && "${FORCE}" != true ]]; then
    echo "CA already exists at ${CERT_DIR}/ (use --force to regenerate)"
    exit 0
  fi
  if [[ "${FORCE}" != true ]]; then
    echo "error: incomplete CA pair exists at ${CERT_DIR}/; inspect it and use --force to replace both files" >&2
    exit 1
  fi
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "error: openssl is required" >&2
  exit 1
fi

# Extensions are passed through a config file instead of `-addext` so the script
# also works on OpenSSL 1.0.2 (RHEL 7 / older SLES), where `-addext` is absent.
EXT_CONF="$(mktemp "${TMPDIR:-/tmp}/bsdm-ca-ext.XXXXXX")"
trap 'rm -f "${EXT_CONF}"' EXIT
cat >"${EXT_CONF}" <<'EOF'
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

openssl genrsa -out "${CERT_DIR}/ca.key" 4096
openssl req -new -x509 -days "${DAYS}" -key "${CERT_DIR}/ca.key" -out "${CERT_DIR}/ca.crt" \
  -config "${EXT_CONF}" \
  -subj "/C=RU/ST=Moscow/L=Moscow/O=BSDM/CN=BSDM Root CA"
chmod 600 "${CERT_DIR}/ca.key"
chmod 644 "${CERT_DIR}/ca.crt"

echo "Wrote ${CERT_DIR}/ca.key and ${CERT_DIR}/ca.crt"
echo "Trust ca.crt on clients for HTTPS MITM, or use: curl --cacert certs/ca.crt ..."
