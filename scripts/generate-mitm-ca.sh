#!/usr/bin/env bash
# Generate a self-signed Root CA for BSDM-Proxy MITM TLS interception.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${CERT_DIR:-$ROOT/certs}"
DAYS="${MITM_CA_DAYS:-3650}"

mkdir -p "$CERT_DIR"

if [[ -f "$CERT_DIR/ca.key" || -f "$CERT_DIR/ca.crt" ]]; then
  echo "Backing up existing CA to ${CERT_DIR}/backup-$(date +%Y%m%d-%H%M%S)/"
  backup_dir="$CERT_DIR/backup-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$backup_dir"
  [[ -f "$CERT_DIR/ca.key" ]] && mv "$CERT_DIR/ca.key" "$backup_dir/"
  [[ -f "$CERT_DIR/ca.crt" ]] && mv "$CERT_DIR/ca.crt" "$backup_dir/"
fi

conf="$(mktemp)"
trap 'rm -f "$conf"' EXIT

cat >"$conf" <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = RU
ST = Moscow
L = Moscow
O = BSDM
CN = BSDM Root CA

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

openssl genrsa -out "$CERT_DIR/ca.key" 4096
chmod 600 "$CERT_DIR/ca.key"
openssl req -new -x509 -days "$DAYS" -key "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
  -config "$conf" -extensions v3_ca

echo "MITM CA created:"
echo "  key:  $CERT_DIR/ca.key"
echo "  cert: $CERT_DIR/ca.crt"
openssl x509 -in "$CERT_DIR/ca.crt" -noout -subject -issuer -dates

echo
echo "Trust on macOS:"
echo "  sudo security add-trusted-cert -d -r trustRoot \\"
echo "    -k /Library/Keychains/System.keychain $CERT_DIR/ca.crt"
echo
echo "Test via proxy:"
echo "  curl --cacert $CERT_DIR/ca.crt -x http://127.0.0.1:1488 https://httpbin.org/get"
