#!/usr/bin/env bash
# Install BSDM-Proxy from a release package directory.
set -euo pipefail

PREFIX="/opt/bsdm-proxy"
ETC_DIR="/etc/bsdm-proxy"
INSTALL_SYSTEMD=false
CREATE_USER=false

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh [OPTIONS]

Options:
  --prefix PATH       Install binaries to PATH (default: /opt/bsdm-proxy)
  --etc PATH          Config directory (default: /etc/bsdm-proxy)
  --systemd           Install and enable systemd units
  --create-user       Create system user 'bsdm-proxy'
  -h, --help          Show this help

Example:
  sudo ./install.sh --create-user --systemd
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      PREFIX="$2"
      shift 2
      ;;
    --etc)
      ETC_DIR="$2"
      shift 2
      ;;
    --systemd)
      INSTALL_SYSTEMD=true
      shift
      ;;
    --create-user)
      CREATE_USER=true
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root (sudo ./install.sh)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -x "${SCRIPT_DIR}/bin/proxy" ]]; then
  echo "Missing ${SCRIPT_DIR}/bin/proxy — run from unpacked package root" >&2
  exit 1
fi

if $CREATE_USER; then
  if ! id bsdm-proxy &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin bsdm-proxy
    echo "Created user bsdm-proxy"
  fi
fi

install -d -m 0755 "${PREFIX}/bin"
install -m 0755 "${SCRIPT_DIR}/bin/proxy" "${PREFIX}/bin/proxy"
install -m 0755 "${SCRIPT_DIR}/bin/cache-indexer" "${PREFIX}/bin/cache-indexer"

install -d -m 0755 "${ETC_DIR}"
if [[ ! -f "${ETC_DIR}/bsdm-proxy.env" ]]; then
  install -m 0640 "${SCRIPT_DIR}/config/bsdm-proxy.env.example" "${ETC_DIR}/bsdm-proxy.env"
  echo "Installed ${ETC_DIR}/bsdm-proxy.env"
fi
if [[ ! -f "${ETC_DIR}/cache-indexer.env" ]]; then
  install -m 0640 "${SCRIPT_DIR}/config/cache-indexer.env.example" "${ETC_DIR}/cache-indexer.env"
  echo "Installed ${ETC_DIR}/cache-indexer.env"
fi
if [[ ! -f "${ETC_DIR}/acl-rules.json" ]]; then
  install -m 0644 "${SCRIPT_DIR}/config/acl-rules.example.json" "${ETC_DIR}/acl-rules.json"
  echo "Installed ${ETC_DIR}/acl-rules.json"
fi

install -d -m 0750 /certs
if $CREATE_USER; then
  chown bsdm-proxy:bsdm-proxy /certs "${ETC_DIR}"
  chown -R bsdm-proxy:bsdm-proxy "${PREFIX}"
fi

if $INSTALL_SYSTEMD; then
  for unit in bsdm-proxy bsdm-cache-indexer; do
    sed "s|/opt/bsdm-proxy|${PREFIX}|g" \
      "${SCRIPT_DIR}/systemd/${unit}.service" \
      >"/etc/systemd/system/${unit}.service"
  done
  systemctl daemon-reload
  echo "Systemd units installed. Start with:"
  echo "  systemctl enable --now bsdm-proxy"
  echo "  systemctl enable --now bsdm-cache-indexer  # optional"
fi

cat <<EOF

BSDM-Proxy installed to ${PREFIX}

MITM requires CA certificates:
  /certs/ca.key
  /certs/ca.crt

Health check: curl http://127.0.0.1:9090/health
Metrics:      http://127.0.0.1:9090/metrics

EOF
