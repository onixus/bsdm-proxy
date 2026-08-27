#!/usr/bin/env bash
# Install BSDM-Proxy from a release package directory.
set -euo pipefail

PREFIX="/opt/bsdm-proxy"
ETC_DIR="/etc/bsdm-proxy"
INSTALL_SYSTEMD=false
CREATE_USER=false
# MITM CA lives under the config directory (FHS) so that it is covered by the
# systemd units' ReadWritePaths=/etc/bsdm-proxy. See LEGACY_CERTS_DIR below.
CERTS_DIR=""
LEGACY_CERTS_DIR="/certs"

# Mirrors validate_install_path() from scripts/installer/common.sh. It is
# duplicated on purpose: the release tarball ships only this file (see
# scripts/build-package.sh), so common.sh cannot be sourced here. The extra
# character-class check matters because PREFIX is substituted into a systemd
# unit via sed below — an unvalidated value would be unit-file injection
# executed by root (e.g. --prefix '/x|d;s|ExecStart=.*|ExecStart=/bin/sh -c ...').
validate_install_path() {
  local value="$1"
  local label="$2"
  [[ "$value" == /* ]] || { echo "${label} must be an absolute path: ${value}" >&2; exit 2; }
  [[ "$value" != *".."* ]] || { echo "${label} must not contain '..': ${value}" >&2; exit 2; }
  [[ "$value" =~ ^[A-Za-z0-9._/-]+$ ]] || {
    echo "${label} may only contain letters, digits and . _ - / : ${value}" >&2
    exit 2
  }
  case "${value%/}" in
    ''|/|/etc|/usr|/var|/opt|/home|/root|/bin|/sbin|/lib|/lib64)
      echo "${label} must not be a system root directory: ${value}" >&2
      exit 2
      ;;
  esac
}

need_value() {
  # need_value <option> <remaining-argc>
  [[ "$2" -ge 2 ]] || { echo "error: $1 requires a value" >&2; exit 2; }
}

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh [OPTIONS]

Options:
  --prefix PATH       Install binaries to PATH (default: /opt/bsdm-proxy)
  --etc PATH          Config directory (default: /etc/bsdm-proxy)
  --certs PATH        MITM CA directory (default: <etc>/certs; an existing
                      legacy /certs directory is reused and kept in place)
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
      need_value "$1" "$#"
      PREFIX="$2"
      shift 2
      ;;
    --etc)
      need_value "$1" "$#"
      ETC_DIR="$2"
      shift 2
      ;;
    --certs)
      need_value "$1" "$#"
      CERTS_DIR="$2"
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

if [[ $# -eq 0 && -t 0 ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [[ -f "${SCRIPT_DIR}/scripts/interactive-install.sh" ]]; then
    exec "${SCRIPT_DIR}/scripts/interactive-install.sh"
  elif [[ -f "${SCRIPT_DIR}/../scripts/interactive-install.sh" ]]; then
    exec "${SCRIPT_DIR}/../scripts/interactive-install.sh"
  fi
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root (sudo ./install.sh)" >&2
  exit 1
fi

validate_install_path "$PREFIX" "--prefix"
validate_install_path "$ETC_DIR" "--etc"
if [[ -n "$CERTS_DIR" ]]; then
  validate_install_path "$CERTS_DIR" "--certs"
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
install -m 0755 "${SCRIPT_DIR}/bin/alert-worker" "${PREFIX}/bin/alert-worker"
if [[ -x "${SCRIPT_DIR}/bin/ml-worker" ]]; then
  install -m 0755 "${SCRIPT_DIR}/bin/ml-worker" "${PREFIX}/bin/ml-worker"
fi
if [[ -x "${SCRIPT_DIR}/bin/dns-sinkhole" ]]; then
  install -m 0755 "${SCRIPT_DIR}/bin/dns-sinkhole" "${PREFIX}/bin/dns-sinkhole"
fi
if [[ -x "${SCRIPT_DIR}/bin/threat-intel" ]]; then
  install -m 0755 "${SCRIPT_DIR}/bin/threat-intel" "${PREFIX}/bin/threat-intel"
fi

install -d -m 0755 "${ETC_DIR}"
if [[ ! -f "${ETC_DIR}/bsdm-proxy.env" ]]; then
  install -m 0640 "${SCRIPT_DIR}/config/bsdm-proxy.env.example" "${ETC_DIR}/bsdm-proxy.env"
  echo "" >> "${ETC_DIR}/bsdm-proxy.env"
  echo "# Security and API Control" >> "${ETC_DIR}/bsdm-proxy.env"
  echo "CONTROL_API_TOKEN=$(openssl rand -hex 32)" >> "${ETC_DIR}/bsdm-proxy.env"
  echo "ACL_API_TOKEN=$(openssl rand -hex 32)" >> "${ETC_DIR}/bsdm-proxy.env"
  echo "Installed ${ETC_DIR}/bsdm-proxy.env"
fi
if [[ ! -f "${ETC_DIR}/cache-indexer.env" ]]; then
  install -m 0640 "${SCRIPT_DIR}/config/cache-indexer.env.example" "${ETC_DIR}/cache-indexer.env"
  echo "" >> "${ETC_DIR}/cache-indexer.env"
  echo "# Security and API Control" >> "${ETC_DIR}/cache-indexer.env"
  echo "SEARCH_API_TOKEN=$(openssl rand -hex 32)" >> "${ETC_DIR}/cache-indexer.env"
  echo "Installed ${ETC_DIR}/cache-indexer.env"
fi
if [[ ! -f "${ETC_DIR}/alert-worker.env" ]]; then
  install -m 0640 "${SCRIPT_DIR}/config/alert-worker.env.example" "${ETC_DIR}/alert-worker.env"
  echo "Installed ${ETC_DIR}/alert-worker.env"
fi
if [[ -f "${SCRIPT_DIR}/config/ml-worker.env.example" && ! -f "${ETC_DIR}/ml-worker.env" ]]; then
  install -m 0640 "${SCRIPT_DIR}/config/ml-worker.env.example" "${ETC_DIR}/ml-worker.env"
  echo "Installed ${ETC_DIR}/ml-worker.env"
fi
if [[ -f "${SCRIPT_DIR}/config/threat-intel.env.example" && ! -f "${ETC_DIR}/threat-intel.env" ]]; then
  install -m 0640 "${SCRIPT_DIR}/config/threat-intel.env.example" "${ETC_DIR}/threat-intel.env"
  echo "Installed ${ETC_DIR}/threat-intel.env"
fi
if [[ ! -f "${ETC_DIR}/acl-rules.json" ]]; then
  install -m 0644 "${SCRIPT_DIR}/config/acl-rules.example.json" "${ETC_DIR}/acl-rules.json"
  echo "Installed ${ETC_DIR}/acl-rules.json"
fi

# MITM CA directory.
#
# New installs put the CA under ${ETC_DIR}/certs: /certs is outside the FHS and
# is not covered by the systemd units' ProtectSystem=strict + ReadWritePaths.
# Existing installs keep /certs (moving a live CA would break every client that
# already trusts it and every running proxy holding the old path).
#
# No /certs symlink: the proxy resolves the CA from MITM_CA_DIR (default
# ${ETC_DIR}/certs) and falls back to a real /certs on its own — see
# proxy/src/tls.rs:load_for_startup. The resolved directory is written into the
# env file below, so a legacy install keeps working without the deprecation
# warning that the fallback logs.
if [[ -z "$CERTS_DIR" ]]; then
  if [[ -d "$LEGACY_CERTS_DIR" && ! -L "$LEGACY_CERTS_DIR" ]]; then
    CERTS_DIR="$LEGACY_CERTS_DIR"
    echo "Note: keeping the existing MITM CA directory ${LEGACY_CERTS_DIR}."
    echo "      New installs use ${ETC_DIR}/certs; to migrate, stop bsdm-proxy, then:"
    echo "        mv ${LEGACY_CERTS_DIR} ${ETC_DIR}/certs"
    echo "      and set MITM_CA_DIR=${ETC_DIR}/certs in ${ETC_DIR}/bsdm-proxy.env"
  else
    CERTS_DIR="${ETC_DIR}/certs"
  fi
fi

# 0700, not 0750: the directory holds ca.key. Group read buys nothing here and
# gives every member of the group the ability to mint certificates for any site.
install -d -m 0700 "$CERTS_DIR"

# Point the proxy at the directory this install actually uses, whichever it is.
if [[ -f "${ETC_DIR}/bsdm-proxy.env" ]]; then
  env_tmp="$(mktemp)"
  grep -v '^[[:space:]]*MITM_CA_DIR=' "${ETC_DIR}/bsdm-proxy.env" >"${env_tmp}" || true
  echo "MITM_CA_DIR=${CERTS_DIR}" >>"${env_tmp}"
  install -m 0640 "${env_tmp}" "${ETC_DIR}/bsdm-proxy.env"
  rm -f "${env_tmp}"
fi

if $CREATE_USER; then
  chown bsdm-proxy:bsdm-proxy "$CERTS_DIR" "${ETC_DIR}"
  chown -R bsdm-proxy:bsdm-proxy "${PREFIX}"
fi

if $INSTALL_SYSTEMD; then
  for unit in bsdm-proxy bsdm-cache-indexer bsdm-alert-worker bsdm-ml-worker bsdm-dns-sinkhole bsdm-threat-intel; do
    if [[ -f "${SCRIPT_DIR}/systemd/${unit}.service" ]]; then
      # PREFIX/ETC_DIR are validated above (absolute, no '..', no sed
      # metacharacters such as | & \ or newline), so this substitution cannot
      # inject additional directives into a root-executed unit file.
      # ETC_DIR is substituted too: the units now hard-require their
      # EnvironmentFile, so a non-default --etc must be reflected here.
      unit_tmp="$(mktemp)"
      sed -e "s|/opt/bsdm-proxy|${PREFIX}|g" \
        -e "s|/etc/bsdm-proxy|${ETC_DIR}|g" \
        "${SCRIPT_DIR}/systemd/${unit}.service" \
        >"${unit_tmp}"
      install -m 0644 "${unit_tmp}" "/etc/systemd/system/${unit}.service"
      rm -f "${unit_tmp}"
    fi
  done
  systemctl daemon-reload
  echo "Systemd units installed. Start with:"
  echo "  systemctl enable --now bsdm-proxy"
  echo "  systemctl enable --now bsdm-cache-indexer  # optional"
  echo "  systemctl enable --now bsdm-alert-worker   # optional; set ALERT_WEBHOOK_URL first"
  echo "  systemctl enable --now bsdm-ml-worker      # optional; M5 feature store"
  echo "  systemctl enable --now bsdm-dns-sinkhole   # optional; DoH/DoT DNS gateway"
  echo "  systemctl enable --now bsdm-threat-intel   # optional; IOC feed collector"
fi

cat <<EOF

BSDM-Proxy installed to ${PREFIX}

MITM requires CA certificates (0600 ca.key, owned by bsdm-proxy):
  ${CERTS_DIR}/ca.key
  ${CERTS_DIR}/ca.crt

The directory is recorded as MITM_CA_DIR in ${ETC_DIR}/bsdm-proxy.env.

Health check: curl http://127.0.0.1:9090/health
Metrics:      http://127.0.0.1:9090/metrics

EOF
