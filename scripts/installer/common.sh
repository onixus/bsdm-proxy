#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

info() { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*" >&2; }
die() { echo -e "${RED}${BOLD}Error:${NC} $*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

require_root() {
  [[ "$(id -u)" -eq 0 ]] || die "Native installation must run as root (sudo ./install.sh)."
}

validate_port() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+$ ]] || return 1
  (( value >= 1 && value <= 65535 ))
}

validate_install_path() {
  local value="$1"
  [[ "$value" == /* ]] || return 1
  case "$value" in
    /|/etc|/usr|/var|/opt|/home|/root|/bin|/sbin|/lib|/lib64)
      return 1
      ;;
  esac
}

prompt_input() {
  local prompt="$1"
  local default="$2"
  local var_name="$3"
  local input=""

  read -r -p "$(echo -e "${YELLOW}${BOLD}${prompt}${NC} [${default}]: ")" input
  input="${input:-$default}"
  printf -v "$var_name" '%s' "$input"
}

prompt_port() {
  local prompt="$1"
  local default="$2"
  local var_name="$3"
  local value=""
  while true; do
    prompt_input "$prompt" "$default" value
    if validate_port "$value"; then
      printf -v "$var_name" '%s' "$value"
      return 0
    fi
    warn "Port must be an integer from 1 to 65535."
  done
}

prompt_yn() {
  local prompt="$1"
  local default="$2"
  local var_name="$3"
  local hint="Y/n"
  local response=""

  [[ "$default" == "false" ]] && hint="y/N"
  read -r -p "$(echo -e "${YELLOW}${BOLD}${prompt}${NC} (${hint}): ")" response
  response="$(printf '%s' "$response" | tr '[:upper:]' '[:lower:]')"

  case "$response" in
    '') printf -v "$var_name" '%s' "$default" ;;
    y|yes) printf -v "$var_name" '%s' true ;;
    n|no) printf -v "$var_name" '%s' false ;;
    *) warn "Unrecognized answer; treating it as no."; printf -v "$var_name" '%s' false ;;
  esac
}

backup_file_if_present() {
  local path="$1"
  [[ -f "$path" ]] || return 0
  local timestamp backup
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  backup="${path}.bak.${timestamp}"
  cp -p "$path" "$backup"
  info "Backed up $path -> $backup"
}

upsert_env() {
  local file="$1"
  local key="$2"
  local value="$3"
  local tmp rendered

  if [[ ! -f "$file" ]]; then
    : > "$file"
    chmod 0640 "$file"
  fi

  tmp="$(mktemp "${file}.tmp.XXXXXX")"
  rendered="${tmp}.rendered"

  awk -v key="$key" -v value="$value" '
    BEGIN { replaced = 0 }
    $0 ~ "^" key "=" {
      if (!replaced) print key "=" value
      replaced = 1
      next
    }
    { print }
    END { if (!replaced) print key "=" value }
  ' "$file" > "$rendered"

  if cp -p "$file" "$tmp" 2>/dev/null; then
    :
  else
    cp "$file" "$tmp"
    chmod 0640 "$tmp"
  fi
  cat "$rendered" > "$tmp"
  rm -f "$rendered"
  mv -f "$tmp" "$file"
}

# Resolve the MITM CA directory: keep a pre-existing legacy /certs (moving a
# live CA breaks every client that already trusts it), otherwise use the
# FHS location under the config directory, which the systemd units cover via
# ReadWritePaths=/etc/bsdm-proxy.
resolve_certs_dir() {
  local etc_dir="${1:-/etc/bsdm-proxy}"
  local legacy="${2:-/certs}"
  if [[ -d "$legacy" && ! -L "$legacy" ]]; then
    printf '%s' "$legacy"
  else
    printf '%s' "${etc_dir}/certs"
  fi
}

ensure_ca() {
  local certs_dir="$1"
  require_cmd openssl
  # 0700, not 0750: the directory holds ca.key; group read means anyone in the
  # group can mint a certificate for any site the proxy intercepts.
  install -d -m 0700 "$certs_dir"

  if [[ -f "${certs_dir}/ca.key" && -f "${certs_dir}/ca.crt" ]]; then
    info "Existing MITM CA preserved in ${certs_dir}"
    return 0
  fi

  [[ ! -e "${certs_dir}/ca.key" && ! -e "${certs_dir}/ca.crt" ]] || \
    die "Incomplete CA state in ${certs_dir}; expected both ca.key and ca.crt or neither."

  # umask BEFORE openssl: `openssl req` creates ca.key with 0644 minus umask and
  # only the chmod below narrows it. Without this there is a window in which the
  # private CA key is world-readable — same fix as scripts/gen-ca.sh:30.
  # Subshell so the caller's umask is untouched.
  # Extensions via a config file rather than `-addext`: `-addext` needs OpenSSL
  # 1.1.1+, and installers still land on RHEL 7 / older SLES with 1.0.2.
  # 730 days (2y), not 10y: bounds the exposure window of a leaked ca.key.
  # Rotate with scripts/rotate-ca.sh before expiry.
  local ca_days="${CA_DAYS:-730}"
  local ext_conf
  ext_conf="$(mktemp "${TMPDIR:-/tmp}/bsdm-ca-ext.XXXXXX")"
  cat >"${ext_conf}" <<'EOF'
[req]
distinguished_name = ca_dn
prompt = no
x509_extensions = v3_ca

[ca_dn]
CN = BSDM Proxy Root CA

[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
  (
    umask 077
    openssl req -x509 -newkey rsa:4096 \
      -keyout "${certs_dir}/ca.key" \
      -out "${certs_dir}/ca.crt" \
      -days "${ca_days}" -nodes \
      -config "${ext_conf}" \
      -subj "/CN=BSDM Proxy Root CA/O=BSDM Security"
  ) || { rm -f "${ext_conf}"; die "CA generation failed"; }
  rm -f "${ext_conf}"
  chmod 0600 "${certs_dir}/ca.key"
  chmod 0644 "${certs_dir}/ca.crt"
  info "Generated MITM CA in ${certs_dir} (valid ${ca_days} days, CA:TRUE pathlen:0)"
}
