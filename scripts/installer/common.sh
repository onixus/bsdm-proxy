#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
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
  cp -a -- "$path" "$backup"
  info "Backed up $path -> $backup"
}

upsert_env() {
  local file="$1"
  local key="$2"
  local value="$3"
  local tmp
  tmp="$(mktemp "${file}.tmp.XXXXXX")"

  awk -v key="$key" -v value="$value" '
    BEGIN { replaced = 0 }
    $0 ~ "^" key "=" {
      if (!replaced) print key "=" value
      replaced = 1
      next
    }
    { print }
    END { if (!replaced) print key "=" value }
  ' "$file" > "$tmp"
  chmod --reference="$file" "$tmp" 2>/dev/null || chmod 0640 "$tmp"
  chown --reference="$file" "$tmp" 2>/dev/null || true
  mv -f -- "$tmp" "$file"
}

ensure_ca() {
  local certs_dir="$1"
  require_cmd openssl
  install -d -m 0750 "$certs_dir"

  if [[ -f "${certs_dir}/ca.key" && -f "${certs_dir}/ca.crt" ]]; then
    info "Existing MITM CA preserved in ${certs_dir}"
    return 0
  fi

  [[ ! -e "${certs_dir}/ca.key" && ! -e "${certs_dir}/ca.crt" ]] || \
    die "Incomplete CA state in ${certs_dir}; expected both ca.key and ca.crt or neither."

  openssl req -x509 -newkey rsa:4096 \
    -keyout "${certs_dir}/ca.key" \
    -out "${certs_dir}/ca.crt" \
    -days 3650 -nodes \
    -subj "/CN=BSDM Proxy Root CA/O=BSDM Security"
  chmod 0600 "${certs_dir}/ca.key"
  chmod 0644 "${certs_dir}/ca.crt"
  info "Generated MITM CA in ${certs_dir}"
}
