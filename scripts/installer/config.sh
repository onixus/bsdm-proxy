#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

read_env_value() {
  local file="$1"
  local key="$2"
  [[ -f "$file" ]] || return 1
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$file"
}

ensure_secret() {
  local file="$1"
  local key="$2"
  local current=""
  current="$(read_env_value "$file" "$key" 2>/dev/null || true)"
  case "$current" in
    ''|change-me*)
      upsert_env "$file" "$key" "$(openssl rand -hex 32)"
      info "Generated ${key}"
      ;;
    *)
      info "Preserved existing ${key}"
      ;;
  esac
}

configure_native_proxy() {
  local root="$1"
  local etc_dir="$2"
  local http_port="$3"
  local metrics_port="$4"
  local enable_acl="${5:-false}"
  local template="${root}/packaging/config/bsdm-proxy.env.example"
  local env_file="${etc_dir}/bsdm-proxy.env"

  [[ -f "$template" ]] || die "Missing config template: $template"
  install -d -m 0750 "$etc_dir"

  if [[ -f "$env_file" ]]; then
    backup_file_if_present "$env_file"
    info "Updating existing proxy config without replacing unrelated settings"
  else
    install -m 0640 "$template" "$env_file"
    info "Installed proxy config template"
  fi

  upsert_env "$env_file" HTTP_PORT "$http_port"
  upsert_env "$env_file" METRICS_PORT "$metrics_port"
  upsert_env "$env_file" METRICS_BIND "127.0.0.1"
  upsert_env "$env_file" DEPLOYMENT_PROFILE "production"
  upsert_env "$env_file" POLICY_MODE "selective-mitm"
  upsert_env "$env_file" MITM_ENABLED "true"
  upsert_env "$env_file" CONTROL_API_ALLOW_INSECURE "false"
  upsert_env "$env_file" ACL_ENABLED "$enable_acl"

  ensure_secret "$env_file" CONTROL_API_TOKEN
  ensure_secret "$env_file" ACL_API_TOKEN
  chmod 0640 "$env_file"
}

# Create a real basic-auth users file so an install does not fall back to
# config/basic-auth-users.example.json, whose hashes are published in this
# repository. Hashing is done by `proxy hash-password` (the algorithm lives only
# in the Rust code); if that binary is unavailable we say so and leave the
# example in place rather than writing a file the proxy cannot verify.
ensure_basic_auth_users() {
  local root="$1"
  local env_file="${root}/.env"
  local users_file="${root}/config/basic-auth-users.json"
  local existing=""

  existing="$(read_env_value "$env_file" BASIC_AUTH_USERS_HOST 2>/dev/null || true)"
  if [[ -n "$existing" && -f "$existing" ]]; then
    info "Preserved existing basic-auth users file (${existing})"
    return 0
  fi
  if [[ -f "$users_file" ]]; then
    upsert_env "$env_file" BASIC_AUTH_USERS_HOST "./config/basic-auth-users.json"
    info "Preserved existing basic-auth users file (${users_file})"
    return 0
  fi

  local proxy_bin="${BSDM_PROXY_BIN:-}"
  if [[ -z "$proxy_bin" ]]; then
    for candidate in "${root}/target/release/proxy" "${root}/target/debug/proxy" "$(command -v proxy 2>/dev/null || true)"; do
      [[ -n "$candidate" && -x "$candidate" ]] && { proxy_bin="$candidate"; break; }
    done
  fi
  if [[ -z "$proxy_bin" ]]; then
    warn "proxy binary not found: cannot generate basic-auth users."
    warn "The stack would mount config/basic-auth-users.example.json, whose hashes are public."
    warn "Generate one before exposing the proxy:"
    warn "  printf '%s' '<password>' | ./scripts/gen-basic-auth-user.sh --stdin --role users <name> > config/basic-auth-users.json"
    warn "  then set BASIC_AUTH_USERS_HOST=./config/basic-auth-users.json in ${env_file}"
    return 0
  fi

  local password hash
  password="$(openssl rand -base64 24)"
  if ! hash="$(printf '%s' "$password" | "$proxy_bin" hash-password 2>/dev/null)" || [[ -z "$hash" ]]; then
    warn "${proxy_bin} hash-password failed; leaving basic-auth users unset."
    return 0
  fi

  ( umask 077
    printf '[\n  {\n    "username": "admin",\n    "password_hash": "%s",\n    "role": "admins"\n  }\n]\n' \
      "$hash" > "$users_file" )
  chmod 0600 "$users_file"
  upsert_env "$env_file" BASIC_AUTH_USERS_HOST "./config/basic-auth-users.json"
  upsert_env "$env_file" BASIC_AUTH_ADMIN_PASSWORD "$password"
  info "Generated basic-auth user 'admin' in ${users_file}"
  info "Its password is stored as BASIC_AUTH_ADMIN_PASSWORD in ${env_file} (0600)."
}

configure_compose_secrets() {
  local root="$1"
  local env_file="${root}/.env"

  if [[ -f "$env_file" ]]; then
    backup_file_if_present "$env_file"
  else
    : > "$env_file"
  fi
  chmod 0600 "$env_file"

  ensure_secret "$env_file" CONTROL_API_TOKEN
  ensure_secret "$env_file" ACL_API_TOKEN
  ensure_secret "$env_file" SEARCH_API_TOKEN
  # Grafana is fail-closed in docker-compose.yml
  # (GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD:?...}), so without this
  # `docker compose config` in installer/docker.sh aborts before anything starts.
  # Generated like every other secret here: 32 random bytes, never printed.
  ensure_secret "$env_file" GRAFANA_ADMIN_PASSWORD
  upsert_env "$env_file" CONTROL_API_ALLOW_INSECURE "false"

  ensure_basic_auth_users "$root"

  chmod 0600 "$env_file"
  info "Compose secrets ready in ${env_file}"
}
