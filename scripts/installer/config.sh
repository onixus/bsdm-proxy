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

  chmod 0600 "$env_file"
  info "Compose secrets ready in ${env_file}"
}
