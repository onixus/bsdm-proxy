#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"
source "${SCRIPT_DIR}/backup.sh"
source "${SCRIPT_DIR}/config.sh"

install_native() {
  local root="$1"
  local prefix="${2:-/opt/bsdm-proxy}"
  local http_port="${3:-3128}"
  local metrics_port="${4:-9090}"
  local enable_acl="${5:-false}"
  local version package_version os arch staging

  [[ -x "${root}/scripts/build-package.sh" ]] || die "Missing canonical package builder"
  [[ -f "${root}/proxy/Cargo.toml" ]] || die "Cargo workspace not found"

  # The CA now lives under /etc/bsdm-proxy/certs (covered by the first path);
  # /certs is still backed up for installs that predate the move.
  backup_installation "/etc/bsdm-proxy" "/certs" >/dev/null

  info "Building canonical release package"
  (
    cd "$root"
    ./scripts/build-package.sh
  )

  version="$(awk -F'"' '/^version = / { print $2; exit }' "${root}/proxy/Cargo.toml")"
  [[ -n "$version" ]] || die "Unable to determine proxy version"
  package_version="${version//-b/b}"
  package_version="${package_version//-test/test}"
  package_version="${package_version//+/.}"
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  staging="${root}/dist/bsdm-proxy-${package_version}-${os}-${arch}"

  [[ -x "${staging}/install.sh" ]] || die "Release package staging not found: ${staging}"
  [[ -x "${staging}/bin/proxy" ]] || die "Release package does not contain proxy binary"

  info "Installing canonical native package"
  "${staging}/install.sh" \
    --prefix "$prefix" \
    --etc /etc/bsdm-proxy \
    --create-user \
    --systemd

  configure_native_proxy "$root" /etc/bsdm-proxy "$http_port" "$metrics_port" "$enable_acl"
  ensure_ca /etc/bsdm-proxy/certs

  if id bsdm-proxy >/dev/null 2>&1; then
    chown -R bsdm-proxy:bsdm-proxy /etc/bsdm-proxy/certs
  fi

  systemctl daemon-reload
  systemctl enable --now bsdm-proxy
  info "Native proxy service started"
}
