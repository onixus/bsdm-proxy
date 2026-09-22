#!/usr/bin/env bash
# Interactive-installer backend for "Native proxy service (prebuilt release)":
# download the GitHub Release tarball for this host, verify it, run its
# install.sh, then apply the operator's answers and start the service. No
# cargo, npm or docker on the host.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"
source "${SCRIPT_DIR}/backup.sh"
source "${SCRIPT_DIR}/config.sh"
# finalize_native_install lives next to the source-build path so the two
# native modes cannot drift apart.
source "${SCRIPT_DIR}/native.sh"

install_release() {
  local root="$1"
  local prefix="${2:-/opt/bsdm-proxy}"
  local http_port="${3:-3128}"
  local metrics_port="${4:-9090}"
  local enable_acl="${5:-false}"
  local version="${6:-}"
  local fetcher="${root}/scripts/install-release.sh"
  local certs_dir

  [[ -x "$fetcher" ]] || die "Missing release fetcher: ${fetcher}"
  certs_dir="$(resolve_certs_dir /etc/bsdm-proxy /certs)"

  backup_installation "/etc/bsdm-proxy" "$certs_dir" >/dev/null

  local -a args=(--prefix "$prefix" --etc /etc/bsdm-proxy --certs "$certs_dir")
  if [[ -n "$version" ]]; then
    args+=(--version "$version")
  fi

  info "Installing prebuilt release ${version:-latest}"
  "$fetcher" "${args[@]}"

  finalize_native_install "$root" "$http_port" "$metrics_port" "$enable_acl" "$certs_dir"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  install_release "$@"
fi
