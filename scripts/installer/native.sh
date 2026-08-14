#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

install_native() {
  local root="$1"

  require_cmd cargo

  [[ -f "${root}/Cargo.toml" ]] || die "Cargo workspace not found"

  info "Building release binaries"
  cargo build --release --locked

  [[ -x "${root}/target/release/proxy" ]] || die "proxy binary was not produced"

  info "Installing canonical package"
  [[ -x "${root}/packaging/install.sh" ]] || die "Canonical packaging installer missing"
  "${root}/packaging/install.sh"
}
