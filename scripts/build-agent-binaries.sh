#!/usr/bin/env bash
# Build agent-spike release binaries for multi-OS pilot packaging.
# Usage: ./scripts/build-agent-binaries.sh [outdir]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-${ROOT}/dist/agent}"
mkdir -p "${OUT}"

build_one() {
  local target="$1"
  local name="$2"
  echo "==> ${target}"
  if [[ -n "${target}" ]]; then
    rustup target add "${target}" 2>/dev/null || true
    (cd "${ROOT}" && cargo build -p agent-spike --release --target "${target}")
    local src="${ROOT}/target/${target}/release/agent-spike"
    [[ -f "${src}.exe" ]] && src="${src}.exe"
    install -m 0755 "${src}" "${OUT}/${name}"
  else
    (cd "${ROOT}" && cargo build -p agent-spike --release)
    install -m 0755 "${ROOT}/target/release/agent-spike" "${OUT}/${name}"
  fi
}

HOST="$(uname -s)-$(uname -m)"
case "$(uname -s)" in
  Darwin)
    build_one "" "bsdm-agent-macos-$(uname -m)"
    # Optional: cross aarch64/x86_64 if toolchains present
    if rustup target list --installed 2>/dev/null | grep -q aarch64-apple-darwin; then
      build_one "aarch64-apple-darwin" "bsdm-agent-macos-aarch64"
    fi
    if rustup target list --installed 2>/dev/null | grep -q x86_64-apple-darwin; then
      build_one "x86_64-apple-darwin" "bsdm-agent-macos-x86_64"
    fi
    ;;
  Linux)
    build_one "" "bsdm-agent-linux-$(uname -m)"
    if rustup target list --installed 2>/dev/null | grep -q x86_64-unknown-linux-gnu; then
      build_one "x86_64-unknown-linux-gnu" "bsdm-agent-linux-x86_64"
    fi
    if rustup target list --installed 2>/dev/null | grep -q aarch64-unknown-linux-gnu; then
      build_one "aarch64-unknown-linux-gnu" "bsdm-agent-linux-aarch64"
    fi
    ;;
  *)
    build_one "" "bsdm-agent-${HOST}"
    ;;
esac

# Copy install helpers into dist
cp -a "${ROOT}/packaging/agent/." "${OUT}/packaging-agent/"
echo "Artifacts in ${OUT}:"
ls -la "${OUT}"
