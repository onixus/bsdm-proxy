#!/usr/bin/env bash
# Build BSDM-Proxy release package (binaries + config + systemd + installer).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(grep '^version' proxy/Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')"
# Cargo 0.2.2-b → package label 0.2.2b
PACKAGE_VERSION="${VERSION//-b/b}"
ARCH="$(uname -m)"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
PACKAGE_NAME="bsdm-proxy-${PACKAGE_VERSION}-${OS}-${ARCH}"
STAGING="${ROOT}/dist/${PACKAGE_NAME}"

echo "==> Building release binaries (v${VERSION})"
cargo build --release -p bsdm-proxy --bin proxy -p cache-indexer --bin cache-indexer

echo "==> Assembling package ${PACKAGE_NAME}"
rm -rf "$STAGING"
mkdir -p "$STAGING"/{bin,config,systemd}

cp target/release/proxy target/release/cache-indexer "$STAGING/bin/"
cp packaging/config/*.example "$STAGING/config/"
cp config/acl-rules.example.json "$STAGING/config/"
cp packaging/systemd/*.service "$STAGING/systemd/"
cp packaging/install.sh "$STAGING/"
cp packaging/README.md "$STAGING/"
chmod +x "$STAGING/install.sh" "$STAGING/bin/"*

echo "${VERSION}" >"$STAGING/VERSION"

(
  cd "$STAGING"
  sha256sum bin/* >SHA256SUMS
)

TARBALL="${ROOT}/dist/${PACKAGE_NAME}.tar.gz"
tar -C "${ROOT}/dist" -czf "$TARBALL" "$PACKAGE_NAME"

echo "==> Package ready"
echo "    Directory: ${STAGING}"
echo "    Archive:   ${TARBALL}"
echo "    Size:      $(du -h "$TARBALL" | cut -f1)"
echo ""
cat "$STAGING/SHA256SUMS"
