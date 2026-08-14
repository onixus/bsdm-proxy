#!/usr/bin/env bash
# Validate release metadata before building or publishing artifacts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' proxy/Cargo.toml | head -1)"
if [[ -z "$VERSION" ]]; then
  echo "cannot read package version from proxy/Cargo.toml" >&2
  exit 1
fi

RELEASE_TAG="${CI_RELEASE_TAG:-}"
if [[ -n "$RELEASE_TAG" && "$RELEASE_TAG" != "v${VERSION}" ]]; then
  echo "release tag ${RELEASE_TAG} does not match workspace version v${VERSION}" >&2
  exit 1
fi

PRODUCT_CRATES=(
  proxy
  bsdm-events
  cache-indexer
  alert-worker
  ml-worker
  dns-sinkhole
)

for manifest_dir in "${PRODUCT_CRATES[@]}"; do
  if ! grep -q "^version = \"${VERSION}\"$" "${manifest_dir}/Cargo.toml"; then
    echo "version mismatch in ${manifest_dir}/Cargo.toml; expected ${VERSION}" >&2
    exit 1
  fi
done

if ! grep -Fq "## [${VERSION}]" CHANGELOG.md; then
  echo "CHANGELOG.md has no section for ${VERSION}" >&2
  exit 1
fi

if [[ ! -f "docs/releases/v${VERSION}.md" ]]; then
  echo "release notes are missing: docs/releases/v${VERSION}.md" >&2
  exit 1
fi

if [[ "${SKIP_CARGO_METADATA:-0}" != "1" ]]; then
  if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo is required for locked metadata validation" >&2
    exit 1
  fi
  cargo metadata --locked --no-deps --format-version 1 >/dev/null
fi

echo "Release metadata OK: version=${VERSION} tag=${RELEASE_TAG:-<dry-run>}"
