#!/usr/bin/env bash
# Publish the already-built dist artifacts as a GitHub Release.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

TAG="${1:-${CI_RELEASE_TAG:-}}"
if [[ ! "$TAG" =~ ^v.+ ]]; then
  echo "usage: publish-github-release.sh <vX.Y.Z>" >&2
  exit 1
fi

for command_name in gh sha256sum; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required command is not available: ${command_name}" >&2
    exit 1
  fi
done

CI_RELEASE_TAG="$TAG" ./scripts/ci/validate-release.sh
shopt -s nullglob
archives=(dist/*.tar.gz)
checksums=(dist/*.tar.gz.sha256)
if (( ${#archives[@]} == 0 || ${#checksums[@]} == 0 )); then
  echo "release artifacts are missing in dist/" >&2
  exit 1
fi

(
  cd dist
  sha256sum -c ./*.tar.gz.sha256
)

if gh release view "$TAG" >/dev/null 2>&1; then
  echo "GitHub Release ${TAG} already exists; refusing to overwrite it" >&2
  exit 1
fi

VERSION="${TAG#v}"
./scripts/extract-release-notes.sh "$VERSION" >dist/RELEASE_NOTES.md
arguments=(
  release create "$TAG"
  --verify-tag
  --title "BSDM-Proxy ${TAG}"
  --notes-file dist/RELEASE_NOTES.md
)
if [[ "$VERSION" == *-* ]]; then
  arguments+=(--prerelease)
fi

gh "${arguments[@]}" "${archives[@]}" "${checksums[@]}"
