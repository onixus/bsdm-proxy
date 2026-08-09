#!/usr/bin/env bash
# Build and publish the multi-platform proxy image from a validated release tag.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

TAG="${1:-${CI_RELEASE_TAG:-}}"
if [[ ! "$TAG" =~ ^v.+ ]]; then
  echo "usage: publish-image.sh <vX.Y.Z>" >&2
  exit 1
fi

command -v docker >/dev/null 2>&1 || {
  echo "docker is required" >&2
  exit 1
}

CI_RELEASE_TAG="$TAG" SKIP_CARGO_METADATA=1 ./scripts/ci/validate-release.sh

IMAGE_NAME="${IMAGE_NAME:-ghcr.io/onixus/bsdm-proxy}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
VERSION="${TAG#v}"
tags=(--tag "${IMAGE_NAME}:${VERSION}")
if [[ "$VERSION" != *-* && "${PUBLISH_LATEST:-1}" == "1" ]]; then
  tags+=(--tag "${IMAGE_NAME}:latest")
fi

temporary_builder=""
cleanup_builder() {
  if [[ -n "$temporary_builder" ]]; then
    docker buildx rm "$temporary_builder" >/dev/null 2>&1 || true
  fi
}
trap cleanup_builder EXIT

if ! docker buildx inspect >/dev/null 2>&1; then
  temporary_builder="$(docker buildx create --use)"
fi
docker buildx inspect --bootstrap >/dev/null

docker buildx build \
  --file Dockerfile \
  --target proxy \
  --platform "$PLATFORMS" \
  --provenance=mode=max \
  --sbom=true \
  --push \
  "${tags[@]}" \
  .
