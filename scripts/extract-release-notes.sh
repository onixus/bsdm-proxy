#!/usr/bin/env bash
# Print GitHub Release body for a version (e.g. 0.3.0 or v0.3.0).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1#v}"

if [[ -z "$VERSION" ]]; then
  echo "usage: extract-release-notes.sh <version>" >&2
  echo "  example: extract-release-notes.sh v0.3.0" >&2
  exit 1
fi

NOTES_FILE="${ROOT}/docs/releases/v${VERSION}.md"
if [[ -f "$NOTES_FILE" ]]; then
  cat "$NOTES_FILE"
  exit 0
fi

CHANGELOG="${ROOT}/CHANGELOG.md"
if [[ ! -f "$CHANGELOG" ]]; then
  echo "No release notes for v${VERSION}" >&2
  exit 1
fi

awk -v ver="$VERSION" '
  $0 ~ "^## \\[" ver "\\]" { found=1; next }
  found && $0 ~ "^## \\[" { exit }
  found { print }
' "$CHANGELOG"
