#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

command -v bash >/dev/null

for file in \
  "scripts/interactive-install.sh" \
  "scripts/installer/common.sh" \
  "scripts/installer/preflight.sh" \
  "scripts/installer/config.sh" \
  "scripts/installer/backup.sh" \
  "scripts/installer/docker.sh" \
  "scripts/installer/native.sh" \
  "scripts/installer/validation.sh"
do
  test -f "${ROOT}/${file}"
  bash -n "${ROOT}/${file}"
done

echo "Installer sanity checks passed"
