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
  "scripts/installer/release.sh" \
  "scripts/install-release.sh" \
  "scripts/installer/validation.sh"
do
  test -f "${ROOT}/${file}"
  bash -n "${ROOT}/${file}"
done

# install-release.sh must stay self-contained: it is documented as a
# curl | bash entry point, so it may not source anything from the repo.
if grep -qE '^[[:space:]]*(source|\.)[[:space:]]' "${ROOT}/scripts/install-release.sh"; then
  echo "scripts/install-release.sh must not source other files" >&2
  exit 1
fi
"${ROOT}/scripts/install-release.sh" --help >/dev/null

echo "Installer sanity checks passed"
