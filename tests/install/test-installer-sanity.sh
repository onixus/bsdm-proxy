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
  "scripts/installer/validation.sh" \
  "packaging/install.sh"
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

# Every service advertised by the release installer must have the assets needed
# to start. In particular, dns-sinkhole requires both an environment file and a
# readable RPZ zone; silently installing only the binary leaves a broken unit.
dns_unit="${ROOT}/packaging/systemd/bsdm-dns-sinkhole.service"
test -f "$dns_unit"
grep -Fq 'EnvironmentFile=/etc/bsdm-proxy/dns-sinkhole.env' "$dns_unit"
grep -Fq 'ExecStart=/opt/bsdm-proxy/bin/dns-sinkhole' "$dns_unit"
grep -Fq 'AmbientCapabilities=CAP_NET_BIND_SERVICE' "$dns_unit"
grep -Fq 'dns-sinkhole.env.example' "${ROOT}/packaging/install.sh"
grep -Fq 'blocklist.rpz.example' "${ROOT}/packaging/install.sh"
grep -Fq 'examples/dns/blocklist.rpz' "${ROOT}/scripts/build-package.sh"
test -f "${ROOT}/packaging/config/dns-sinkhole.env.example"
test -f "${ROOT}/examples/dns/blocklist.rpz"

# PAC is built into the proxy but its optional hot-reload file must still be
# present in the release package and installed to the configured etc directory.
test -f "${ROOT}/packaging/config/pac-bypass.txt.example"
grep -Fq 'pac-bypass.txt.example' "${ROOT}/packaging/install.sh"
grep -Fq 'PAC_BYPASS_FILE=/etc/bsdm-proxy/pac-bypass.txt' \
  "${ROOT}/packaging/config/bsdm-proxy.env.example"
grep -Fq 'PAC_PROXY=proxy.corp.example:3128' \
  "${ROOT}/packaging/config/bsdm-proxy.env.example"

echo "Installer sanity checks passed"
