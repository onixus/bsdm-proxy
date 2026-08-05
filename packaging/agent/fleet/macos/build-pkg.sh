#!/usr/bin/env bash
# Build an *unsigned* macOS component package for Jamf / MDM.
# Sign + notarize in your pipeline (productsign, notarytool).
#
# Usage:
#   ./packaging/agent/fleet/macos/build-pkg.sh --bin ./target/release/agent-spike --out ./dist/bsdm-agent.pkg
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
BIN=""
OUT="${ROOT}/dist/bsdm-agent.pkg"
IDENTIFIER="com.bsdm.agent"
VERSION="${VERSION:-0.9.10}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin) BIN="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --identifier) IDENTIFIER="$2"; shift 2 ;;
    -h|--help) sed -n '1,12p' "$0"; exit 0 ;;
    *) echo "unknown: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "${BIN}" || ! -x "${BIN}" ]]; then
  echo "error: --bin path to agent binary required" >&2
  exit 2
fi
if ! command -v pkgbuild >/dev/null; then
  echo "error: pkgbuild not found (run on macOS)" >&2
  exit 1
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/bsdm-pkg.XXXXXX")"
trap 'rm -rf "${STAGE}"' EXIT
mkdir -p "${STAGE}/payload/usr/local/bsdm-agent/bin" \
         "${STAGE}/payload/usr/local/etc/bsdm-agent" \
         "${STAGE}/payload/Library/LaunchDaemons" \
         "${STAGE}/scripts"

install -m 0755 "${BIN}" "${STAGE}/payload/usr/local/bsdm-agent/bin/bsdm-agent"
install -m 0644 "${ROOT}/packaging/agent/agent.env.example" \
  "${STAGE}/payload/usr/local/etc/bsdm-agent/agent.env"
install -m 0644 "${ROOT}/packaging/agent/launchd/com.bsdm.agent.plist" \
  "${STAGE}/payload/Library/LaunchDaemons/com.bsdm.agent.plist"

# postinstall: ensure wrapper + bootstrap launchd
cat > "${STAGE}/scripts/postinstall" <<'POST'
#!/bin/bash
set -euo pipefail
PREFIX=/usr/local/bsdm-agent
ETC=/usr/local/etc/bsdm-agent
WRAP="${PREFIX}/bin/bsdm-agent-launch"
cat > "${WRAP}" <<EOF
#!/bin/bash
set -a
[[ -f ${ETC}/agent.env ]] && source ${ETC}/agent.env
set +a
exec ${PREFIX}/bin/bsdm-agent "\$@"
EOF
chmod 0755 "${WRAP}"
if command -v /usr/libexec/PlistBuddy >/dev/null; then
  /usr/libexec/PlistBuddy -c "Set :ProgramArguments:0 ${WRAP}" \
    /Library/LaunchDaemons/com.bsdm.agent.plist 2>/dev/null || true
fi
launchctl bootout system/com.bsdm.agent 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.bsdm.agent.plist 2>/dev/null || true
exit 0
POST
chmod 0755 "${STAGE}/scripts/postinstall"

mkdir -p "$(dirname "${OUT}")"
pkgbuild \
  --root "${STAGE}/payload" \
  --scripts "${STAGE}/scripts" \
  --identifier "${IDENTIFIER}" \
  --version "${VERSION}" \
  --install-location / \
  "${OUT}"

echo "Wrote unsigned package: ${OUT}"
echo "Next: productsign --sign 'Developer ID Installer: …' ${OUT} ${OUT%.pkg}-signed.pkg"
echo "      xcrun notarytool submit …  (enterprise Apple Developer account)"
