#!/usr/bin/env bash
# Assemble a fleet drop directory (unsigned) from built agent binaries.
# Usage:
#   ./scripts/build-agent-binaries.sh   # optional first
#   ./scripts/build-agent-fleet-packages.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OUT:-${ROOT}/dist/fleet}"
VERSION="${VERSION:-$(grep -m1 '^version' "${ROOT}/proxy/Cargo.toml" | sed 's/.*"\(.*\)"/\1/')}"

mkdir -p "${OUT}/windows" "${OUT}/linux" "${OUT}/macos" "${OUT}/docs"

# Prefer cross-built names from build-agent-binaries.sh; fall back to local release.
copy_if() {
  local src="$1" dest="$2"
  if [[ -f "${src}" ]]; then
    install -m 0755 "${src}" "${dest}"
    echo "  + ${dest}"
  fi
}

echo "Assembling fleet drop → ${OUT} (version ${VERSION})"
copy_if "${ROOT}/target/release/agent-spike" "${OUT}/linux/bsdm-agent"
copy_if "${ROOT}/target/x86_64-unknown-linux-gnu/release/agent-spike" "${OUT}/linux/bsdm-agent-linux-amd64"
copy_if "${ROOT}/target/aarch64-unknown-linux-gnu/release/agent-spike" "${OUT}/linux/bsdm-agent-linux-arm64"
copy_if "${ROOT}/target/release/agent-spike" "${OUT}/macos/bsdm-agent"
copy_if "${ROOT}/target/release/agent-spike.exe" "${OUT}/windows/bsdm-agent.exe"
copy_if "${ROOT}/target/x86_64-pc-windows-gnu/release/agent-spike.exe" "${OUT}/windows/bsdm-agent.exe"

# Fleet scripts
cp -R "${ROOT}/packaging/agent/fleet/windows/intune/"*.ps1 "${OUT}/windows/" 2>/dev/null || true
cp -R "${ROOT}/packaging/agent/fleet/windows/intune/README.md" "${OUT}/windows/INTUNE.md" 2>/dev/null || true
cp -R "${ROOT}/packaging/agent/fleet/windows/gpo" "${OUT}/windows/gpo"
cp "${ROOT}/packaging/agent/fleet/linux/install-silent.sh" "${OUT}/linux/"
cp "${ROOT}/packaging/agent/install-linux.sh" "${OUT}/linux/"
cp "${ROOT}/packaging/agent/install-macos.sh" "${OUT}/macos/"
cp "${ROOT}/packaging/agent/install-windows.ps1" "${OUT}/windows/"
cp "${ROOT}/packaging/agent/agent.env.example" "${OUT}/"
cp "${ROOT}/packaging/agent/fleet/README.md" "${OUT}/README.md"
cp "${ROOT}/docs/getting-started/pilot-agent-fleet.md" "${OUT}/docs/" 2>/dev/null || true

# macOS pkg if on Darwin and binary present
if [[ "$(uname -s)" == "Darwin" && -x "${OUT}/macos/bsdm-agent" ]]; then
  "${ROOT}/packaging/agent/fleet/macos/build-pkg.sh" \
    --bin "${OUT}/macos/bsdm-agent" \
    --out "${OUT}/macos/bsdm-agent-${VERSION}.pkg" \
    --version "${VERSION}" || true
fi

cat > "${OUT}/MANIFEST.txt" <<EOF
BSDM Agent fleet drop
version=${VERSION}
generated=$(date -u +%Y-%m-%dT%H:%M:%SZ)
unsigned=yes
see=packaging/agent/fleet/README.md
EOF

echo "Done. Sign binaries/packages before production fleet deploy."
ls -laR "${OUT}" | head -80
