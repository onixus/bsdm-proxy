#!/usr/bin/env bash
# Create macOS .app bundle for BSDM Connect
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
APP_DIR="${1:-${ROOT}/dist/BSDMConnect.app}"
CONTENTS="${APP_DIR}/Contents"
MACOS="${CONTENTS}/MacOS"
RESOURCES="${CONTENTS}/Resources"

echo "==> Building BSDM Connect macOS Application Bundle: ${APP_DIR}"
mkdir -p "${MACOS}" "${RESOURCES}"

# Build release binary if not present
(cd "${ROOT}" && cargo build --release -p agent-spike --bin bsdm-connect)
cp "${ROOT}/target/release/bsdm-connect" "${MACOS}/bsdm-connect-bin"

# Launcher script
cat << 'EOF' > "${MACOS}/BSDMConnect"
#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${DIR}/bsdm-connect-bin"

# Start daemon in background if not running
if ! pgrep -f "bsdm-connect-bin daemon" >/dev/null; then
    "${BIN}" daemon &
    sleep 1
fi

# Open UI in default browser / webview
open "http://127.0.0.1:8765"
EOF

chmod +x "${MACOS}/BSDMConnect" "${MACOS}/bsdm-connect-bin"

# Info.plist
cat << 'EOF' > "${CONTENTS}/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>BSDM Connect</string>
    <key>CFBundleDisplayName</key>
    <string>BSDM Connect</string>
    <key>CFBundleIdentifier</key>
    <string>com.bsdm.connect</string>
    <key>CFBundleVersion</key>
    <string>0.1.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleExecutable</key>
    <string>BSDMConnect</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>LSUIElement</key>
    <false/>
</dict>
</plist>
EOF

echo "==> BSDMConnect.app generated at ${APP_DIR}"
