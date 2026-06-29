#!/usr/bin/env bash
# Disable macOS system HTTP/HTTPS proxy (Wi‑Fi).
set -euo pipefail

SERVICE="${1:-Wi-Fi}"

networksetup -setwebproxystate "$SERVICE" off
networksetup -setsecurewebproxystate "$SERVICE" off

echo "System proxy disabled on '$SERVICE'"
