#!/usr/bin/env bash
# Configure macOS system HTTP/HTTPS proxy for BSDM (Wi‑Fi).
set -euo pipefail

SERVICE="${1:-Wi-Fi}"
HOST="${PROXY_HOST:-127.0.0.1}"
PORT="${PROXY_PORT:-8080}"

# macOS expects host only — NOT http://127.0.0.1
HOST="${HOST#http://}"
HOST="${HOST#https://}"
HOST="${HOST%%/*}"

networksetup -setwebproxy "$SERVICE" "$HOST" "$PORT"
networksetup -setsecurewebproxy "$SERVICE" "$HOST" "$PORT"
networksetup -setproxybypassdomains "$SERVICE" \
  localhost 127.0.0.1 "*.local" "*.localhost" \
  10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16

echo "Proxy enabled on '$SERVICE': $HOST:$PORT"
networksetup -getwebproxy "$SERVICE"
networksetup -getsecurewebproxy "$SERVICE"

echo
echo "IMPORTANT: use port 8080 for native proxy (not 1488)."
echo "Docker Desktop can exhaust localhost:1488 with stale TCP connections."
echo
echo "Quick setup:"
echo "  ./scripts/setup-macos-browser-proxy.sh"
echo
echo "Also trust MITM CA: ./scripts/trust-mitm-ca-macos.sh"
