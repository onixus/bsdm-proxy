#!/usr/bin/env bash
# Diagnose why BSDM proxy / browser MITM fails on macOS.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${HTTP_PORT:-8080}"

echo "=== TCP connections to :1488 (Docker leak indicator) ==="
STALE_1488=$(netstat -an 2>/dev/null | grep -c '\.1488 ' || true)
echo "Count: $STALE_1488"
if (( STALE_1488 > 1000 )); then
  echo "WARNING: Docker Desktop leaked connections to port 1488."
  echo "  Quit Docker Desktop completely, then retry:"
  echo "    osascript -e 'quit app \"Docker\"'"
  echo "  Or reboot macOS."
fi

echo
echo "=== Proxy process / port ${PORT} ==="
if lsof -i ":${PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
  lsof -i ":${PORT}" -sTCP:LISTEN
else
  echo "No listener on ${PORT}. Run: ./scripts/setup-macos-browser-proxy.sh"
fi

echo
echo "=== Loopback connect test ==="
if python3 -c "import socket; s=socket.create_connection(('127.0.0.1',${PORT}),2); s.close()"; then
  echo "OK: can connect to 127.0.0.1:${PORT}"
else
  echo "FAIL: cannot connect to 127.0.0.1:${PORT} (often stale Docker TCP on 1488)"
fi

echo
echo "=== System proxy (Wi-Fi) ==="
networksetup -getwebproxy Wi-Fi 2>/dev/null || true
networksetup -getsecurewebproxy Wi-Fi 2>/dev/null || true

echo
echo "=== CA trust ==="
if security find-certificate -c "BSDM Root CA" /Library/Keychains/System.keychain >/dev/null 2>&1; then
  echo "BSDM Root CA found in System keychain"
else
  echo "CA NOT trusted. Run: ./scripts/trust-mitm-ca-macos.sh"
fi

echo
echo "=== MITM smoke test (explicit proxy, no system settings changed) ==="
if curl -sf -o /dev/null -w "example.com -> HTTP %{http_code}\n" \
  -x "http://127.0.0.1:${PORT}" --cacert "$ROOT/certs/ca.crt" https://example.com/; then
  :
else
  echo "MITM test failed"
fi
