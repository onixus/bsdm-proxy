#!/usr/bin/env bash
# Trust BSDM MITM Root CA on macOS (Safari, Chrome, Edge use System keychain).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA="${CA:-$ROOT/certs/ca.crt}"

if [[ ! -f "$CA" ]]; then
  echo "CA not found: $CA" >&2
  echo "Run: ./scripts/generate-mitm-ca.sh" >&2
  exit 1
fi

echo "Installing BSDM Root CA to System keychain (requires sudo)..."
echo "File: $CA"

# Remove stale copies so trust settings apply cleanly.
sudo security delete-certificate -c "BSDM Root CA" /Library/Keychains/System.keychain 2>/dev/null || true

sudo security add-trusted-cert -d -r trustRoot -p ssl -p basic \
  -k /Library/Keychains/System.keychain "$CA"

echo
echo "Done. Verify:"
security find-certificate -c "BSDM Root CA" /Library/Keychains/System.keychain | head -3

echo
echo "Browser proxy settings (System Settings → Network → Wi‑Fi/Ethernet → Details → Proxies):"
echo "  Web Proxy (HTTP):      127.0.0.1  port 8080"
echo "  Secure Web Proxy:      127.0.0.1  port 8080"
echo "  Bypass: localhost, 127.0.0.1, *.local"
echo
echo "Firefox uses its own store — import $CA manually:"
echo "  Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import"
echo
echo "For browser use on macOS, run the proxy natively (not in Docker):"
echo "  ./scripts/run-proxy-native.sh"
echo
echo "Docker + system proxy on port 1488 causes upstream 502 (proxy loop)."
