#!/usr/bin/env bash
# Start native BSDM proxy and configure macOS system proxy (port 8080).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROXY_PORT="${PROXY_PORT:-8080}"
SERVICE="${1:-Wi-Fi}"

chmod +x "$ROOT/scripts/"*.sh

if [[ ! -f certs/ca.key ]]; then
  echo "CA not found. Run: ./scripts/generate-mitm-ca.sh" >&2
  exit 1
fi

STALE_1488=$(netstat -an 2>/dev/null | grep -c '\.1488 ' || true)
if (( STALE_1488 > 1000 )); then
  echo "ERROR: $STALE_1488 stale TCP connections on port 1488 (Docker Desktop leak)." >&2
  echo "Quit Docker Desktop first: osascript -e 'quit app \"Docker\"'" >&2
  echo "Then wait 5 seconds and re-run this script." >&2
  exit 1
fi

if [[ ! -x target/debug/proxy ]]; then
  echo "Building proxy..."
  CARGO_TARGET_DIR=target cargo build -p bsdm-proxy --bin proxy
fi

echo "=== Stop Docker proxy and any old native instance ==="
docker compose stop proxy 2>/dev/null || true
pkill -f 'target/debug/proxy' 2>/dev/null || true
pkill -f 'target/release/proxy' 2>/dev/null || true
sleep 1

echo "=== Start native proxy on 0.0.0.0:${PROXY_PORT} ==="
nohup env HTTP_PORT="$PROXY_PORT" METRICS_PORT=9090 MITM_ENABLED=true \
  AUTH_ENABLED=false ACL_ENABLED=false CATEGORIZATION_ENABLED=false \
  SHALLALIST_ENABLED=false RUST_LOG=info,bsdm_proxy=info \
  NO_PROXY='*' HTTP_PROXY= HTTPS_PROXY= ALL_PROXY= \
  CARGO_TARGET_DIR=target "$ROOT/target/debug/proxy" \
  >>"$ROOT/proxy-native.log" 2>&1 &
echo $! >"$ROOT/proxy-native.pid"

for _ in $(seq 1 40); do
  if curl -sf "http://127.0.0.1:9090/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

if ! curl -sf "http://127.0.0.1:9090/health" >/dev/null 2>&1; then
  echo "Proxy failed to start. See $ROOT/proxy-native.log" >&2
  exit 1
fi

echo "=== Configure system proxy (after proxy is up) ==="
PROXY_PORT="$PROXY_PORT" "$ROOT/scripts/configure-macos-proxy.sh" "$SERVICE"

echo
echo "=== Smoke test ==="
curl -sS -o /dev/null -w "example.com via system proxy: HTTP %{http_code}\n" \
  --cacert "$ROOT/certs/ca.crt" https://example.com/

echo
echo "Done."
echo "  Proxy PID: $(cat "$ROOT/proxy-native.pid")"
echo "  Log:       $ROOT/proxy-native.log"
echo "  Port:      ${PROXY_PORT}"
echo
echo "If browser shows certificate errors:"
echo "  ./scripts/trust-mitm-ca-macos.sh"
echo "  Keychain Access -> System -> BSDM Root CA -> Trust -> Always Trust"
echo "  Fully quit and reopen Safari/Chrome."
