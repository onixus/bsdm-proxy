#!/usr/bin/env bash
# Run BSDM proxy natively on macOS (recommended with system-wide proxy enabled).
#
# Docker Desktop forwards container outbound traffic through the macOS system
# proxy. When the system proxy points at 127.0.0.1:1488, the container loops
# back into itself and upstream requests fail with 502.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f certs/ca.key ]]; then
  echo "CA not found. Run: ./scripts/generate-mitm-ca.sh" >&2
  exit 1
fi

echo "Stopping Docker proxy container (if running)..."
docker compose stop proxy 2>/dev/null || true

# Port 8080 avoids Docker Desktop leaking tens of thousands of stale TCP
# connections to 1488 (docstor), which breaks localhost on macOS.
export HTTP_PORT="${HTTP_PORT:-8080}"
export METRICS_PORT="${METRICS_PORT:-9090}"
export MITM_ENABLED=true
export AUTH_ENABLED=false
export ACL_ENABLED=false
export CATEGORIZATION_ENABLED=false
export SHALLALIST_ENABLED=false
export RUST_LOG="${RUST_LOG:-info,bsdm_proxy=debug}"

echo "Starting native proxy on 0.0.0.0:${HTTP_PORT} (metrics :${METRICS_PORT})"
echo "Trust CA: ./scripts/trust-mitm-ca-macos.sh"
echo "Press Ctrl+C to stop."
exec cargo run -p bsdm-proxy --bin proxy
