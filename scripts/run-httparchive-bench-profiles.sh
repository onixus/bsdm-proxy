#!/usr/bin/env bash
# Run HTTP Archive sites bench for warm and cold WORKER_COUNT profiles (#97).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

for profile in warm cold; do
  echo ""
  echo "=============================="
  echo " BENCH_PROFILE=${profile}"
  echo "=============================="
  BENCH_PROFILE="${profile}" "${ROOT}/scripts/run-httparchive-benchmark.sh" "httparchive-${profile}"
done

echo ""
echo "Profiles complete. Compare warm vs cold goodput in bench output above."
