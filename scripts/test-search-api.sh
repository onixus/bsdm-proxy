#!/usr/bin/env bash
# Smoke test for cache-indexer Search API (requires docker compose up stack).
set -euo pipefail

BASE_URL="${SEARCH_API_URL:-http://127.0.0.1:8080}"

echo "Checking /health..."
curl -fsS "${BASE_URL}/health" | grep -q ok

echo "Checking /api/search (JSON)..."
body=$(curl -fsS "${BASE_URL}/api/search?limit=5")
echo "$body" | python3 -c "import json,sys; json.load(sys.stdin)"

echo "Checking /api/search (CSV)..."
curl -fsS "${BASE_URL}/api/search?limit=2&format=csv" | head -1 | grep -q domain

echo "Search API smoke test passed."
