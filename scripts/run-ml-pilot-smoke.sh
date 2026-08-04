#!/usr/bin/env bash
# Smoke: ml-worker one-model pilot path (health, threat-scores API, metrics).
#
# Prerequisites: ml-worker healthy (compose --profile ml or cargo run -p ml-worker).
# ClickHouse checks are best-effort when clickhouse-client / curl to CH is available.
#
# Usage:
#   ML_URL=http://127.0.0.1:8091 \
#   CLICKHOUSE_URL=http://127.0.0.1:8123 \
#   ./scripts/run-ml-pilot-smoke.sh
set -euo pipefail

ML_URL="${ML_URL:-http://127.0.0.1:8091}"
ML_URL="${ML_URL%/}"
CLICKHOUSE_URL="${CLICKHOUSE_URL:-http://127.0.0.1:8123}"
CLICKHOUSE_URL="${CLICKHOUSE_URL%/}"
CLICKHOUSE_DATABASE="${CLICKHOUSE_DATABASE:-bsdm}"
TIMEOUT="${TIMEOUT:-10}"
REQUIRE_SCORES="${REQUIRE_SCORES:-0}"

echo "============================================================"
echo " ML pilot smoke (one model / UEBA path)"
echo " ml-worker: ${ML_URL}"
echo " ClickHouse: ${CLICKHOUSE_URL} (optional)"
echo "============================================================"

health="$(
  curl -fsS --max-time "$TIMEOUT" "${ML_URL}/health" || true
)"
if [[ -z "${health}" ]]; then
  echo "❌ ml-worker not healthy at ${ML_URL}/health" >&2
  echo "   Start: docker compose --profile ml up -d ml-worker" >&2
  echo "   Docs:  docs/getting-started/pilot-ml.md" >&2
  exit 1
fi
if ! echo "${health}" | grep -q 'ok'; then
  echo "❌ Unexpected health body: ${health}" >&2
  exit 1
fi
echo "✅ GET /health → ${health}"

scores="$(
  curl -fsS --max-time "$TIMEOUT" "${ML_URL}/api/threat-scores" || true
)"
if [[ -z "${scores}" ]]; then
  echo "❌ GET /api/threat-scores failed" >&2
  exit 1
fi
# Accept empty array/object — write-back may be empty without traffic
if ! echo "${scores}" | grep -qE '\[|\{'; then
  echo "❌ threat-scores body is not JSON-like: ${scores}" >&2
  exit 1
fi
echo "✅ GET /api/threat-scores (body length ${#scores})"

if [[ "${REQUIRE_SCORES}" == "1" ]]; then
  # Non-empty: at least one digit score or entity field
  if ! echo "${scores}" | grep -qE '"score"|[0-9]+\.[0-9]+'; then
    echo "❌ REQUIRE_SCORES=1 but snapshot looks empty: ${scores}" >&2
    exit 1
  fi
  echo "✅ REQUIRE_SCORES: snapshot has score data"
fi

metrics="$(
  curl -fsS --max-time "$TIMEOUT" "${ML_URL}/metrics" || true
)"
if [[ -z "${metrics}" ]]; then
  echo "❌ GET /metrics failed" >&2
  exit 1
fi
if ! echo "${metrics}" | grep -q 'bsdm_ml_worker_cycles_total'; then
  echo "❌ metrics missing bsdm_ml_worker_cycles_total" >&2
  exit 1
fi
cycles="$(echo "${metrics}" | awk '/^bsdm_ml_worker_cycles_total / {print $2; exit}')"
echo "✅ GET /metrics · bsdm_ml_worker_cycles_total=${cycles:-?}"

# Optional ClickHouse probes (do not fail the smoke if CH CLI/curl unavailable)
ch_ok=0
if command -v clickhouse-client >/dev/null 2>&1; then
  if count="$(clickhouse-client --query "SELECT count() FROM ${CLICKHOUSE_DATABASE}.entity_features" 2>/dev/null)"; then
    echo "ℹ️  ClickHouse entity_features rows: ${count}"
    ch_ok=1
  fi
  if count="$(clickhouse-client --query "SELECT count() FROM ${CLICKHOUSE_DATABASE}.ml_scores" 2>/dev/null)"; then
    echo "ℹ️  ClickHouse ml_scores rows: ${count}"
    ch_ok=1
  fi
elif curl -fsS --max-time "$TIMEOUT" \
  "${CLICKHOUSE_URL}/?query=SELECT%201" >/dev/null 2>&1; then
  feat="$(
    curl -fsS --max-time "$TIMEOUT" \
      --get "${CLICKHOUSE_URL}/" \
      --data-urlencode "query=SELECT count() FROM ${CLICKHOUSE_DATABASE}.entity_features" \
      2>/dev/null || true
  )"
  if [[ -n "${feat}" ]]; then
    echo "ℹ️  ClickHouse entity_features rows: ${feat}"
    ch_ok=1
  fi
fi
if [[ "${ch_ok}" -eq 0 ]]; then
  echo "ℹ️  ClickHouse not probed (optional) — worker HTTP path is enough for smoke"
fi

echo "============================================================"
echo " ML pilot smoke PASSED"
echo "============================================================"
echo " Next: generate proxy traffic, wait ≥ ML_POLL_INTERVAL_SECS, re-check"
echo "       ml_scores /api/threat-scores. Full guide: docs/getting-started/pilot-ml.md"
