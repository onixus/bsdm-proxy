#!/usr/bin/env bash
# Backup ClickHouse database `bsdm` from a running compose (or remote) instance.
#
# Usage:
#   ./scripts/backup-clickhouse.sh
#   COMPOSE_FILE=docker-compose.yml CLICKHOUSE_CONTAINER=bsdm-proxy-clickhouse-1 \
#     BACKUP_DIR=./backups/clickhouse ./scripts/backup-clickhouse.sh
#
# Produces: $BACKUP_DIR/<timestamp>/ with Native table dumps + MANIFEST.txt
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_ROOT="${BACKUP_DIR:-${ROOT}/backups/clickhouse}"
STAMP="${BACKUP_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT="${BACKUP_ROOT}/${STAMP}"
DATABASE="${CLICKHOUSE_DATABASE:-bsdm}"
COMPOSE_FILES="${COMPOSE_FILES:--f docker-compose.yml}"
SERVICE="${CLICKHOUSE_SERVICE:-clickhouse}"
# Prefer docker compose exec when service is up; else CLICKHOUSE_URL for HTTP.
USE_COMPOSE="${USE_COMPOSE:-1}"

mkdir -p "$OUT"

ch_query() {
  local sql="$1"
  if [[ "$USE_COMPOSE" == "1" ]]; then
    # shellcheck disable=SC2086
    docker compose ${COMPOSE_FILES} exec -T "$SERVICE" \
      clickhouse-client --database "$DATABASE" --query "$sql"
  else
    local url="${CLICKHOUSE_URL:-http://127.0.0.1:8123}"
    curl -fsS --get "$url" \
      --data-urlencode "database=${DATABASE}" \
      --data-urlencode "query=${sql}"
  fi
}

ch_query_raw() {
  local sql="$1"
  local outfile="$2"
  if [[ "$USE_COMPOSE" == "1" ]]; then
    # shellcheck disable=SC2086
    docker compose ${COMPOSE_FILES} exec -T "$SERVICE" \
      clickhouse-client --database "$DATABASE" --query "$sql" >"$outfile"
  else
    local url="${CLICKHOUSE_URL:-http://127.0.0.1:8123}"
    curl -fsS --get "$url" \
      --data-urlencode "database=${DATABASE}" \
      --data-urlencode "query=${sql}" \
      -o "$outfile"
  fi
}

echo "==> ClickHouse backup → ${OUT}"

if ! ch_query "SELECT 1" >/dev/null 2>&1; then
  echo "Cannot reach ClickHouse (service=${SERVICE}). Is compose up?" >&2
  echo "Hint: docker compose -f docker-compose.yml up -d clickhouse" >&2
  exit 1
fi

# List ordinary tables in the database (skip views if any).
tables="$(
  ch_query "SELECT name FROM system.tables WHERE database = '${DATABASE}' AND engine NOT LIKE '%View%' FORMAT TSV" \
    | tr -d '\r' || true
)"

if [[ -z "${tables//[[:space:]]/}" ]]; then
  echo "No tables found in database ${DATABASE}; writing empty manifest."
  {
    echo "timestamp=${STAMP}"
    echo "database=${DATABASE}"
    echo "tables="
    echo "note=empty"
  } >"${OUT}/MANIFEST.txt"
  echo "Done (empty)."
  exit 0
fi

table_list=()
while IFS= read -r t; do
  [[ -z "$t" ]] && continue
  table_list+=("$t")
  echo "  dumping ${DATABASE}.${t}"
  # Native format is compact and re-loadable via clickhouse-client.
  ch_query_raw "SELECT * FROM ${DATABASE}.${t} FORMAT Native" "${OUT}/${t}.native" || {
    echo "WARN: failed to dump ${t}" >&2
    rm -f "${OUT}/${t}.native"
  }
  # Also store row count for verification.
  count="$(ch_query "SELECT count() FROM ${DATABASE}.${t}" | tr -d '[:space:]' || echo "?")"
  echo "${t}=${count}" >>"${OUT}/COUNTS.txt"
done <<<"$tables"

{
  echo "timestamp=${STAMP}"
  echo "database=${DATABASE}"
  echo "tables=$(IFS=,; echo "${table_list[*]}")"
  echo "host=$(hostname 2>/dev/null || echo unknown)"
  echo "created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"${OUT}/MANIFEST.txt"

echo "==> Backup complete: ${OUT}"
cat "${OUT}/MANIFEST.txt"
[[ -f "${OUT}/COUNTS.txt" ]] && cat "${OUT}/COUNTS.txt"
