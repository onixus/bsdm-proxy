#!/usr/bin/env bash
# Restore ClickHouse Native dumps produced by backup-clickhouse.sh.
#
# Usage:
#   ./scripts/restore-clickhouse.sh backups/clickhouse/20260804T120000Z
#
# Requires: target DB schema already applied (init SQL / migrations).
# Does not DROP tables; inserts into existing tables (may duplicate rows —
# for drill use a clean volume or TRUNCATE first with RESTORE_TRUNCATE=1).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${1:-}"
if [[ -z "$SRC" || ! -d "$SRC" ]]; then
  echo "usage: $0 <backup-directory>" >&2
  exit 1
fi

DATABASE="${CLICKHOUSE_DATABASE:-bsdm}"
COMPOSE_FILES="${COMPOSE_FILES:--f docker-compose.yml}"
SERVICE="${CLICKHOUSE_SERVICE:-clickhouse}"
USE_COMPOSE="${USE_COMPOSE:-1}"
TRUNCATE="${RESTORE_TRUNCATE:-0}"

ch_exec() {
  if [[ "$USE_COMPOSE" == "1" ]]; then
    # shellcheck disable=SC2086
    docker compose ${COMPOSE_FILES} exec -T "$SERVICE" clickhouse-client --database "$DATABASE" "$@"
  else
    echo "Non-compose restore: pipe Native files via clickhouse-client --query 'INSERT INTO ...' FORMAT Native" >&2
    exit 1
  fi
}

echo "==> Restoring from ${SRC}"
if [[ ! -f "${SRC}/MANIFEST.txt" ]]; then
  echo "Missing MANIFEST.txt in ${SRC}" >&2
  exit 1
fi
cat "${SRC}/MANIFEST.txt"

if ! ch_exec --query "SELECT 1" >/dev/null 2>&1; then
  echo "Cannot reach ClickHouse" >&2
  exit 1
fi

shopt -s nullglob
for f in "${SRC}"/*.native; do
  table="$(basename "$f" .native)"
  echo "  restoring ${DATABASE}.${table}"
  if [[ "$TRUNCATE" == "1" ]]; then
    ch_exec --query "TRUNCATE TABLE IF EXISTS ${DATABASE}.${table}"
  fi
  # shellcheck disable=SC2086
  docker compose ${COMPOSE_FILES} exec -T "$SERVICE" \
    clickhouse-client --database "$DATABASE" \
    --query "INSERT INTO ${DATABASE}.${table} FORMAT Native" <"$f"
done

echo "==> Restore complete"
if [[ -f "${SRC}/COUNTS.txt" ]]; then
  echo "Expected counts:"
  cat "${SRC}/COUNTS.txt"
fi
