#!/usr/bin/env bash
# Offline-friendly drill for CA archive restore + optional ClickHouse backup path.
#
# Always runs the CA rotation drill and verifies archive restore steps.
# If ClickHouse is reachable via compose, also runs backup → truncate → restore.
#
# Usage:
#   ./scripts/drill-backup-restore.sh
#   SKIP_CLICKHOUSE=1 ./scripts/drill-backup-restore.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "============================================================"
echo " BSDM backup/restore drill"
echo "============================================================"

echo ""
echo "==> [1/2] CA rotation + archive restore path"
# Existing offline CA drill (permissions, activate, archive).
"${ROOT}/scripts/test-ca-rotation.sh"

# Explicit archive restore rehearsal (simulate rollback after bad activate).
DRILL="$(mktemp -d "${TMPDIR:-/tmp}/bsdm-ca-restore.XXXXXX")"
trap 'rm -rf "${DRILL}"' EXIT
CERT_DIR="${DRILL}/certs"
"${ROOT}/scripts/gen-ca.sh" --cert-dir "${CERT_DIR}" >/dev/null
fp1="$(openssl x509 -in "${CERT_DIR}/ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
prep="$("${ROOT}/scripts/rotate-ca.sh" prepare --cert-dir "${CERT_DIR}" --common-name "BSDM Restore Drill")"
stage="$(printf '%s\n' "${prep}" | sed -n 's/^Prepared CA: //p')"
"${ROOT}/scripts/rotate-ca.sh" activate "${stage}" --cert-dir "${CERT_DIR}" >/dev/null
fp2="$(openssl x509 -in "${CERT_DIR}/ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
[[ "$fp1" != "$fp2" ]]
archive_key="$(find "${CERT_DIR}/archive" -name ca.key -type f | head -1)"
archive_dir="$(dirname "${archive_key}")"
# Rollback: restore archived pair as active.
cp "${archive_dir}/ca.key" "${CERT_DIR}/ca.key"
cp "${archive_dir}/ca.crt" "${CERT_DIR}/ca.crt"
chmod 600 "${CERT_DIR}/ca.key"
fp3="$(openssl x509 -in "${CERT_DIR}/ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
[[ "$fp3" == "$fp1" ]]
echo "CA archive restore drill passed (rolled back to original fingerprint)"

echo ""
echo "==> [2/2] ClickHouse backup/restore (optional)"
if [[ "${SKIP_CLICKHOUSE:-0}" == "1" ]]; then
  echo "SKIP_CLICKHOUSE=1 — skipping ClickHouse section"
  echo "============================================================"
  echo " Drill complete (CA only)"
  echo "============================================================"
  exit 0
fi

COMPOSE_FILES="${COMPOSE_FILES:--f docker-compose.yml}"
SERVICE="${CLICKHOUSE_SERVICE:-clickhouse}"
# shellcheck disable=SC2086
if ! docker compose ${COMPOSE_FILES} ps --status running "$SERVICE" 2>/dev/null | grep -q "$SERVICE"; then
  echo "ClickHouse service not running — skip CH drill (start with: docker compose up -d clickhouse)"
  echo "============================================================"
  echo " Drill complete (CA only; CH skipped)"
  echo "============================================================"
  exit 0
fi

BACKUP_DIR="${DRILL}/ch-backup"
export BACKUP_DIR COMPOSE_FILES CLICKHOUSE_SERVICE="$SERVICE"
# Ensure schema exists
# shellcheck disable=SC2086
docker compose ${COMPOSE_FILES} exec -T "$SERVICE" \
  clickhouse-client --query "CREATE DATABASE IF NOT EXISTS bsdm" >/dev/null || true

# Seed a tiny table for the drill if http_cache missing or empty.
# shellcheck disable=SC2086
docker compose ${COMPOSE_FILES} exec -T "$SERVICE" clickhouse-client --multiquery <<'SQL' >/dev/null || true
CREATE DATABASE IF NOT EXISTS bsdm;
CREATE TABLE IF NOT EXISTS bsdm.drill_probe (
  id UInt32,
  note String
) ENGINE = MergeTree ORDER BY id;
TRUNCATE TABLE bsdm.drill_probe;
INSERT INTO bsdm.drill_probe VALUES (1, 'backup-drill');
SQL

"${ROOT}/scripts/backup-clickhouse.sh"
latest="$(ls -1d "${BACKUP_DIR}"/* | sort | tail -1)"
[[ -d "$latest" ]]

export RESTORE_TRUNCATE=1
"${ROOT}/scripts/restore-clickhouse.sh" "$latest"

# shellcheck disable=SC2086
count="$(docker compose ${COMPOSE_FILES} exec -T "$SERVICE" \
  clickhouse-client --database bsdm --query "SELECT count() FROM bsdm.drill_probe" | tr -d '[:space:]')"
[[ "$count" == "1" ]]
echo "ClickHouse backup/restore drill passed (drill_probe count=${count})"

echo "============================================================"
echo " Drill complete (CA + ClickHouse)"
echo "============================================================"
