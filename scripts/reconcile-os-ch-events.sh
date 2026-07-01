#!/usr/bin/env bash
# Compare OpenSearch vs ClickHouse event counts during dual-write migration.
set -euo pipefail

WINDOW_HOURS="${WINDOW_HOURS:-24}"
DRIFT_PCT="${DRIFT_PCT:-0.1}"
OPENSEARCH_URL="${OPENSEARCH_URL:-http://127.0.0.1:9200}"
OPENSEARCH_INDEX="${OPENSEARCH_INDEX:-http-cache}"
CLICKHOUSE_URL="${CLICKHOUSE_URL:-http://127.0.0.1:8123}"
CLICKHOUSE_DATABASE="${CLICKHOUSE_DATABASE:-bsdm}"
CLICKHOUSE_TABLE="${CLICKHOUSE_TABLE:-http_cache}"

now_epoch="$(date +%s)"
from_epoch=$((now_epoch - WINDOW_HOURS * 3600))

echo "Reconciling OS vs CH (window=${WINDOW_HOURS}h, drift<=${DRIFT_PCT}%)"
echo "  OpenSearch: ${OPENSEARCH_URL}/${OPENSEARCH_INDEX}"
echo "  ClickHouse: ${CLICKHOUSE_URL}/${CLICKHOUSE_DATABASE}.${CLICKHOUSE_TABLE}"

os_query=$(cat <<EOF
{
  "query": {
    "range": {
      "timestamp": {
        "gte": ${from_epoch},
        "lte": ${now_epoch}
      }
    }
  }
}
EOF
)

os_count="$(
  curl -fsS "${OPENSEARCH_URL}/${OPENSEARCH_INDEX}/_count" \
    -H 'Content-Type: application/json' \
    -d "${os_query}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("count",0))'
)"

ch_sql="SELECT count(), count(DISTINCT event_id) FROM ${CLICKHOUSE_DATABASE}.${CLICKHOUSE_TABLE} WHERE ts >= fromUnixTimestamp(${from_epoch}) AND ts <= fromUnixTimestamp(${now_epoch}) FORMAT TabSeparated"
ch_line="$(curl -fsS "${CLICKHOUSE_URL}/" --data-binary "${ch_sql}")"
ch_count="$(echo "${ch_line}" | cut -f1)"
ch_distinct="$(echo "${ch_line}" | cut -f2)"

echo "OpenSearch count:        ${os_count}"
echo "ClickHouse count:        ${ch_count}"
echo "ClickHouse distinct ids: ${ch_distinct}"

if [[ "${os_count}" -eq 0 && "${ch_count}" -eq 0 ]]; then
  echo "OK: both stores empty in window"
  exit 0
fi

base="${os_count}"
if [[ "${base}" -eq 0 ]]; then
  base="${ch_count}"
fi
diff=$((os_count > ch_count ? os_count - ch_count : ch_count - os_count))
drift="$(python3 - <<PY
base=${base}
diff=${diff}
print((diff/base*100) if base else 0)
PY
)"

echo "Drift: ${diff} events (${drift}%)"

python3 - <<PY
import sys
drift=float("${drift}")
limit=float("${DRIFT_PCT}")
if drift > limit:
    print(f"FAIL: drift {drift:.4f}% > {limit}%", file=sys.stderr)
    sys.exit(1)
print(f"OK: drift {drift:.4f}% <= {limit}%")
PY
