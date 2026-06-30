#!/bin/sh
set -eu

DASHBOARDS_URL="${DASHBOARDS_URL:-http://opensearch-dashboards:5601}"
OPENSEARCH_INDEX="${OPENSEARCH_INDEX:-http-cache}"
INDEX_PATTERN_ID="${OPENSEARCH_INDEX}-pattern"
INDEX_TITLE="${OPENSEARCH_INDEX}*"

wait_for_dashboards() {
  i=0
  while [ "$i" -lt 60 ]; do
    if curl -fsS "${DASHBOARDS_URL}/api/status" >/dev/null 2>&1; then
      return 0
    fi
    i=$((i + 1))
    sleep 2
  done
  echo "OpenSearch Dashboards is not ready: ${DASHBOARDS_URL}" >&2
  return 1
}

upsert_saved_object() {
  type="$1"
  id="$2"
  body="$3"

  if ! curl -fsS -X POST "${DASHBOARDS_URL}/api/saved_objects/${type}/${id}" \
    -H "osd-xsrf: true" \
    -H "Content-Type: application/json" \
    -d "$body"; then
    curl -fsS -X PUT "${DASHBOARDS_URL}/api/saved_objects/${type}/${id}" \
      -H "osd-xsrf: true" \
      -H "Content-Type: application/json" \
      -d "$body"
  fi
}

search_body() {
  title="$1"
  query="$2"
  columns="$3"
  search_source=$(printf '{"index":"%s","query":{"query":"%s","language":"kuery"},"filter":[]}' \
    "$INDEX_PATTERN_ID" "$query")
  search_source_escaped=$(printf '%s' "$search_source" | sed 's/"/\\"/g')
  printf '{"attributes":{"title":"%s","columns":%s,"kibanaSavedObjectMeta":{"searchSourceJSON":"%s"}}}' \
    "$title" "$columns" "$search_source_escaped"
}

echo "Waiting for OpenSearch Dashboards..."
wait_for_dashboards

echo "Creating index pattern ${INDEX_TITLE}..."
upsert_saved_object "index-pattern" "${INDEX_PATTERN_ID}" \
  "$(printf '{"attributes":{"title":"%s","timeFieldName":"timestamp"}}' "$INDEX_TITLE")"

echo "Creating saved searches..."
upsert_saved_object "search" "requests-by-user" \
  "$(search_body "Requests by user" "username:*" \
    '["timestamp","username","client_ip","domain","url","method","status","cache_status"]')"

upsert_saved_object "search" "requests-by-domain" \
  "$(search_body "Requests by domain" "domain:*" \
    '["timestamp","username","client_ip","domain","url","method","status","cache_status"]')"

upsert_saved_object "search" "blocked-threat-events" \
  "$(search_body "Blocked and threat categories" "acl_action:deny OR acl_action:redirect OR categories:*" \
    '["timestamp","username","client_ip","domain","url","acl_action","cache_status","categories","threat_sources"]')"

upsert_saved_object "search" "top-domains-overview" \
  "$(search_body "Traffic overview by domain" "*" \
    '["timestamp","domain","username","client_ip","url","method","status"]')"

echo "OpenSearch Dashboards saved objects provisioned for index ${OPENSEARCH_INDEX}."
