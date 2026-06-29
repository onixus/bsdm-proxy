#!/bin/sh
set -eu

DASHBOARDS_URL="${DASHBOARDS_URL:-http://opensearch-dashboards:5601}"
INDEX_PATTERN_ID="http-cache-pattern"

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

echo "Waiting for OpenSearch Dashboards..."
wait_for_dashboards

echo "Creating index pattern http-cache*..."
upsert_saved_object "index-pattern" "${INDEX_PATTERN_ID}" \
  '{"attributes":{"title":"http-cache*","timeFieldName":"timestamp"}}'

echo "Creating saved searches..."
upsert_saved_object "search" "requests-by-user" \
  '{"attributes":{"title":"Requests by user","columns":["timestamp","username","client_ip","domain","url","method","status","cache_status"],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"http-cache-pattern\",\"query\":{\"query\":\"username:*\",\"language\":\"kuery\"},\"filter\":[]}"}}}'

upsert_saved_object "search" "requests-by-domain" \
  '{"attributes":{"title":"Requests by domain","columns":["timestamp","username","client_ip","domain","url","method","status","cache_status"],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"http-cache-pattern\",\"query\":{\"query\":\"domain:*\",\"language\":\"kuery\"},\"filter\":[]}"}}}'

upsert_saved_object "search" "blocked-threat-events" \
  '{"attributes":{"title":"Blocked and threat categories","columns":["timestamp","username","client_ip","domain","url","cache_status","categories"],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"http-cache-pattern\",\"query\":{\"query\":\"cache_status:BYPASS OR categories:*\",\"language\":\"kuery\"},\"filter\":[]}"}}}'

upsert_saved_object "search" "top-domains-overview" \
  '{"attributes":{"title":"Traffic overview by domain","columns":["timestamp","domain","username","client_ip","url","method","status"],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"http-cache-pattern\",\"query\":{\"query\":\"*\",\"language\":\"kuery\"},\"filter\":[]}"}}}'

echo "OpenSearch Dashboards saved objects provisioned."
