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

upsert_saved_object_with_refs() {
  type="$1"
  id="$2"
  payload="$3"

  if ! curl -fsS -X POST "${DASHBOARDS_URL}/api/saved_objects/${type}/${id}" \
    -H "osd-xsrf: true" \
    -H "Content-Type: application/json" \
    -d "$payload"; then
    curl -fsS -X PUT "${DASHBOARDS_URL}/api/saved_objects/${type}/${id}" \
      -H "osd-xsrf: true" \
      -H "Content-Type: application/json" \
      -d "$payload"
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

visualization_body() {
  title="$1"
  vis_state="$2"
  query="${3:-*}"
  search_source=$(printf '{"index":"%s","query":{"query":"%s","language":"kuery"},"filter":[]}' \
    "$INDEX_PATTERN_ID" "$query")
  search_source_escaped=$(printf '%s' "$search_source" | sed 's/"/\\"/g')
  vis_state_escaped=$(printf '%s' "$vis_state" | sed 's/"/\\"/g')
  printf '{"attributes":{"title":"%s","visState":"%s","uiStateJSON":"{}","kibanaSavedObjectMeta":{"searchSourceJSON":"%s"}}}' \
    "$title" "$vis_state_escaped" "$search_source_escaped"
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

upsert_saved_object "search" "domain-traffic-playbook" \
  "$(search_body "Playbook: traffic to domain (edit domain: value)" "domain:example.com" \
    '["timestamp","username","client_ip","domain","url","method","status","cache_status","acl_action"]')"

echo "Creating visualizations..."

VIS_REQUESTS_TIMELINE='{"title":"Requests over time","type":"histogram","aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"date_histogram","schema":"segment","params":{"field":"timestamp","useNormalizedOpenSearchInterval":true,"interval":"auto","min_doc_count":1}}],"params":{"type":"histogram","grid":{"categoryLines":false},"categoryAxes":[{"id":"CategoryAxis-1","type":"category","position":"bottom","show":true,"labels":{"show":true,"truncate":100}}],"valueAxes":[{"id":"ValueAxis-1","name":"LeftAxis-1","type":"value","position":"left","show":true,"labels":{"show":true,"truncate":100}}],"seriesParams":[{"show":true,"type":"histogram","mode":"stacked","data":{"label":"Count","id":"1"},"valueAxis":"ValueAxis-1"}],"addTooltip":true,"addLegend":true,"legendPosition":"right","times":[],"addTimeMarker":false}}'
upsert_saved_object "visualization" "vis-requests-timeline" \
  "$(visualization_body "Requests over time" "$VIS_REQUESTS_TIMELINE")"

VIS_TOP_DOMAINS='{"title":"Top domains","type":"horizontal_bar","aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"terms","schema":"segment","params":{"field":"domain","size":10,"order":"desc","orderBy":"1"}}],"params":{"type":"histogram","grid":{"categoryLines":false},"categoryAxes":[{"id":"CategoryAxis-1","type":"category","position":"left","show":true,"labels":{"show":true,"truncate":100}}],"valueAxes":[{"id":"ValueAxis-1","name":"BottomAxis-1","type":"value","position":"bottom","show":true,"labels":{"show":true,"truncate":100}}],"seriesParams":[{"show":true,"type":"histogram","mode":"normal","data":{"label":"Count","id":"1"},"valueAxis":"ValueAxis-1"}],"addTooltip":true,"addLegend":true,"legendPosition":"right","times":[],"addTimeMarker":false}}'
upsert_saved_object "visualization" "vis-top-domains" \
  "$(visualization_body "Top domains" "$VIS_TOP_DOMAINS")"

VIS_CACHE_STATUS='{"title":"Cache status breakdown","type":"pie","aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"terms","schema":"segment","params":{"field":"cache_status","size":8,"order":"desc","orderBy":"1"}}],"params":{"type":"pie","addTooltip":true,"addLegend":true,"legendPosition":"right","isDonut":true,"labels":{"show":true,"values":true,"last_level":true,"truncate":100}}}'
upsert_saved_object "visualization" "vis-cache-status" \
  "$(visualization_body "Cache status breakdown" "$VIS_CACHE_STATUS")"

VIS_BLOCKED='{"title":"Blocked requests","type":"metric","aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}}],"params":{"addTooltip":true,"addLegend":false,"type":"metric","metric":{"colorMode":"None","useRanges":false,"style":{"bgFill":"#000","bgColor":false,"labelColor":false,"subText":""},"labels":{"show":true},"invertColors":false,"percentageMode":false}}}'
upsert_saved_object "visualization" "vis-blocked-requests" \
  "$(visualization_body "Blocked requests" "$VIS_BLOCKED" "acl_action:deny OR acl_action:redirect")"

VIS_THREAT_CATEGORIES='{"title":"Threat categories","type":"pie","aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"terms","schema":"segment","params":{"field":"categories","size":10,"order":"desc","orderBy":"1"}}],"params":{"type":"pie","addTooltip":true,"addLegend":true,"legendPosition":"right","isDonut":false,"labels":{"show":true,"values":true,"last_level":true,"truncate":100}}}'
upsert_saved_object "visualization" "vis-threat-categories" \
  "$(visualization_body "Threat categories" "$VIS_THREAT_CATEGORIES" "categories:*")"

echo "Creating dashboard..."
DASHBOARD_PAYLOAD='{"attributes":{"title":"BSDM HTTP Traffic","description":"Retro-search overview: volume, domains, cache and policy blocks","panelsJSON":"[{\"version\":\"3.7.0\",\"gridData\":{\"x\":0,\"y\":0,\"w\":24,\"h\":12,\"i\":\"1\"},\"panelIndex\":\"1\",\"embeddableConfig\":{\"enhancements\":{}},\"panelRefName\":\"panel_requests_timeline\"},{\"version\":\"3.7.0\",\"gridData\":{\"x\":24,\"y\":0,\"w\":12,\"h\":12,\"i\":\"2\"},\"panelIndex\":\"2\",\"embeddableConfig\":{\"enhancements\":{}},\"panelRefName\":\"panel_top_domains\"},{\"version\":\"3.7.0\",\"gridData\":{\"x\":36,\"y\":0,\"w\":12,\"h\":12,\"i\":\"3\"},\"panelIndex\":\"3\",\"embeddableConfig\":{\"enhancements\":{}},\"panelRefName\":\"panel_cache_status\"},{\"version\":\"3.7.0\",\"gridData\":{\"x\":0,\"y\":12,\"w\":12,\"h\":10,\"i\":\"4\"},\"panelIndex\":\"4\",\"embeddableConfig\":{\"enhancements\":{}},\"panelRefName\":\"panel_blocked_requests\"},{\"version\":\"3.7.0\",\"gridData\":{\"x\":12,\"y\":12,\"w\":36,\"h\":10,\"i\":\"5\"},\"panelIndex\":\"5\",\"embeddableConfig\":{\"enhancements\":{}},\"panelRefName\":\"panel_threat_categories\"}]","optionsJSON":"{\"hidePanelTitles\":false,\"useMargins\":true}","version":1,"timeRestore":true,"timeTo":"now","timeFrom":"now-30d","refreshInterval":{"pause":true,"value":0},"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"language\":\"kuery\",\"query\":\"\"},\"filter\":[]}"}},"references":[{"name":"panel_requests_timeline","type":"visualization","id":"vis-requests-timeline"},{"name":"panel_top_domains","type":"visualization","id":"vis-top-domains"},{"name":"panel_cache_status","type":"visualization","id":"vis-cache-status"},{"name":"panel_blocked_requests","type":"visualization","id":"vis-blocked-requests"},{"name":"panel_threat_categories","type":"visualization","id":"vis-threat-categories"}]}'
upsert_saved_object_with_refs "dashboard" "bsdm-http-traffic" "$DASHBOARD_PAYLOAD"

echo "OpenSearch Dashboards saved objects provisioned for index ${OPENSEARCH_INDEX}."
