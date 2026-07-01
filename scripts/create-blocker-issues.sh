#!/usr/bin/env bash
# Create GitHub issues for architecture blockers B1–B25.
# Requires: gh auth with issues write scope
# Usage: ./scripts/create-blocker-issues.sh [--dry-run]
set -euo pipefail

REPO="${GITHUB_REPO:-onixus/bsdm-proxy}"
DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

create_issue() {
  local id="$1"
  local title="$2"
  local _labels="$3"
  local body="$4"

  if $DRY_RUN; then
    echo "[dry-run] #$id: $title"
    return 0
  fi

  # Skip if issue with same title prefix already exists
  if gh issue list --repo "$REPO" --search "in:title B${id}:" --json title --jq '.[].title' 2>/dev/null | grep -q "B${id}:"; then
    echo "Skip B${id}: already exists"
    return 0
  fi

  gh issue create --repo "$REPO" \
    --title "B${id}: ${title}" \
    --body "$body" \
    && echo "Created B${id}" \
    || echo "Failed B${id}"
}

DOC="docs/architecture.md"

# --- Critical M1 ---
create_issue 1 "Wire hierarchy modules into binary" "pillar:squid,milestone:m1" "$(cat <<EOF
## Blocker B1 — Critical

**Milestone:** M1 Foundation
**Pillar:** Squid parity

### Problem
\`peers.rs\`, \`icp.rs\`, \`hierarchy.rs\`, \`selection.rs\` exist but are not declared in \`lib.rs\` or \`main.rs\` — not compiled into the proxy binary.

### Files
- \`proxy/src/lib.rs\`
- \`proxy/src/peers.rs\`, \`icp.rs\`, \`hierarchy.rs\`, \`selection.rs\`

### Resolution
Add \`mod\` declarations, export types, ensure \`cargo test --workspace\` includes hierarchy unit tests.

### References
- [$DOC]($DOC#-critical--m1-foundation)
- [docs/roadmap.md](docs/roadmap.md)
EOF
)"

create_issue 2 "Add rand dependency for WeightedStrategy" "pillar:squid,milestone:m1" "$(cat <<EOF
## Blocker B2 — Critical

**Milestone:** M1 Foundation

### Problem
\`selection.rs\` uses \`rand::random()\` in \`WeightedStrategy\` but \`rand\` is not in \`proxy/Cargo.toml\`. Wiring hierarchy (B1) will break the build.

### Files
- \`proxy/src/selection.rs:84\`
- \`proxy/Cargo.toml\`

### Resolution
Add \`rand = "0.8"\` (or replace with \`std\` hasher-based selection).

### References
- [$DOC]($DOC#-critical--m1-foundation)
EOF
)"

create_issue 3 "Implement HTTP fetch from hierarchy peer" "pillar:squid,milestone:m1" "$(cat <<EOF
## Blocker B3 — Critical

**Milestone:** M1 Foundation

### Problem
\`HierarchyManager::resolve_source()\` returns \`SiblingHit\` / \`ParentHit\` after ICP query, but there is no HTTP proxy fetch from the selected peer. Integration cannot work without this.

### Files
- \`proxy/src/hierarchy.rs\`
- \`proxy/src/main.rs\` (request path)

### Resolution
After \`ParentHit\`/\`SiblingHit\`, forward request to peer via HTTP proxy client; on miss, fall back to origin.

### References
- [$DOC]($DOC#-critical--m1-foundation)
EOF
)"

create_issue 4 "Start ICP server in proxy runtime" "pillar:squid,milestone:m1" "$(cat <<EOF
## Blocker B4 — Critical

**Milestone:** M1 Foundation

### Problem
\`IcpServer\` is implemented in \`icp.rs\` but never started in \`main.rs\`. Sibling caches cannot query this node.

### Files
- \`proxy/src/icp.rs\`
- \`proxy/src/main.rs\`

### Resolution
Spawn \`IcpServer\` when \`HIERARCHY_ENABLED=true\`; respond based on L1 cache presence.

### References
- [$DOC]($DOC#-critical--m1-foundation)
EOF
)"

create_issue 5 "Make ca.key optional when MITM disabled" "pillar:squid,milestone:m1" "$(cat <<EOF
## Blocker B5 — Critical

**Milestone:** M1 Foundation

### Problem
Proxy fails to start if \`/certs/ca.key\` is missing (\`?\` on read), even when \`MITM_ENABLED=false\`.

### Files
- \`proxy/src/main.rs:858-861\`

### Resolution
Only require CA key/cert when MITM is enabled; allow plain CONNECT tunnel mode without certs.

### References
- [$DOC]($DOC#-critical--m1-foundation)
EOF
)"

create_issue 6 "Implement rate limiting per user/IP" "pillar:squid,milestone:m1" "$(cat <<EOF
## Blocker B6 — Critical

**Milestone:** M1 Foundation

### Problem
Rate limiting is on the roadmap but not implemented. Required for production proxy deployments.

### Resolution
Token bucket or sliding window per client IP and authenticated user; configurable via env; Prometheus metrics.

### References
- [$DOC]($DOC#-critical--m1-foundation)
- [docs/roadmap.md](docs/roadmap.md)
EOF
)"

# --- High M2/M3 ---
create_issue 7 "Refactor ProxyService out of main.rs monolith" "pillar:squid,milestone:m2" "$(cat <<EOF
## Blocker B7 — High

**Milestone:** M2 Squid parity (starts in M1)

### Problem
\`ProxyService\`, cache, Kafka, and HTTP server logic live in \`main.rs\` (~1300 lines). Blocks clean integration of hierarchy, L2, and rate limiting.

### Resolution
Extract \`proxy\`, \`cache\`, \`pipeline\` modules into \`lib.rs\`; keep \`main.rs\` as thin entrypoint.

### References
- [$DOC]($DOC#-high--m2-squid-parity--m3-retro-search)
EOF
)"

create_issue 8 "Move online categorization off hot request path" "pillar:squid,milestone:m2" "$(cat <<EOF
## Blocker B8 — High

**Milestone:** M2 Squid parity

### Problem
\`check_policy()\` calls URLhaus/PhishTank HTTP APIs synchronously before ACL on uncached URLs — adds latency and external dependency.

### Files
- \`proxy/src/main.rs\` — \`check_policy\`
- \`proxy/src/categorization.rs\`

### Resolution
Local DB first; online checks async with timeout/circuit breaker, or background enrichment to OpenSearch.

### References
- [$DOC]($DOC#-high--m2-squid-parity--m3-retro-search)
EOF
)"

create_issue 9 "Replace ACL global Mutex with concurrent structure" "pillar:squid,milestone:m2" "$(cat <<EOF
## Blocker B9 — High

**Milestone:** M2 Squid parity

### Problem
\`acl_engine.lock().await\` on every request serializes ACL evaluation under load.

### Files
- \`proxy/src/policy_config.rs\`
- \`proxy/src/main.rs\`

### Resolution
\`RwLock\` for reads + atomic rule swap on reload, or lock-free rule snapshot.

### References
- [$DOC]($DOC#-high--m2-squid-parity--m3-retro-search)
EOF
)"

create_issue 10 "Kafka reliable delivery: env topic and acks" "pillar:retro-search,milestone:m3" "$(cat <<EOF
## Blocker B10 — High

**Milestone:** M3 Retro-search

### Problem
Kafka producer uses \`acks=0\` (fire-and-forget) and hardcoded topic \`"cache-events"\`. Events can be lost — breaks retro-search reliability.

### Files
- \`proxy/src/main.rs:154-165, 363\`

### Resolution
\`KAFKA_TOPIC\` env var; \`acks=1\` minimum; metric for delivery failures.

### References
- [$DOC]($DOC#-high--m2-squid-parity--m3-retro-search)
EOF
)"

create_issue 11 "Indexer: add categories field to CacheEvent" "pillar:retro-search,milestone:m3" "$(cat <<EOF
## Blocker B11 — High

**Milestone:** M3 Retro-search

### Problem
Proxy sends \`categories\` in Kafka events; \`cache-indexer\` struct omits the field — threat tags are dropped.

### Files
- \`proxy/src/main.rs\` — \`CacheEvent\`
- \`cache-indexer/src/main.rs\` — \`CacheEvent\`

### Resolution
Add \`categories: Vec<String>\` to indexer; update OpenSearch mapping.

### References
- [$DOC]($DOC#-high--m2-squid-parity--m3-retro-search)
EOF
)"

create_issue 12 "Shared bsdm-events crate for event schema" "pillar:retro-search,milestone:m3" "$(cat <<EOF
## Blocker B12 — High

**Milestone:** M3 Retro-search

### Problem
\`CacheEvent\` is duplicated in proxy and cache-indexer without a shared contract — causes schema drift (B11).

### Resolution
Create workspace crate \`bsdm-events\` with versioned schema; used by proxy, indexer, future analytics worker.

### References
- [$DOC]($DOC#-high--m2-squid-parity--m3-retro-search)
EOF
)"

create_issue 13 "Implement NTLM authentication" "pillar:squid,milestone:m2" "$(cat <<EOF
## Blocker B13 — High

**Milestone:** M2 Squid parity

### Problem
\`AuthBackend::Ntlm\` returns \`"NTLM not implemented yet"\` but docs/README list NTLM as supported.

### Files
- \`proxy/src/auth.rs:231\`

### Resolution
Implement NTLM challenge/response or remove from roadmap and docs.

### References
- [$DOC]($DOC#-high--m2-squid-parity--m3-retro-search)
EOF
)"

create_issue 14 "Complete ACL TimeWindow and group rules" "pillar:squid,milestone:m2" "$(cat <<EOF
## Blocker B14 — High

**Milestone:** M2 Squid parity

### Problem
- \`TimeWindow\` rule type always returns \`true\` (TODO in \`acl.rs:225\`)
- \`Principal::Group\` is ignored — only username checked

### Files
- \`proxy/src/acl.rs\`

### Resolution
Implement time parsing (cron or HH:MM); wire LDAP group membership to ACL.

### References
- [$DOC]($DOC#-high--m2-squid-parity--m3-retro-search)
EOF
)"

# --- Medium M4/M5 ---
create_issue 15 "Design analytics/ML worker service" "pillar:ml-security,milestone:m4" "$(cat <<EOF
## Blocker B15 — Medium

**Milestone:** M4–M5

### Problem
No separate service for aggregations, threat scoring, ML inference, or alerting. Proxy and indexer alone cannot deliver ML security.

### Resolution
New crate or sidecar: reads OpenSearch/Kafka, computes features, writes scores/alerts back.

### References
- [$DOC]($DOC#-medium--m4-threat--m5-ml)
- [docs/roadmap.md](docs/roadmap.md) — M4, M5
EOF
)"

create_issue 16 "Extend event schema for threat analytics" "pillar:ml-security,milestone:m4" "$(cat <<EOF
## Blocker B16 — Medium

**Milestone:** M4 Threat analytics

### Problem
Events lack \`session_id\`, \`acl_action\`, \`threat_score\`, \`threat_sources\` — insufficient for UEBA and ML features.

### Resolution
Extend \`bsdm-events\` schema (depends on B12); index in OpenSearch with proper mappings.

### References
- [$DOC]($DOC#-medium--m4-threat--m5-ml)
EOF
)"

create_issue 17 "Add OpenSearch Dashboards to docker-compose" "pillar:retro-search,milestone:m3" "$(cat <<EOF
## Blocker B17 — Medium

**Milestone:** M3 Retro-search

### Problem
OpenSearch runs in compose but Dashboards are not provisioned — no UI for retro-search.

### Files
- \`docker-compose.yml\`

### Resolution
Add \`opensearch-dashboards\` service; provision saved searches for user/domain/threat queries.

### References
- [$DOC]($DOC#-medium--m4-threat--m5-ml)
EOF
)"

create_issue 18 "Behavioral threat signals beyond URL blocklists" "pillar:ml-security,milestone:m4" "$(cat <<EOF
## Blocker B18 — Medium

**Milestone:** M4–M5

### Problem
Threat detection is URL list-based only (UT1 Blacklists, OTX). No DNS, timing, volume, or beacon analysis for C&C.

### Resolution
M4: rule-based heuristics; M5: ML models on behavioral features.

### References
- [$DOC]($DOC#-medium--m4-threat--m5-ml)
EOF
)"

create_issue 19 "Alerting pipeline to SIEM/webhook" "pillar:ml-security,milestone:m4" "$(cat <<EOF
## Blocker B19 — Medium

**Milestone:** M4 Threat analytics

### Problem
No automated alerts on threat patterns — only real-time ACL deny in proxy.

### Resolution
OpenSearch Alerting or custom worker → webhook/email/SIEM integration.

### References
- [$DOC]($DOC#-medium--m4-threat--m5-ml)
EOF
)"

create_issue 20 "Security analytics dashboards on historical data" "pillar:retro-search,milestone:m3" "$(cat <<EOF
## Blocker B20 — Medium

**Milestone:** M3–M4

### Problem
Grafana dashboard covers Prometheus real-time metrics only — not historical threat analytics from OpenSearch.

### Resolution
OpenSearch Dashboards or Grafana OpenSearch datasource for threat/top-blocked/beacon views.

### References
- [$DOC]($DOC#-medium--m4-threat--m5-ml)
EOF
)"

# --- Structural ---
create_issue 21 "Use Cargo feature flags in main binary" "pillar:squid,milestone:m2" "$(cat <<EOF
## Blocker B21 — Structural

**Milestone:** M2

### Problem
\`Cargo.toml\` defines \`auth-ldap\`, \`categorization\` features but \`main.rs\` always compiles all modules unconditionally.

### Resolution
Gate optional backends behind features; reduce binary size and attack surface.

### References
- [$DOC]($DOC#-structural--технический-долг)
EOF
)"

create_issue 22 "Implement cache refresh and negative caching" "pillar:squid,milestone:m2" "$(cat <<EOF
## Blocker B22 — Structural

**Milestone:** M2 Squid parity

### Problem
No Squid-style negative caching or Cache-Control revalidation — only TTL-based L1.

### Resolution
Honor \`Cache-Control\`, \`ETag\`, \`If-Modified-Since\`; negative cache for 404/403.

### References
- [$DOC]($DOC#-structural--технический-долг)
EOF
)"

create_issue 23 "HTTP/2 upstream client" "pillar:squid,milestone:m2" "$(cat <<EOF
## Blocker B23 — Structural

**Milestone:** M2 (v0.3.x roadmap)

### Problem
Upstream connector enables HTTP/1 only (\`enable_http1()\`).

### Files
- \`proxy/src/main.rs\` — \`build_upstream_https_connector\`

### Resolution
Enable HTTP/2 in hyper-rustls connector.

### References
- [$DOC]($DOC#-structural--технический-долг)
EOF
)"

create_issue 24 "Fix docker-compose healthcheck curl vs wget" "pillar:squid,milestone:m1" "$(cat <<EOF
## Blocker B24 — Structural

**Milestone:** M1

### Problem
\`docker-compose.yml\` proxy healthcheck uses \`curl\`; Alpine proxy image has \`wget\` only.

### Files
- \`docker-compose.yml\`
- \`Dockerfile\`

### Resolution
Align healthcheck command with image tooling.

### References
- [$DOC]($DOC#-structural--технический-долг)
EOF
)"

create_issue 25 "Implement or remove documented REST ACL API" "pillar:squid,milestone:m2" "$(cat <<EOF
## Blocker B25 — Structural

**Milestone:** M2

### Problem
\`docs/acl.md\` documents \`/api/acl/*\` REST endpoints; metrics server only exposes \`/health\`, \`/ready\`, \`/metrics\`.

### Resolution
Implement ACL management API or remove from documentation.

### References
- [$DOC]($DOC#-structural--технический-долг)
- [docs/acl.md](docs/acl.md)
EOF
)"

echo "Done. Issues: gh issue list --repo $REPO --search 'in:title B'"
