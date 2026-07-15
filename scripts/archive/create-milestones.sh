#!/usr/bin/env bash
# ARCHIVED — do not re-run. See scripts/archive/README.md
# Create GitHub milestones for BSDM-Proxy roadmap.
# Requires: gh auth with repo admin scope
# Usage: ./scripts/create-milestones.sh
set -euo pipefail

REPO="${GITHUB_REPO:-onixus/bsdm-proxy}"

create_milestone() {
  local title="$1"
  local description="$2"
  gh api "repos/${REPO}/milestones" \
    --method POST \
    -f "title=${title}" \
    -f "description=${description}" \
    -f "state=open" \
    && echo "Created: ${title}" \
    || echo "Skip or failed: ${title} (may already exist)"
}

create_milestone "M1: Foundation (v0.2.x)" \
  "Proxy core, ACL, categorization, observability, rate limiting, hierarchy Phase 3. docs/roadmap.md"

create_milestone "M2: Squid parity (v0.3.x)" \
  "Cache hierarchy Phase 4, Redis L2, HTTP/2, compression, full ACL, NTLM. docs/roadmap.md"

create_milestone "M3: Retro-search (v0.4.x)" \
  "ClickHouse analytics, Search API, Grafana. docs/roadmap.md"

create_milestone "M4: Threat analytics (v0.5.x)" \
  "Rule-based anomaly alerts, C&C heuristics, threat enrichment, SIEM export. docs/roadmap.md"

create_milestone "M5: ML security (v1.0.x)" \
  "ML anomaly detection, phishing ML, C&C beacon detection, feedback loop. docs/roadmap.md"

echo "Done. List: gh api repos/${REPO}/milestones"
