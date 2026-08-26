# Threat Intelligence Roadmap

## Phase 1 - MVP & Ingestion

- [x] Integrate public threat feeds (`threat-intel` collector: OpenPhish, PhishStats, Phishing.Database, URLhaus — TASK-TI-001)
- [x] Store IOC (structured SQLite persistence with WAL, migrations, indexes, and TTL expiration — TASK-TI-002)
- [x] Normalize domains, URLs and IP addresses (canonicalization, Punycode, bogon filter — TASK-TI-003)
- [x] Generate ACL lists (`threat_domains.json` JSON feed for proxy data-plane policies — TASK-TI-021)

## Phase 2 - Scoring & RPZ Enforcement

- [x] Weighted confidence scoring & multi-source correlation bonus with freshness decay (TASK-TI-010)
- [x] Automated DNS RPZ zone compilation (`threats.rpz`) with atomic rotation for `dns-sinkhole` (TASK-TI-020)
- [x] RPZ syntax validation and zone serial management (TASK-TI-020)
- [x] Proxy ACL and DNS blocklist integration (TASK-TI-020 & 021)

## Phase 3 - Enterprise SIEM & SOAR

- [x] SIEM integration with CEF, ECS JSON, and Syslog RFC 5424 serialization (TASK-TI-030)
- [x] SOAR automated containment API (`/api/v1/soar/block`, `/api/v1/soar/unblock`, `/api/v1/soar/investigate` — TASK-TI-031)
- [x] Real-time REST endpoints on port 8093 (`/health`, `/metrics`, `/api/v1/soar/*`, `/api/v1/ml/*`)

## Phase 4 - Advanced Detection & ML

- [x] ML domain reputation & typosquatting / visual homoglyph engine (Damerau-Levenshtein, confusable mapping, keyword stacking — TASK-TI-040)
- [x] Multi-source feed reputation scoring & tag multipliers (TASK-TI-010)
- [x] End-to-end integration and lifecycle test suites (`threat-intel/tests/pipeline_test.rs`, `threat-intel/tests/soar_ml_test.rs`)

## Success Criteria

- [x] Automated IOC collection and deduplication
- [x] Reliable DNS RPZ and Proxy ACL blocking
- [x] Auditable SIEM decisions and SOAR exceptions
- [x] Integration with BSDM Proxy security controls
