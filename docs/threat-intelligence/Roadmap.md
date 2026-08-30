# Threat Intelligence Roadmap

> **Shadow Mode is the current default posture.** BSDM-Proxy performs threat
> *monitoring* from these feeds; direct automated blocking requires explicit
> operator configuration (`TI_ENFORCEMENT_MODE=enforce`) under the transition criteria in
> [ADR 0008](../adr/0008-threat-intel-shadow-mode.md).

## Phase 1 - MVP & Ingestion

- [x] Integrate public threat feeds (`threat-intel` collector: OpenPhish, PhishStats, Phishing.Database, URLhaus — TASK-TI-001)
- [x] Store IOC (structured SQLite persistence with WAL, migrations, indexes, and TTL expiration — TASK-TI-002)
- [x] Normalize domains, URLs and IP addresses (canonicalization, Punycode, bogon filter — TASK-TI-003)
- [x] Generate ACL lists (`threat_domains.json` JSON feed — TASK-TI-021). Consumed only by the proxy shadow matcher for observation; no ACL engine reads it in any mode

## Phase 2 - Scoring & RPZ artifact generation (enforcement gated by ADR 0008)

- [x] Weighted confidence scoring & multi-source correlation bonus with freshness decay (TASK-TI-010)
- [x] Automated DNS RPZ zone compilation (`threats.rpz`) with atomic rotation for `dns-sinkhole` (TASK-TI-020)
- [x] RPZ syntax validation and zone serial management (TASK-TI-020)
- [x] Compilation of RPZ/ACL artifacts to disk (TASK-TI-020 & 021)
- [x] Consumption of `threat_domains.json` by proxy policy / ACL data-plane engine under `TI_ENFORCEMENT_MODE=enforce` with Triple-Gate protection and Allowlist precedence (TASK-TI-021 / Phase 2)
- [x] Shadow Mode observation & false-positive evaluation (`threat_shadow_match`, `bsdm_proxy_ti_shadow_matches_total{feed}`) (ADR 0008)

## Phase 3 - Enterprise SIEM & SOAR

- [x] SIEM integration with CEF, ECS JSON, and Syslog RFC 5424 serialization (TASK-TI-030)
- [x] SOAR automated containment API (`/api/v1/soar/block`, `/api/v1/soar/unblock`, `/api/v1/soar/investigate` — TASK-TI-031)
- [x] Real-time REST endpoints on port 8093 (`/health`, `/metrics`, `/api/v1/soar/*`, `/api/v1/ml/*`)
- [ ] Multi-tenant support

## Phase 4 - Advanced Detection & ML

- [x] ML domain reputation & typosquatting / visual homoglyph engine (Damerau-Levenshtein, confusable mapping, keyword stacking — TASK-TI-040)
- [x] Multi-source feed reputation scoring & tag multipliers (TASK-TI-010)
- [x] End-to-end integration and lifecycle test suites (`threat-intel/tests/pipeline_test.rs`, `threat-intel/tests/soar_ml_test.rs`)

## Success Criteria

- [x] Automated IOC collection and deduplication
- [x] Mechanism for measuring the per-feed false-positive rate (`threat_shadow_match`, per-feed metric — ADR 0008)
- [ ] The measurement itself on real traffic (observation window per ADR 0008); not yet performed on any installation
- [ ] Reliable DNS RPZ blocking — requires an explicit `TI_ENFORCEMENT_MODE=enforce` under the ADR 0008 transition criteria; not enabled in the pilot
- [x] Proxy ACL blocking — implemented via `ti_enforce.rs` and gated by Triple-Gate fail-safe and Allowlist precedence
- [x] Auditable SIEM decisions and SOAR exceptions
- [x] Observational integration with BSDM Proxy (shadow matching, event field, per-feed metric)
