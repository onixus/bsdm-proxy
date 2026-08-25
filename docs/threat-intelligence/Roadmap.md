# Threat Intelligence Roadmap

> **Shadow Mode is the current posture.** BSDM-Proxy performs threat
> *monitoring* from these feeds; enforcement is in development and is off by
> default (`TI_ENFORCEMENT_MODE=shadow`). Everything described below as blocking
> or enforcement is the target design and may only be enabled per installation
> under the transition criteria in
> [ADR 0008](../adr/0008-threat-intel-shadow-mode.md).

## Phase 1 - MVP

- [x] Integrate public threat feeds (`threat-intel` collector: OpenPhish, PhishStats, Phishing.Database, URLhaus)
- [x] Store IOC (SQLite persistence with TTL, `threat-intel/src/storage.rs`)
- [x] Normalize domains and URLs (`threat-intel/src/normalizer.rs`)
- [x] Generate ACL lists (`threat_domains.json`, `threat-intel/src/rpz.rs` — file export, not wired into the proxy)

## Phase 2 - RPZ Enforcement

- [x] RPZ generation (`threats.rpz`, `threat-intel/src/rpz.rs`)
- [ ] DNS integration — **gated**: the generated zone is not published to `dns-sinkhole` by default (ADR 0008)
- [ ] Policy validation — shadow observation (`threat_shadow_match`, `bsdm_proxy_ti_shadow_matches_total{feed}`) is the validation input
- [ ] Rollback — zone-serial rollback drill required before enforcement

## Phase 3 - Enterprise

- [x] SIEM integration (CEF/ECS/Syslog, `threat-intel/src/siem.rs`)
- [x] SOAR automation (`/api/v1/soar/*`, `threat-intel/src/soar.rs`) — mode-aware per ADR 0008
- [x] API service (`/metrics`, `/health`, SOAR and `/api/v1/ml/reputation` on `METRICS_PORT`)
- [ ] Multi-tenant support

## Phase 4 - Advanced Detection

- [ ] Reputation enrichment
- [ ] ML scoring
- [ ] Automated false positive handling
- [ ] Threat hunting workflows

## Success Criteria

- Automated IOC collection
- Measured false-positive rate per feed before any blocking (ADR 0008)
- Reliable blocking, only after the shadow transition criteria are met
- Auditable decisions
- Integration with BSDM Proxy security controls

