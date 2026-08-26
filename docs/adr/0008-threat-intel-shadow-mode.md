# ADR 0008: Threat Intelligence Shadow Mode before enforcement

- **Status**: Accepted
- **Date**: 2026-08-25
- **Deciders**: BSDM Core Security & Architecture Team
- **Issues**: #323, #330, #313
- **Relates**: [ADR 0004: DNS sinkhole sidecar](0004-dns-sinkhole-sidecar.md) · [threat-intel-collector.md](../features/threat-intel-collector.md) · [pilot-deployment.md](../getting-started/pilot-deployment.md)

## Context

The `threat-intel` crate collects public phishing/malware feeds (OpenPhish, PhishStats, Phishing.Database, URLhaus), normalizes them, stores them in SQLite with TTL, and scores them by source weight. That part is uncontroversial: it is metadata-only collection.

The enforcement path, however, landed **before** this decision was written down, and it is on by default:

1. `TI_RPZ_ENABLED` defaults to `true` (`threat-intel/src/config.rs:74`). On every collection cycle the collector compiles `threats.rpz` and `threat_domains.json` from feed content (`threat-intel/src/collector.rs:242-262`, `threat-intel/src/rpz.rs`).
2. `POST /api/v1/soar/block` inserts an indicator straight into the same IOC store with `soar_blocked` tags and returns `200` (`threat-intel/src/main.rs:218-240`, `threat-intel/src/soar.rs:49-92`), so a SOAR action reaches the same generated artifacts on the next cycle.
3. At the time of this decision the word *shadow* did not exist anywhere in the codebase: no shadow annotation on events, no per-feed match metric, and therefore **no data on which to judge the false-positive rate of these feeds** in our own traffic.
4. Only the last mile is manual: the compose stack points `dns-sinkhole` at the control-plane compiled zone (`DNS_SINKHOLE_ZONE_PATH=/var/lib/bsdm-proxy/rpz/compiled.rpz`, `docker-compose.yml:128,431`), while the collector writes `threats.rpz` into its own volume, and the proxy does not read `threat_domains.json` at all today. A single operator step — publishing the generated zone into the sinkhole path — turns unmoderated feed content into hard DNS blocking for the whole pilot.

Public phishing feeds carry URL-level indicators, shared hosters, URL shorteners and CDN hostnames. Promoting them to a domain-level block list without measuring hit quality first risks blocking legitimate business traffic during the pilot, which is precisely the failure mode the pilot cannot absorb.

## Decision

1. **Shadow Mode is the default posture.**
   - Introduce `TI_ENFORCEMENT_MODE` with values `shadow` (default) and `enforce`.
   - In `shadow`, no artifact that a data-plane component can consume unintentionally is produced: enforcement artifacts are either not written at all or written with a `.shadow` suffix that neither `dns-sinkhole` nor the proxy ACL loader will pick up.
   - `TI_RPZ_ENABLED=true` **without** an explicit `TI_ENFORCEMENT_MODE=enforce` yields shadow behaviour plus a warning in the log. Enforcement requires one explicit, auditable variable — never a combination of legacy flags.

2. **Shadow matches are observed, never acted on.**
   - When traffic matches an IOC while in shadow mode, the proxy annotates the outgoing event with a `threat_shadow_match` field carrying the reporting feed name, and it travels the normal Kafka → `cache-indexer` → ClickHouse pipeline alongside `decision_source`.
   - The allow/deny path is unchanged: the request is neither blocked nor delayed by the match. A shadow match is telemetry, not a policy decision.

3. **Per-feed observability.**
   - Prometheus counter `bsdm_proxy_ti_shadow_matches_total{feed}` counts shadow matches per feed, so feed quality can be compared feed by feed rather than in aggregate.
   - The SOC reviews candidates through the Search API over events carrying `threat_shadow_match`; no separate review UI is required for the pilot.

4. **SOAR containment is mode-aware.**
   - In shadow mode `POST /api/v1/soar/block` returns `202 Accepted` with a `shadow` marker instead of `200`, and the indicator is tagged `shadow` in the store so that it reaches the shadow export only. Flipping `TI_ENFORCEMENT_MODE` to `enforce` does **not** promote indicators accepted while shadow was in force — the enforcement export skips them, and promoting one takes a deliberate re-submission under `enforce`. The response must make it unambiguous to the calling playbook that nothing is being blocked.
   - `enforce` mode keeps the current `200` semantics.

5. **Documentation states the mode, not an aspiration.** README, `project-status.md` and the TI pages describe the feature as *threat monitoring in Shadow Mode (enforcement in development)*, without present-tense claims of protection or blocking.

## Transition criteria to enforcement

Enforcement (`TI_ENFORCEMENT_MODE=enforce`) may be enabled for an installation only when **all** of the following hold, and the evidence is attached to the pilot go/no-go record ([pilot-go-no-go-template.md](../ops-and-dev/pilot-go-no-go-template.md)):

1. **Volume of evidence**: at least 14 consecutive days of `threat_shadow_match` data collected on the target installation's real traffic, with no feed-collection gaps (`threat_intel_last_success_timestamp_seconds` staleness alert clean).
2. **False-positive rate**: SOC review of the shadow matches shows a false-positive share **below 1%** per feed; feeds above that threshold are excluded from the enforcement set via `TI_SOURCES` rather than enforced with exceptions.
3. **No business-critical hit**: no shadow match against a domain on the organisation's business-critical allowlist within the observation window; if there is one, the allowlist wins and the finding is documented.
4. **Rollback is proven**: reverting to `shadow` and restoring the previous DNS zone serial has been exercised on this installation ([RPZ_Deployment.md](../threat-intelligence/RPZ_Deployment.md) rollback section, [backup-restore.md](../ops-and-dev/backup-restore.md)).
5. **Named owner**: an accountable operator is named for the enforcement change, and the change has a scheduled review date.

Enforcement is enabled per feed set and per installation. Passing these criteria in one pilot does not authorise enforcement elsewhere.

## Operator procedure

**Verifying shadow mode (default, expected during the pilot):**

1. `TI_ENFORCEMENT_MODE` is unset or `shadow` in the environment of the `threat-intel` service.
2. The path referenced by `DNS_SINKHOLE_ZONE_PATH` is **not** a collector-generated `threats.rpz`, and no automation copies it there.
3. The proxy ACL configuration does not reference `TI_ACL_EXPORT_PATH` / `threat_domains.json`.
4. `bsdm_proxy_ti_shadow_matches_total` is present in `/metrics` on the proxy and grows with traffic; events carrying `threat_shadow_match` are searchable in ClickHouse.

**Enabling enforcement (only after the transition criteria are met):**

1. Record the evidence (shadow window, per-feed FP rate, reviewer) in the go/no-go record.
2. Set `TI_ENFORCEMENT_MODE=enforce` for the `threat-intel` service and restart it.
3. Publish the generated zone to the sinkhole path through the control-plane RPZ API, keeping the previous serial for rollback.
4. Watch deny volume and user reports for the first 24 hours with a named on-call operator.

**Rolling back:**

1. Set `TI_ENFORCEMENT_MODE=shadow` (or unset it) and restart `threat-intel`.
2. Restore the previous DNS zone serial ([RPZ_Deployment.md](../threat-intelligence/RPZ_Deployment.md)); the sinkhole falls back to the compiled zone it had before.
3. If the incident touched stored indicators, restore from the backup/restore runbook ([backup-restore.md](../ops-and-dev/backup-restore.md)).

## Implementation status

Implemented on this branch; the mode contract above is what the code does:

- `TI_ENFORCEMENT_MODE` parsing, the fail-safe fallback for any unrecognised value and the warning for `TI_RPZ_ENABLED=true` without `enforce`: `threat-intel/src/config.rs`.
- Artifacts under the enforcement names are written **only** in `enforce`; in shadow the collector writes `threats.rpz.shadow` and `threat_domains.json.shadow`, and the zone body carries a `SHADOW MODE … Do NOT load this zone into dns-sinkhole` banner: `threat-intel/src/collector.rs`, `threat-intel/src/rpz.rs`.
- SOAR block answers `202` with `"mode":"shadow"`, `"enforced":false` and is counted by `threat_intel_soar_blocks_total{mode}`: `threat-intel/src/soar.rs`, `threat-intel/src/main.rs`, `threat-intel/src/metrics.rs`. Indicators tagged `shadow` are excluded from the enforcement export: `threat-intel/src/storage.rs` (`list_active_domain_sources`), `threat-intel/src/collector.rs`.
- Mutating SOAR calls additionally require `Authorization: Bearer $TI_API_TOKEN` and are audited accepted-or-denied: `threat-intel/src/api_auth.rs` ([configuration.md](../ops-and-dev/configuration.md#adminsoar-api-коллектора-доступ-и-аудит)).
- `dns-sinkhole` refuses an observe-only artifact outright — by `.shadow` path suffix and by the `_bsdm-enforcement-mode IN TXT "shadow"` marker the collector writes into the zone; at boot this is a hard error rather than a fallback, so a mistaken `DNS_SINKHOLE_ZONE_PATH` cannot pass unnoticed: `threat-intel/src/rpz.rs`, `dns-sinkhole/src/zone.rs`, `dns-sinkhole/src/main.rs`.
- The control-plane RPZ API (`/api/dns/*`) is a separate path into the same zone and is **not** governed by `TI_ENFORCEMENT_MODE`; it is bounded instead by a mutation audit trail, `?dryRun=true` previews and a confirmation threshold on list size: `proxy/src/rpz_api.rs` ([control-plane-security.md](../ops-and-dev/control-plane-security.md)).
- The proxy-side matcher reads only the shadow export (`TI_SHADOW_MATCH_ENABLED`, `TI_SHADOW_FEED_PATH`, `TI_SHADOW_RELOAD_SECS`), annotates `threat_shadow_match` and counts `bsdm_proxy_ti_shadow_matches_total{feed}` without touching the allow/deny path: `proxy/src/ti_shadow.rs`, `proxy/src/metrics.rs`.
- The event field and its ClickHouse column: `bsdm-events/src/lib.rs`, `bsdm-events/src/clickhouse.rs`, `cache-indexer/src/clickhouse.rs`.

Operator-facing variables and metrics: [configuration.md](../ops-and-dev/configuration.md#threat-intel-shadow-matching-proxy) · [logging.md](../ops-and-dev/logging.md).

## Consequences

### Positive

- **Fail-safe by default**: no default configuration and no single legacy flag can turn unmoderated feed content into a block decision. Enforcement is an explicit, named act.
- **Decision based on measurement**: the false-positive question is answered with per-feed data from the installation's own traffic instead of vendor reputation.
- **Reversible**: switching back to shadow is one variable plus a zone serial restore, both exercised before enforcement is allowed.
- **Honest product surface**: documentation and UI describe monitoring, which is what the code does.

### Negative

- **No protection from TI during the observation window.** The feeds detect but do not block; other controls (ACL, categorization, DNS sinkhole lists, ML scoring) carry that load during the pilot.
- **Extra telemetry cost**: shadow matches add events to Kafka/ClickHouse and one more Prometheus series per feed.
- **Operational delay**: at least a two-week observation window separates deployment from any enforcement value.

### Neutral

- The collector, IOC store, scoring, SIEM export and `/api/v1/ml/reputation` are unaffected; only the artifacts that a data-plane component could consume, and the SOAR block semantics, are gated by the mode.
