# Pilot go / no-go decision record (template)

Decision template for the **end of pilot week 4** (issue [#332](https://github.com/onixus/bsdm-proxy/issues/332)).
Copy this file, fill every "Actual" cell with a measured value and a link to the
evidence, and keep the completed record next to the pilot artifacts.

This is a *decision record*, not a status report: every criterion ends in
**pass / fail**, and the outcome follows from the table, not from the mood in the
room. Empty or "not measured" cells count as **fail**.

**Related:** [Pilot deployment](../getting-started/pilot-deployment.md) ·
[Hybrid load test](load-test-selective-mitm.md) ·
[Load-test results](load-test-results/README.md) ·
[Backup & restore](backup-restore.md) ·
[CA lifecycle](ca-lifecycle.md) ·
[ADR 0007: MITM circuit breaker](../adr/0007-mitm-circuit-breaker.md) ·
[ADR 0008: TI Shadow Mode](../adr/0008-threat-intel-shadow-mode.md) ·
[Project status](../project-status.md)

---

## 1. Header

| Field | Value |
|---|---|
| Installation / site | |
| Pilot window (UTC) | `YYYY-MM-DD` → `YYYY-MM-DD` |
| Build / version | `proxy/Cargo.toml` version + commit |
| Profile | `deploy/compose/docker-compose.pilot.yml`, `POLICY_MODE=selective-mitm` |
| Users in scope | |
| Decision date | |
| Decision | ☐ go ☐ go-with-conditions ☐ no-go |

Scope reminder: the Day-1 component matrix in
[pilot-deployment.md](../getting-started/pilot-deployment.md) defines what was in
scope. Anything marked **OFF** there is not evaluated here and must not be used
as an argument for or against go.

---

## 2. Criteria

Thresholds below are **defaults to be confirmed per site** before the pilot
starts — latency budgets are site-specific
([load-test-selective-mitm.md](load-test-selective-mitm.md)). Agree on them in
week 1 and freeze them; renegotiating a threshold in week 4 invalidates the
record.

### 2.1 Performance (issue #326)

Source: `./scripts/run-hybrid-load-test.sh` report in
[`load-test-results/`](load-test-results/README.md) (snapshot [`20260830T210000Z.md`](load-test-results/20260830T210000Z.md) / [`latest.md`](load-test-results/latest.md)), 100 users, 60 s.

| Metric | Threshold | Actual | Verdict |
|---|---|---|---|
| Added latency p95 (ms), cached/HIT path | ≤ agreed SLO (≤ 10 ms) | 4.8 ms (L1 HIT ~1.2 ms, blended 4.8 ms) | pass |
| Added latency p99 (ms), selective-MITM path | ≤ agreed SLO (≤ 50 ms) | 8.9 ms | pass |
| Error rate under load probe | < 0.5% | 0.21% (38 err / 18,412 ok) | pass |
| Sustained proxy RPS at target concurrency | ≥ pilot load model (≥ 50–100 RPS) | 307.5 RPS (100 users) | pass |
| `decision_source` mix matches policy intent (`sni` / `mitm` / `local-agent` / `pinning-bypass`) | no unexplained skew | 80.0% SNI / 15.0% MITM / 5.0% DNS (0 pinning bypass) | pass |
| CPU proxy under peak | < 70% for > 15 min → resize trigger | 22.4% peak (4 vCPU allocated) | pass |
| Host RAM / swap | < 80%, no swap | 28.7% RAM (~6.8 GiB / 24 GiB), 0 B swap | pass |

### 2.2 Operational drills (issue #329)

Source: `./scripts/drill-backup-restore.sh` and [pilot-drills-runbook.md](pilot-drills-runbook.md).

| Drill | Threshold | Actual | Verdict |
|---|---|---|---|
| MITM CA rotation ([ca-lifecycle.md](ca-lifecycle.md)) | completed, no client breakage outside the window | completed in 1.63 s, SHA-256 rotated, dual-trust verified | pass |
| CA restore / rollback ([backup-restore.md](backup-restore.md)) | restored and verified | restored in 3.06 s, exact original SHA-256 matched (`fp3 == fp1`) | pass |
| ClickHouse backup + restore | row counts verified after restore | Native table dump + restore verified with `RESTORE_TRUNCATE=1` (`count=1`) | pass |
| CA private key permissions on the pilot host | `0600`, owner-only, off shared storage | verified `0600` on disk; runtime check active in `proxy/src/tls.rs` | pass |
| Time-to-restore measured | ≤ agreed RTO (≤ 1 h proxy / ≤ 4 h analytics) | measured ~3.06 s (CA) / ~1.2 s per table (ClickHouse) | pass |

### 2.3 Incidents during the pilot

| Metric | Threshold | Actual | Verdict |
|---|---|---|---|
| P1 incidents (user-visible outage caused by the proxy) | 0 | | |
| P2 incidents | ≤ agreed count, all with root cause | | |
| Open incidents without a root cause at decision time | 0 | | |
| Unplanned availability loss | ≤ agreed budget | | |

List every incident with date, impact, root cause and fix status in section 6.

### 2.4 Threat Intelligence false positives (shadow)

TI runs in **Shadow Mode** during the pilot — it observes and does not block
([ADR 0008](../adr/0008-threat-intel-shadow-mode.md)). The purpose of this block
is to decide whether enforcement may ever be considered, **not** to gate the
pilot on blocking quality.

| Metric | Threshold | Actual | Verdict |
|---|---|---|---|
| Shadow observation window | ≥ 14 consecutive days | | |
| Feed collection staleness (`threat_intel_last_success_timestamp_seconds`) | no gap beyond one poll interval | | |
| `bsdm_proxy_ti_shadow_matches_total{feed}` reviewed per feed | every feed reviewed | | |
| False-positive share per feed (SOC review of `threat_shadow_match`) | < 1% | | |
| Shadow matches against business-critical allowlist | 0 | | |
| Enforcement flag state | `TI_ENFORCEMENT_MODE` unset or `shadow` | | |

A failing row here is **not** by itself a no-go: it means enforcement stays off
and the transition criteria in ADR 0008 are not met.

### 2.5 MITM circuit breaker stability (issue #328, ADR 0007)

| Metric | Threshold | Actual | Verdict |
|---|---|---|---|
| Breaker trips during the pilot | all attributable to a known pinned domain | | |
| Domains permanently bypassed (`decision_source: "pinning-bypass"`) | ≤ agreed list, all documented | | |
| Share of traffic on bypass | ≤ agreed % | | |
| Audit trail (`PINNING_AUDIT_LOG_PATH`) complete for trips/resets | yes | | |
| Operator reset via Control API exercised | yes | | |
| Unauthenticated mutation attempts rejected | yes ([control-plane-security.md](control-plane-security.md)) | | |

### 2.6 Control plane and scope hygiene

| Check | Threshold | Actual | Verdict |
|---|---|---|---|
| `CONTROL_API_ALLOW_INSECURE=false`, `:9090` not publicly reachable | yes | | |
| All tokens set and rotated per policy | yes | | |
| Out-of-scope profiles (ICAP, WASM, eBPF, agent fleet, AmneziaWG) stayed off | yes | | |
| Retention as agreed (ClickHouse TTL, Kafka) | yes | | |

---

## 3. Outcomes

Exactly one applies.

### go

All criteria in 2.1–2.3, 2.5 and 2.6 pass. Section 2.4 may be incomplete —
that only keeps TI in shadow. Proceed to the next phase with the same Day-1
scope; scope expansion is a separate decision with its own record.

### go-with-conditions

No failure in 2.1–2.3 or 2.5 that affects availability or data integrity, but
open items remain. Each condition must be recorded with an **owner**, a
**deadline** and a **verification method**; the pilot continues under the
existing scope until all conditions are closed. Conditions without an owner and
a date are not conditions — they are a no-go.

| # | Condition | Owner | Deadline | Verification |
|---|---|---|---|---|
| 1 | | | | |

### no-go

Any of: a P1 incident without a closed root cause; performance outside the
agreed SLO with no identified fix; a failed CA rotation or restore drill; loss
of analytics data integrity; control-plane exposure. The pilot stops taking
production-like traffic and the rollback procedure runs.

---

## 4. Rollback on no-go

Do not improvise. Use the existing runbooks in this order:

1. **Remove users from the proxy path.** Revert the client/PAC/DHCP change that
   points endpoints at `:3128` and the DNS change that points resolvers at the
   sinkhole (`:5353`); confirm direct egress works.
2. **Stop enforcement components** before touching data: proxy, then
   `dns-sinkhole`. TI needs no action if it stayed in shadow
   ([ADR 0008](../adr/0008-threat-intel-shadow-mode.md) rollback section);
   if enforcement was ever enabled, set `TI_ENFORCEMENT_MODE=shadow` and restore
   the previous zone serial.
3. **CA**: if the incident involved TLS interception or a rotation, follow
   *Restore / rollback after failed rotation* in
   [backup-restore.md](backup-restore.md) and, for compromise, the emergency
   revocation checklist in [ca-lifecycle.md](ca-lifecycle.md). Remove the pilot
   CA from client trust stores as part of the rollback.
4. **Analytics**: restore ClickHouse from the latest verified dump per
   [backup-restore.md](backup-restore.md); record row counts before and after.
5. **Preserve evidence**: keep the load-test reports, `PINNING_AUDIT_LOG_PATH`,
   proxy logs and the incident timeline before recycling the host — the retry
   depends on them.
6. **Record the outcome**: file the completed record, the root cause and the
   entry conditions for a second attempt.

---

## 5. Roles and sign-off

Sign-off means each signer read the filled table and accepts the outcome in
their area. A missing signature blocks **go** and **go-with-conditions**.

| Role | Responsibility in this decision | Name | Date | Signature |
|---|---|---|---|---|
| Pilot owner / product | Owns the outcome and the conditions list | | | |
| Operations / DevOps lead | Sections 2.1, 2.2, 2.6 — measurements and drills | | | |
| Security lead / SOC | Sections 2.4, 2.5, 2.6 — TI review, bypass list, control plane | | | |
| Network / infrastructure | Client path, DNS, rollback feasibility | | | |
| Service owner of affected business apps | Impact and incident record | | | |

---

## 6. Evidence and appendices
 
| Item | Link / location |
|---|---|
| Load-test report(s) | [`load-test-results/latest.md`](load-test-results/latest.md) ([`20260830T210000Z.md`](load-test-results/20260830T210000Z.md)) |
| Drill logs (CA, backup/restore) | [`docs/ops-and-dev/pilot-drills-runbook.md`](pilot-drills-runbook.md) |
| Incident list with root causes | |
| SOC shadow-match review | Search query over `threat_shadow_match` |
| Circuit breaker audit log excerpt | `PINNING_AUDIT_LOG_PATH` |
| Grafana snapshots | |
