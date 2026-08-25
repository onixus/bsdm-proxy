# Threat intelligence collector (TASK-TI-001)

> **Threat monitoring in Shadow Mode — enforcement is in development.** The
> feeds are observed, not enforced: `TI_ENFORCEMENT_MODE=shadow` is the default
> posture and blocking on feed content requires an explicit `enforce` decision
> under the transition criteria of
> [ADR 0008](../adr/0008-threat-intel-shadow-mode.md).

Optional `threat-intel` worker that pulls phishing/malware IOC feeds on a
schedule, parses them through per-source plugins, and writes a snapshot per feed
plus a run report. Beyond the collector framework from the
[TI backlog](../threat-intelligence/AI_Agent_Backlog.md), the crate also holds an
IOC store (SQLite with TTL, `TI_SQLITE_PATH`), normalization, weighted confidence
scoring, SIEM export, a SOAR API (`/api/v1/soar/*`) and a reputation endpoint
(`/api/v1/ml/reputation`).

It also **compiles enforcement artifacts** when `TI_RPZ_ENABLED` is on (default
`true`, `threat-intel/src/config.rs`): an RPZ zone `threats.rpz` and a Proxy ACL
list `threat_domains.json` (`threat-intel/src/collector.rs`,
`threat-intel/src/rpz.rs`). In shadow mode both are written under a `.shadow`
suffix (`threats.rpz.shadow`, `threat_domains.json.shadow`) that no enforcement
component loads, and `TI_RPZ_ENABLED=true` without an explicit
`TI_ENFORCEMENT_MODE=enforce` logs a warning.

Even in `enforce` these remain **files, not decisions**: `dns-sinkhole` loads the
zone named by `DNS_SINKHOLE_ZONE_PATH` (compose:
`/var/lib/bsdm-proxy/rpz/compiled.rpz`) and the proxy does not read
`threat_domains.json`, so nothing blocks until an operator deliberately publishes
the generated zone. Do not do that during a pilot — see ADR 0008.

Status: **Beta, monitoring only**. Treat the output as an input to a review
pipeline, not as a block list.

## Quick start

```bash
TI_RUN_ONCE=true TI_OUTPUT_DIR=./data/threat-intel cargo run -p threat-intel
ls ./data/threat-intel   # openphish.jsonl phishstats.jsonl ... report.json
```

Long-running (default) mode refreshes every source every
`TI_POLL_INTERVAL_SECS` and serves `/metrics` and `/health` on `METRICS_PORT`:

```bash
cargo run -p threat-intel
curl http://127.0.0.1:8093/health
curl http://127.0.0.1:8093/metrics | grep threat_intel_
```

Compose profile:

```bash
docker compose --profile threat-intel up -d --build threat-intel
```

Helm: `--set threatIntel.enabled=true` (see `charts/bsdm/values.yaml`).

## Sources

Each source is a plugin: an endpoint plus a parser. The framework owns fetching,
scheduling, retries, deduplication and metrics, so adding a feed means
implementing `FeedSource` in `threat-intel/src/sources/` and registering it in
`sources::build`.

| `TI_SOURCES` name | Feed | IOC kinds | Weight |
|---|---|---|---:|
| `openphish` | OpenPhish community feed | url | 90 |
| `phishstats` | PhishStats scored CSV | url, ip | 80 |
| `phishing_database` | Phishing.Database active domains | domain | 75 |
| `urlhaus` | URLhaus recent URLs (online only) | url | 70 |

Weights come from the [collector spec](../threat-intelligence/Threat_Intelligence_Collector_Agent.md)
and are carried on every indicator (`source_weight`) for the scoring engine.
Any endpoint can be overridden with `TI_<SOURCE>_URL`, which is also how the
collector is pointed at a local fixture in tests.

## Output

`TI_OUTPUT_DIR/<source>.jsonl` is a full snapshot of the last successful fetch —
one JSON object per line, replaced atomically on every cycle:

```json
{"value":"https://a.example/login","kind":"url","source":"openphish","source_weight":90,
 "collected_at":"2026-08-20T03:52:21Z","reported_at":null,"reference":null,"tags":[]}
```

`TI_OUTPUT_DIR/report.json` holds the latest result per source — status,
indicator count, attempts, duration and the last error, if any.

The exported `domains.txt` / `urls.txt` / `ips.txt` artifacts described in the
collector spec belong to the export stage (TASK-TI-020) and are not produced
here.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `TI_SOURCES` | `openphish,phishstats,phishing_database,urlhaus` | Enabled feeds, in collection order |
| `TI_<SOURCE>_URL` | vendor default | Per-source endpoint override |
| `TI_POLL_INTERVAL_SECS` | `900` | Refresh interval per source (floor 60) |
| `TI_HTTP_TIMEOUT_SECS` | `30` | Per-request timeout |
| `TI_MAX_ATTEMPTS` | `3` | Attempts per cycle, including the first |
| `TI_RETRY_BACKOFF_SECS` | `5` | Base of the exponential backoff (capped at 600s) |
| `TI_MAX_BODY_MB` | `64` | Hard cap on a feed response body |
| `TI_MAX_INDICATORS_PER_FETCH` | `500000` | Hard cap on indicators kept per fetch |
| `TI_OUTPUT_DIR` | `./data/threat-intel` | Snapshot directory |
| `TI_ENFORCEMENT_MODE` | `shadow` | `shadow` observes only; `enforce` is the explicit opt-in required by [ADR 0008](../adr/0008-threat-intel-shadow-mode.md) |
| `TI_SQLITE_PATH` | `<TI_OUTPUT_DIR>/ioc.db` | IOC store path (`TI_STORAGE_ENABLED`, `TI_IOC_TTL_SECS`) |
| `TI_RPZ_ENABLED` | `true` | Compile `threats.rpz` / `threat_domains.json`; in shadow mode they are written with a `.shadow` suffix |
| `TI_MIN_CONFIDENCE_SCORE` | `75` | Minimum weighted score for an indicator to reach the artifacts |
| `TI_USER_AGENT` | `bsdm-threat-intel/<version>` | Feed request User-Agent |
| `TI_RUN_ONCE` | `false` | Collect every source once and exit |
| `METRICS_PORT` | `8093` | `/metrics` and `/health` |

Packaged example: `packaging/config/threat-intel.env.example`.

## Error handling

Each source runs in its own scheduled task, so a slow or broken feed never
delays the others. Within a cycle, transport errors, `429` and `5xx` are retried
with exponential backoff up to `TI_MAX_ATTEMPTS`; `4xx`, parse errors, oversized
bodies and empty feeds fail the cycle immediately, since retrying them would
fail the same way. A failed cycle keeps the previous snapshot on disk and is
recorded in `report.json` and in the metrics; the next tick retries the feed.

`TI_RUN_ONCE=true` exits non-zero if any source failed, which makes it usable as
a cron job or a CI smoke check.

## Metrics

| Metric | Labels | Meaning |
|---|---|---|
| `threat_intel_fetches_total` | `source`, `result` | Cycles by outcome (`ok`, `http_error`, `parse_error`, `transport_error`, `too_large`, `empty`) |
| `threat_intel_retries_total` | `source` | Retried attempts |
| `threat_intel_indicators_total` | `source`, `kind` | Indicators accepted |
| `threat_intel_indicators_dropped_total` | `source`, `reason` | Dropped as `duplicate` or `over_cap` |
| `threat_intel_last_batch_indicators` | `source` | Size of the latest snapshot |
| `threat_intel_last_success_timestamp_seconds` | `source` | Unix time of the last success — alert on staleness |
| `threat_intel_fetch_duration_seconds` | `source` | Cycle duration histogram |
| `threat_intel_sink_errors_total` | `source` | Snapshot write failures |
| `threat_intel_soar_blocks_total` | `mode` | SOAR block actions by enforcement mode (`shadow`, `enforce`) |
| `ti_shadow_matches_total` | `feed` | **Proxy-side, per [ADR 0008](../adr/0008-threat-intel-shadow-mode.md)**: traffic matches against an IOC while in shadow mode, emitted together with the `threat_shadow_match` event; the request is **not** blocked. This is the false-positive review input for the go/no-go record |

## Shadow Mode review flow

1. Keep `TI_ENFORCEMENT_MODE` unset or `shadow` (default) and confirm the
   artifacts on disk carry the `.shadow` suffix.
2. Let the collector run for at least the observation window in
   [ADR 0008](../adr/0008-threat-intel-shadow-mode.md) (≥ 14 days).
3. Review `threat_shadow_match` events per feed through the Search API and
   compare volumes with `ti_shadow_matches_total{feed}`.
4. Record the per-feed false-positive share in the
   [go/no-go record](../ops-and-dev/pilot-go-no-go-template.md). Feeds above the
   threshold are dropped from `TI_SOURCES` rather than enforced with exceptions.
5. `POST /api/v1/soar/block` answers `202` with `"mode": "shadow"` and
   `"enforced": false` while in shadow mode — a playbook must treat that as
   "recorded", not "contained".

## Security

Processing is metadata-only by construction: the collector issues `GET` requests
against the configured feed endpoints and never requests a collected indicator,
so it does not visit phishing pages or download payloads. Response bodies are
capped (`TI_MAX_BODY_MB`) before buffering, redirects are limited, and non-HTTP
feed URLs are rejected.

The container runs as a non-root user and needs egress to the feed vendors. In
an air-gapped deployment, mirror the feeds internally and point `TI_<SOURCE>_URL`
at the mirror.
