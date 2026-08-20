# Threat intelligence collector (TASK-TI-001)

Optional `threat-intel` worker that pulls phishing/malware IOC feeds on a
schedule, parses them through per-source plugins, and writes a snapshot per feed
plus a run report. This is the collector framework from the
[TI backlog](../threat-intelligence/AI_Agent_Backlog.md): the IOC database
(TASK-TI-002), full normalization (TASK-TI-003) and confidence scoring
(TASK-TI-010) are **not** part of it, and nothing here is wired into ACL or RPZ
enforcement yet.

Status: **Experimental**. Treat the output as an input to a review pipeline, not
as a block list.

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

## Security

Processing is metadata-only by construction: the collector issues `GET` requests
against the configured feed endpoints and never requests a collected indicator,
so it does not visit phishing pages or download payloads. Response bodies are
capped (`TI_MAX_BODY_MB`) before buffering, redirects are limited, and non-HTTP
feed URLs are rejected.

The container runs as a non-root user and needs egress to the feed vendors. In
an air-gapped deployment, mirror the feeds internally and point `TI_<SOURCE>_URL`
at the mirror.
