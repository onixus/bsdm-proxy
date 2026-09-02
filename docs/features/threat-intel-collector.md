# Threat intelligence collector & pipeline (TASK-TI-001..040)

> **Threat monitoring in Shadow Mode — enforcement is in development.** The
> feeds are observed, not enforced: `TI_ENFORCEMENT_MODE=shadow` is the default
> posture and blocking on feed content requires an explicit `enforce` decision
> under the transition criteria of
> [ADR 0008](../adr/0008-threat-intel-shadow-mode.md).

The `threat-intel` worker ingests phishing/malware IOC feeds on a schedule,
normalizes and scores indicators, persists them into SQLite with TTL management (`TI_SQLITE_PATH`),
and compiles DNS RPZ zones (`threats.rpz`) with standard `YYYYMMDDNN` monotonic BIND serials, `.bak` zone backups,
and atomic rollback (`rollback_rpz_zone`). It also exports Proxy ACL feeds (`threat_domains.json`) to disk.
In the default shadow mode those artifacts are written with a `.shadow` suffix that no
data-plane component loads. It exposes enterprise SIEM formatting (CEF/ECS/Syslog) with unified network and file
delivery transports (`SyslogTransport` UDP/TCP, `FileSiemTransport`, `SiemDispatcher`),
a SOAR API (`/api/v1/soar/*`) which in shadow mode records indicators for observation only
(`202`, `enforced:false`), and ML domain reputation, typosquatting/homoglyph detection,
phishing campaign clustering (`/api/v1/ml/cluster`), and algorithmic anomaly detection (`/api/v1/ml/anomaly`).


It also **compiles enforcement artifacts** when `TI_RPZ_ENABLED` is on (default
`true`, `threat-intel/src/config.rs`): an RPZ zone `threats.rpz` and a Proxy ACL
list `threat_domains.json` (`threat-intel/src/collector.rs`,
`threat-intel/src/rpz.rs`). In shadow mode both are written under a `.shadow`
suffix (`threats.rpz.shadow`, `threat_domains.json.shadow`) that no enforcement
component loads, and `TI_RPZ_ENABLED=true` without an explicit
`TI_ENFORCEMENT_MODE=enforce` logs a warning.

In `enforce` mode, the proxy data-plane loads `threat_domains.json` via `ti_enforce.rs` and applies real-time `Deny` decisions with Triple-Gate protection and Allowlist precedence (`AclAction::Allow` rules always take priority over external feeds). In `shadow` mode, `ti_shadow.rs` observes traffic matches, emits `threat_shadow_match` annotations, and collects per-feed metrics without blocking. `dns-sinkhole` loads the zone named by `DNS_SINKHOLE_ZONE_PATH` (compose: `/var/lib/bsdm-proxy/rpz/compiled.rpz`).

Status: **Beta, monitoring/shadow mode by default**. Direct automated blocking requires explicit `TI_ENFORCEMENT_MODE=enforce` and completion of transition criteria per ADR 0008.

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

A plain binary run binds `127.0.0.1` (`TI_ADMIN_BIND`). Under Compose the port
is published on `127.0.0.1:8093` and in Helm it is an internal service.

Prometheus scrapes both the collector (`threat_intel_*`) and the proxy
(`bsdm_proxy_ti_*`). The provisioned Grafana dashboard **BSDM Threat
Intelligence (Shadow)** (`grafana/dashboards/bsdm-threat-intel-shadow.json`,
uid `bsdm-threat-intel-shadow`) shows the enforcement posture of collector and
proxy, shadow matches per feed, feed freshness and a ClickHouse table of
shadow-matched hosts (`threat_shadow_match`) for false-positive review. The
matching alert rules live in `prometheus/alerts/ti_shadow.yml`.

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
| `TI_OUTPUT_DIR` | `./data/threat-intel` | Snapshot and artifact output directory |
| `TI_USER_AGENT` | `bsdm-threat-intel/<version>` | Feed request User-Agent |
| `TI_RUN_ONCE` | `false` | Collect every source once and exit |
| `TI_ENFORCEMENT_MODE` | `shadow` | `shadow` writes `.shadow` files; `enforce` compiles live targets. Any unrecognised value falls back to `shadow`. The suffix is a convention on the producer side: `dns-sinkhole` loads whatever `DNS_SINKHOLE_ZONE_PATH` points at, including a `.shadow` file |
| `TI_RPZ_ENABLED` | `true` | Compile `threats.rpz` and `threat_domains.json` |
| `TI_API_TOKEN` | unset | `Authorization: Bearer` token for mutating `POST /api/v1/soar/*`; unset means those endpoints are disabled in the production profile (fail-closed) |
| `TI_API_ALLOW_INSECURE` | `false` | Lab-only override that leaves mutating endpoints open without a token; never set it on a pilot network |
| `TI_SOAR_AUDIT_PATH` | `<TI_OUTPUT_DIR>/soar-audit.jsonl` | Audit trail of SOAR mutations |
| `TI_ADMIN_BIND` | `127.0.0.1` | Bind host for the HTTP admin/metrics listener |
| `METRICS_PORT` | `8093` | `/metrics`, `/health`, SOAR and ML endpoints |
| `TI_SIEM_SYSLOG_ADDR` | unset | Syslog destination endpoint (e.g. `127.0.0.1:514`) |
| `TI_SIEM_SYSLOG_PROTOCOL` | `udp` | Syslog transport protocol (`udp` or `tcp`) |
| `TI_SIEM_FILE_PATH` | unset | Local file path for formatted SIEM event append log |
| `TI_SIEM_FORMAT` | `cef` | SIEM serialization format (`cef`, `ecs`, or `syslog`) |

Packaged example: `packaging/config/threat-intel.env.example`.


## Error handling

Each source runs in its own scheduled task, so a slow or broken feed never
delays the others. Within a cycle, transport errors, `429` and `5xx` are retried
with exponential backoff up to `TI_MAX_ATTEMPTS`; `4xx`, parse errors, oversized
bodies and empty feeds fail the cycle immediately, since retrying them would
fail the same way. A failed cycle keeps the previous snapshot on disk and is
recorded in `report.json` and in the metrics; the next tick retries the feed.
