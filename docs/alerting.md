# Alert worker (B19 / #50)

Polls ClickHouse `bsdm.http_cache`, evaluates rule-based findings, and POSTs
SIEM-friendly JSON to a webhook. Part of M4 threat analytics.

## Quick start

```bash
# Optional: echo receiver
python3 scripts/alert-worker/webhook-echo.py 9080 &

export ALERT_WEBHOOK_URL=http://127.0.0.1:9080/hooks/siem
export CLICKHOUSE_URL=http://127.0.0.1:8123
cargo run -p alert-worker
```

Compose profile (stack already up):

```bash
ALERT_WEBHOOK_URL=https://siem.example/hooks/bsdm \
  docker compose --profile alerts up -d --build alert-worker
```

## Payload (v1)

```json
{
  "version": 1,
  "source": "bsdm-proxy-alert-worker",
  "alert_id": "uuid",
  "rule": "blocked_burst",
  "severity": "critical",
  "title": "ACL deny burst",
  "description": "...",
  "fired_at": "2026-07-15T12:00:00+00:00",
  "window_secs": 300,
  "value": 15,
  "labels": { "username": "alice", "client_ip": "10.0.0.1" },
  "fingerprint": "sha256-hex"
}
```

Identical fingerprints are suppressed for `ALERT_DEDUPE_TTL_SECS` (default 1h).

## Built-in rules

| Rule | Severity | Default threshold |
|------|----------|-------------------|
| `blocked_burst` | critical | ≥10 deny/`DENY` per user+IP in lookback |
| `domain_burst` | warning | ≥50 requests per client+domain |
| `off_hours_threat` | warning | ≥1 threat-tagged event 22:00–06:00 UTC |
| `high_entropy_domain` | warning | ≥5 hits on long/numeric domains |
| `beacon_periodic` | warning | ≥5 regular gaps (CV≤0.25) client→domain over beacon lookback |

Enable a subset: `ALERT_RULES=blocked_burst,beacon_periodic`.

Starter SQL live in [`scripts/clickhouse/m4_threat_queries.sql`](../scripts/clickhouse/m4_threat_queries.sql).

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `ALERT_WEBHOOK_URL` | **required** | Destination URL |
| `ALERT_WEBHOOK_HEADERS` | `{}` | Extra headers JSON, e.g. `{"Authorization":"Bearer …"}` |
| `ALERT_WEBHOOK_TIMEOUT_SECS` | `10` | HTTP timeout |
| `ALERT_POLL_INTERVAL_SECS` | `60` | Eval cycle period |
| `ALERT_LOOKBACK_SECS` | `300` | Query window (most rules) |
| `ALERT_DEDUPE_TTL_SECS` | `3600` | Fingerprint cooldown |
| `ALERT_RULES` | all five | Comma-separated rule ids |
| `ALERT_BLOCKED_BURST_THRESHOLD` | `10` | |
| `ALERT_DOMAIN_BURST_THRESHOLD` | `50` | |
| `ALERT_HIGH_ENTROPY_MIN_REQUESTS` | `5` | |
| `ALERT_OFF_HOURS_MIN_EVENTS` | `1` | |
| `ALERT_BEACON_LOOKBACK_SECS` | `3600` | Beacon rule window (independent) |
| `ALERT_BEACON_MIN_HITS` | `5` | Min inter-request gaps matching interval band |
| `ALERT_BEACON_MIN_INTERVAL_SECS` | `45` | Min gap seconds |
| `ALERT_BEACON_MAX_INTERVAL_SECS` | `900` | Max gap seconds |
| `ALERT_BEACON_MAX_GAP_CV` | `0.25` | Max coeff. of variation of gaps |
| `ALERT_SOURCE` | `bsdm-proxy-alert-worker` | Payload `source` |
| `CLICKHOUSE_URL` | `http://127.0.0.1:8123` | |
| `CLICKHOUSE_DATABASE` / `TABLE` | `bsdm` / `http_cache` | |
| `CLICKHOUSE_USER` / `PASSWORD` | — | Optional basic auth |
| `METRICS_PORT` | `8090` | `/metrics`, `/health` |

## Metrics

- `alert_worker_evaluations_total`
- `alert_worker_findings_total{rule}`
- `alert_worker_webhook_sent_total`
- `alert_worker_webhook_errors_total`
- `alert_worker_dedupe_suppressed_total`
- `alert_worker_clickhouse_errors_total`

Prometheus scrape (when profile enabled): job `alert-worker` → `:8090`.

## Related

- Blocker B19 / issue [#50](https://github.com/onixus/bsdm-proxy/issues/50)
- [clickhouse-analytics.md](clickhouse-analytics.md) · [roadmap.md](roadmap.md) M4
