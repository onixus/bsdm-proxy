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
| `high_entropy_domain` | warning | ≥5 hits on long domains; Shannon and/or legacy digit heuristic |
| `beacon_periodic` | warning | ≥5 regular gaps (CV≤0.25) client→domain over beacon lookback |

Enable a subset: `ALERT_RULES=blocked_burst,beacon_periodic`.

### High-entropy / Shannon (`high_entropy_domain`)

1. ClickHouse prefilter: `length(domain) >= ALERT_HIGH_ENTROPY_MIN_DOMAIN_LEN` and hit count.
2. Worker post-filter on the **leftmost DNS label**:
   - **Shannon** — entropy ≥ `ALERT_SHANNON_MIN_BITS` and label length ≥ `ALERT_SHANNON_MIN_LABEL_LEN`
   - **Legacy** — domain length ≥ `ALERT_HIGH_ENTROPY_LEGACY_MIN_DOMAIN_LEN` and a run of ≥4 digits
   - Mode `ALERT_HIGH_ENTROPY_MODE`: `shannon` | `legacy` | `either` (default)

Alerts include labels `shannon_bits` and `entropy_match` (`shannon` / `legacy` / `shannon+legacy`).

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
| `ALERT_HIGH_ENTROPY_MIN_REQUESTS` | `5` | Min hits per domain in lookback |
| `ALERT_HIGH_ENTROPY_MIN_DOMAIN_LEN` | `16` | SQL prefilter: min full domain length |
| `ALERT_SHANNON_MIN_LABEL_LEN` | `12` | Min leftmost-label length for Shannon |
| `ALERT_SHANNON_MIN_BITS` | `3.5` | Min Shannon entropy (bits/char) on leftmost label |
| `ALERT_HIGH_ENTROPY_MODE` | `either` | `shannon` \| `legacy` \| `either` |
| `ALERT_HIGH_ENTROPY_LEGACY_MIN_DOMAIN_LEN` | `25` | Legacy length+digit-run min domain length |
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

## Grafana Unified Alerting + Alertmanager

Full stack includes **Alertmanager** (`:9093`) and provisioned Grafana rules
under [`grafana/alerting/`](../grafana/alerting/). Prometheus loads
[`prometheus/alerts/m4_threat.yml`](../prometheus/alerts/m4_threat.yml).

```
alert-worker ──webhook──▶ SIEM          (profile alerts, rich CH findings)
Prometheus rules ──▶ Alertmanager ──webhook──▶ SIEM   (ALERT_WEBHOOK_URL)
Grafana Unified Alerting ──▶ Alertmanager ──┘
```

```bash
# SIEM URL used by Alertmanager (and alert-worker when profile alerts is on)
ALERT_WEBHOOK_URL=https://siem.example/hooks/bsdm docker compose up -d

# Inspect
open http://localhost:3000/alerting/list   # Grafana folder "BSDM M4"
open http://localhost:9093                 # Alertmanager
open http://localhost:9091/alerts          # Prometheus rule evaluation
```

Without `ALERT_WEBHOOK_URL`, Alertmanager still receives alerts but does not
forward them (empty webhook receiver). Grafana Alerting UI still shows firing state.

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
- [clickhouse-analytics.md](clickhouse-analytics.md) · [roadmap.md](roadmap.md) M4 ✅
- Grafana provisioning: `grafana/alerting/` · Prometheus rules: `prometheus/alerts/`
- Alertmanager: `alertmanager/` (compose service)