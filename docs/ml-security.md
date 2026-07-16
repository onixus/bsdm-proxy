# M5 — ML security

Async threat scoring on ClickHouse. Design: [ADR 0003](adr/0003-ml-worker-feature-store.md) · Roadmap: [M5](roadmap.md#m5--ml-security-v10x).

> Proxy hot path stays free of ML inference. Rule alerts remain in [`alert-worker`](alerting.md).

## Architecture

```
bsdm.http_cache ──► ml-worker ──► bsdm.entity_features
                      │                 │
                      │                 └── population baseline (mean/std)
                      ├──► bsdm.ml_scores (ueba_zscore_v0 / stub)
                      └──► optional webhook
```

| Component | Role |
|-----------|------|
| `ml-worker` | Poll CH, extract features, score, optional SIEM POST |
| `entity_features` | Per-entity window aggregates |
| Population baseline | Live CH stats or `ML_BASELINE_PATH` JSON artifact |
| `ml_scores` | Model scores + severity |
| `alert-worker` | Unchanged rule engine (M4) |

## Quick start

```bash
# Apply DDL (also mounted in docker-compose)
clickhouse-client --multiquery < scripts/clickhouse/ml_features.sql

# Default model = ueba_zscore_v0 (falls back to stub until enough history)
CLICKHOUSE_URL=http://127.0.0.1:8123 \
  ML_ENTITY_TYPES=client_ip \
  METRICS_PORT=8091 \
  cargo run -p ml-worker --release

docker compose --profile ml up -d --build ml-worker
```

### Offline baseline artifact (optional)

```bash
# After some feature history exists:
python3 scripts/ml/export_baseline.py -o /tmp/bsdm-baseline.json
ML_BASELINE_PATH=/tmp/bsdm-baseline.json ML_MODEL=ueba_zscore_v0 \
  cargo run -p ml-worker --release
```

### Compare stub vs UEBA

```bash
# Run once with each model (or inspect mixed history):
python3 scripts/ml/compare_stub_vs_ueba.py
```

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `CLICKHOUSE_URL` | `http://127.0.0.1:8123` | CH HTTP |
| `CLICKHOUSE_DATABASE` | `bsdm` | Database |
| `CLICKHOUSE_TABLE` | `http_cache` | Source events |
| `ML_FEATURES_TABLE` | `entity_features` | Feature store |
| `ML_SCORES_TABLE` | `ml_scores` | Score store |
| `ML_POLL_INTERVAL_SECS` | `120` | Cycle interval |
| `ML_LOOKBACK_SECS` | `300` | Feature window length |
| `ML_ENTITY_TYPES` | `client_ip` | `client_ip`, `username`, `domain` |
| `ML_MIN_REQUESTS` | `10` | Min events per entity window |
| `ML_MODEL` | `ueba_zscore_v0` | `ueba_zscore_v0` or `anomaly_stub_v0` |
| `ML_SCORE_THRESHOLD` | `0.8` | Webhook / severity cut |
| `ML_BASELINE_LOOKBACK_SECS` | `86400` | History for population stats |
| `ML_BASELINE_MIN_SAMPLES` | `30` | Min windows per entity_type |
| `ML_ZSCORE_CLIP` | `4.0` | Clip \|z\| before \[0,1\] map |
| `ML_BASELINE_PATH` | — | JSON artifact (`export_baseline.py`) |
| `ML_WEBHOOK_URL` | — | Optional SIEM URL |
| `METRICS_PORT` | `8091` | `/health`, `/metrics` |

## Models

| Model | Phase | Behaviour |
|-------|-------|-----------|
| `anomaly_stub_v0` | M5.1 | Heuristic rate/deny/threat mix; also **fallback** when baseline empty |
| `ueba_zscore_v0` | **M5.2** | Unsupervised mean abs-z vs population baseline |
| *(planned)* lexical phishing | M5.3 | Domain/URL features + weak labels |
| *(planned)* C&C ML | M5.4 | Augment `beacon_periodic` |

### UEBA scoring

For each feature \(x\) with baseline \((\mu, \sigma)\):

\[
z = (x - \mu) / \max(\sigma, \varepsilon),\quad
c = \min(|z|, z_{clip}) / z_{clip},\quad
score = 0.4\cdot\mathrm{mean}(c) + 0.6\cdot\max(c)
\]

Features: request_count, unique_domains/urls, deny/threat counts & ratios, avg size/duration, gap_cv, max_domain_len.

## Grafana

Panel **Top anomalous entities (UEBA z-score / ml-worker)** on [BSDM HTTP Traffic (ClickHouse)](../grafana/dashboards/bsdm-http-traffic-ch.json).  
Ad-hoc SQL: [`scripts/clickhouse/m5_ueba_queries.sql`](../scripts/clickhouse/m5_ueba_queries.sql).

## Verify

```bash
curl http://127.0.0.1:8091/health
clickhouse-client -q "SELECT count() FROM bsdm.entity_features"
clickhouse-client -q "SELECT entity_id, score, model, severity FROM bsdm.ml_scores ORDER BY scored_at DESC LIMIT 10"
```

## Phases

Epic: [#165](https://github.com/onixus/bsdm-proxy/issues/165) · [roadmap](roadmap.md#m5--ml-security-v10x)

| Phase | Issue |
|-------|-------|
| M5.1 scaffold | ADR 0003 / #170 |
| M5.2 anomaly / UEBA | [#166](https://github.com/onixus/bsdm-proxy/issues/166) |
| M5.3 phishing lexical | [#167](https://github.com/onixus/bsdm-proxy/issues/167) |
| M5.4 C&C ML | [#168](https://github.com/onixus/bsdm-proxy/issues/168) |
| M5.5 score write-back | [#169](https://github.com/onixus/bsdm-proxy/issues/169) |
