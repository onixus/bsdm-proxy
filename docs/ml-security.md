# M5 — ML security

Async threat scoring on ClickHouse. Design: [ADR 0003](adr/0003-ml-worker-feature-store.md) · Roadmap: [M5](roadmap.md#m5--ml-security-v10x).

> Proxy hot path stays free of ML inference. Rule alerts remain in [`alert-worker`](alerting.md).

## Architecture

```
bsdm.http_cache ──► ml-worker ──► bsdm.entity_features
                      │
                      ├──► bsdm.ml_scores
                      └──► optional webhook (same JSON shape as alert-worker)
```

| Component | Role |
|-----------|------|
| `ml-worker` | Poll CH, extract features, score, optional SIEM POST |
| `entity_features` | Per-entity window aggregates |
| `ml_scores` | Model / stub scores + severity |
| `alert-worker` | Unchanged rule engine (M4) |

## Quick start

```bash
# Apply DDL (also mounted in docker-compose)
clickhouse-client --multiquery < scripts/clickhouse/ml_features.sql

# Local binary
CLICKHOUSE_URL=http://127.0.0.1:8123 \
  ML_ENTITY_TYPES=client_ip \
  METRICS_PORT=8091 \
  cargo run -p ml-worker --release

# Compose profile
docker compose --profile ml up -d --build ml-worker
```

Optional webhook (fires when stub score ≥ threshold):

```bash
ML_WEBHOOK_URL=https://hooks.example/siem \
  ML_SCORE_THRESHOLD=0.7 \
  docker compose --profile ml up -d ml-worker
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
| `ML_LOOKBACK_SECS` | `300` | Window length |
| `ML_ENTITY_TYPES` | `client_ip` | Comma list: `client_ip`, `username`, `domain` |
| `ML_MIN_REQUESTS` | `10` | Min events per entity window |
| `ML_MODEL` | `anomaly_stub_v0` | Score model id |
| `ML_SCORE_THRESHOLD` | `0.8` | Webhook / severity cut |
| `ML_WEBHOOK_URL` | — | Optional SIEM URL |
| `METRICS_PORT` | `8091` | `/health`, `/metrics` |

## Models

| Model | Phase | Behaviour |
|-------|-------|-----------|
| `anomaly_stub_v0` | M5.1 | Heuristic: elevated request rate + deny/threat ratio |
| *(planned)* UEBA / isolation | M5.2 | Unsupervised anomaly on feature windows |
| *(planned)* lexical phishing | M5.3 | Domain/URL features + weak labels |
| *(planned)* C&C ML | M5.4 | Augment `beacon_periodic` with gap/volume model |

## Verify

```bash
curl http://127.0.0.1:8091/health
clickhouse-client -q "SELECT count() FROM bsdm.entity_features"
clickhouse-client -q "SELECT entity_id, score, severity FROM bsdm.ml_scores ORDER BY scored_at DESC LIMIT 10"
```

## Phases

Epic: [#165](https://github.com/onixus/bsdm-proxy/issues/165) · [roadmap](roadmap.md#m5--ml-security-v10x)

| Phase | Issue |
|-------|-------|
| M5.1 scaffold | this tree / ADR 0003 |
| M5.2 anomaly / UEBA | [#166](https://github.com/onixus/bsdm-proxy/issues/166) |
| M5.3 phishing lexical | [#167](https://github.com/onixus/bsdm-proxy/issues/167) |
| M5.4 C&C ML | [#168](https://github.com/onixus/bsdm-proxy/issues/168) |
| M5.5 score write-back | [#169](https://github.com/onixus/bsdm-proxy/issues/169) |
