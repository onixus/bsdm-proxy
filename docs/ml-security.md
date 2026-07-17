# M5 — ML security

Async threat scoring on ClickHouse. Design: [ADR 0003](adr/0003-ml-worker-feature-store.md) · Roadmap: [M5](roadmap.md#m5--ml-security-v10x).

> Proxy hot path stays free of ML inference. Rule alerts remain in [`alert-worker`](alerting.md).

## Architecture

```
bsdm.http_cache ──► ml-worker ──► bsdm.entity_features
                      │                 │
                      │                 └── population baseline (mean/std)
                      ├──► bsdm.ml_scores (ueba_zscore_v0 / stub)
                      ├──► bsdm.threat_score_cache + GET /api/threat-scores (M5.5)
                      └──► optional webhook
```

Proxy (opt-in `THREAT_SCORE_ENABLED=true`) polls `/api/threat-scores` in background; request path does O(1) memory lookup only.

| Component | Role |
|-----------|------|
| `ml-worker` | Poll CH, extract features, score, optional SIEM POST |
| `entity_features` | Per-entity window aggregates |
| Population baseline | Live CH stats or `ML_BASELINE_PATH` JSON artifact |
| `ml_scores` | Model scores + severity |
| `threat_score_cache` | M5.5 write-back rows for proxy poll |
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
| `ML_MODEL` | `ueba_zscore_v0` | `ueba_zscore_v0`, `anomaly_stub_v0`, `phishing_lexical_v0`, or `cc_beacon_v0` |
| `ML_PHISHING_FEATURES_TABLE` | `domain_phishing_features` | M5.3 domain feature store |
| `ML_BEACON_FEATURES_TABLE` | `beacon_pair_features` | M5.4 client→domain feature store |
| `ML_BEACON_LOOKBACK_SECS` | `3600` | Beacon window (aligns with `ALERT_BEACON_LOOKBACK_SECS`) |
| `ML_BEACON_MIN_HITS` | `5` | Min regular gaps (aligns with alert-worker) |
| `ML_BEACON_MIN_INTERVAL_SECS` | `45` | Min gap between requests |
| `ML_BEACON_MAX_INTERVAL_SECS` | `900` | Max gap between requests |
| `ML_BEACON_MAX_GAP_CV` | `0.25` | Max coefficient of variation for periodic beacon |
| `ML_SCORE_THRESHOLD` | `0.8` | Webhook / severity cut |
| `ML_BASELINE_LOOKBACK_SECS` | `86400` | History for population stats |
| `ML_BASELINE_MIN_SAMPLES` | `30` | Min windows per entity_type |
| `ML_ZSCORE_CLIP` | `4.0` | Clip \|z\| before \[0,1\] map |
| `ML_BASELINE_PATH` | — | JSON artifact (`export_baseline.py`) |
| `ML_WEBHOOK_URL` | — | Optional SIEM URL |
| `ML_SCORE_CACHE_TABLE` | `threat_score_cache` | M5.5 write-back table |
| `ML_WRITEBACK_ENABLED` | `true` | Publish to cache + `/api/threat-scores` |
| `ML_WRITEBACK_MIN_SCORE` | `0.5` | Min score to write back |
| `ML_WRITEBACK_TTL_SECS` | `3600` | Row expiry in CH + snapshot |
| `METRICS_PORT` | `8091` | `/health`, `/metrics`, `/api/threat-scores` |

## Models

| Model | Phase | Behaviour |
|-------|-------|-----------|
| `anomaly_stub_v0` | M5.1 | Heuristic rate/deny/threat mix; also **fallback** when baseline empty |
| `ueba_zscore_v0` | **M5.2** | Unsupervised mean abs-z vs population baseline |
| `phishing_lexical_v0` | **M5.3** | Domain lexical heuristics + PhishTank / UT1 weak labels |
| `cc_beacon_v0` | **M5.4** | C&C beacon scoring augmenting `beacon_periodic` |

## M5.5 threat score write-back

After each scoring cycle, `ml-worker` publishes scores ≥ `ML_WRITEBACK_MIN_SCORE` to ClickHouse `threat_score_cache` and refreshes an in-memory snapshot at `GET /api/threat-scores`.

Proxy opt-in (default off):

| Variable | Default | Description |
|----------|---------|-------------|
| `THREAT_SCORE_ENABLED` | `false` | Enable background poll + hot-path lookup |
| `THREAT_SCORE_POLL_URL` | `http://127.0.0.1:8091/api/threat-scores` | ml-worker snapshot URL |
| `THREAT_SCORE_POLL_INTERVAL_SECS` | `60` | Background poll interval |
| `THREAT_SCORE_CACHE_TTL_SECS` | `300` | Local cache entry TTL |
| `THREAT_SCORE_WARN_THRESHOLD` | `0.7` | Adds `ml_score` to `threat_sources` |
| `THREAT_SCORE_BLOCK_THRESHOLD` | `0` | Block when score ≥ threshold (`0` = enrich only) |

Lookup keys: `domain`, `client_ip`, `client_domain` (`{ip}|{domain}`). Highest matching score wins.

```bash
curl http://127.0.0.1:8091/api/threat-scores
# Enable on proxy:
THREAT_SCORE_ENABLED=true THREAT_SCORE_POLL_URL=http://127.0.0.1:8091/api/threat-scores \
  cargo run -p bsdm-proxy --bin proxy
```

Ad-hoc SQL: [`scripts/clickhouse/m5_writeback_queries.sql`](../scripts/clickhouse/m5_writeback_queries.sql).

### UEBA scoring

For each feature \(x\) with baseline \((\mu, \sigma)\):

\[
z = (x - \mu) / \max(\sigma, \varepsilon),\quad
c = \min(|z|, z_{clip}) / z_{clip},\quad
score = 0.4\cdot\mathrm{mean}(c) + 0.6\cdot\max(c)
\]

Features: request_count, unique_domains/urls, deny/threat counts & ratios, avg size/duration, gap_cv, max_domain_len.

### Phishing lexical scoring (M5.3)

Set `ML_MODEL=phishing_lexical_v0` (scores `domain` entities from `http_cache`):

```bash
CLICKHOUSE_URL=http://127.0.0.1:8123 \
  ML_MODEL=phishing_lexical_v0 \
  ML_MIN_REQUESTS=5 \
  METRICS_PORT=8091 \
  cargo run -p ml-worker --release
```

Weak labels from existing categorization pipeline:

| Signal | Source field |
|--------|----------------|
| Phishing category | `has(categories, 'phishing')` |
| PhishTank hit | `has(threat_sources, 'phishtank')` |
| UT1 hit | `has(threat_sources, 'ut1')` |

Lexical signals (computed in Rust): domain length, hyphens, digits, subdomain depth, Shannon entropy, suspicious keywords, IP-as-hostname, suspicious URL paths.

```bash
python3 scripts/ml/eval_phishing_lexical.py
```

### C&C beacon scoring (M5.4)

Set `ML_MODEL=cc_beacon_v0` (scores `(client_ip, domain)` pairs):

```bash
CLICKHOUSE_URL=http://127.0.0.1:8123 \
  ML_MODEL=cc_beacon_v0 \
  ML_BEACON_LOOKBACK_SECS=3600 \
  METRICS_PORT=8091 \
  cargo run -p ml-worker --release
```

Augments M4 alert-worker `beacon_periodic` with behavioral signals:

| Signal | Description |
|--------|-------------|
| **Weak label** | Passes `beacon_periodic` thresholds (gap_cv ≤ 0.25, ≥5 hits, gap 45–900s) |
| Regularity | Low gap coefficient of variation |
| Small payloads | avg response_size < 512 B |
| POST ratio | High POST fraction |
| Off-hours | Traffic 22:00–06:00 UTC |
| Low URL diversity | ≤2 unique URLs with many requests |

```bash
python3 scripts/ml/eval_cc_beacon.py
```

## Grafana

Panel **Top anomalous entities (UEBA z-score / ml-worker)** on [BSDM HTTP Traffic (ClickHouse)](../grafana/dashboards/bsdm-http-traffic-ch.json).  
Panel **Top phishing-scored domains (lexical / ml-worker M5.3)** on the same dashboard.  
Panel **Top C&C beacon pairs (cc_beacon_v0 / ml-worker M5.4)** on the same dashboard.  
Panel **Active threat score cache (M5.5 write-back)** on the same dashboard.  
Ad-hoc SQL: [`scripts/clickhouse/m5_ueba_queries.sql`](../scripts/clickhouse/m5_ueba_queries.sql), [`scripts/clickhouse/m5_phishing_queries.sql`](../scripts/clickhouse/m5_phishing_queries.sql), [`scripts/clickhouse/m5_beacon_queries.sql`](../scripts/clickhouse/m5_beacon_queries.sql), [`scripts/clickhouse/m5_writeback_queries.sql`](../scripts/clickhouse/m5_writeback_queries.sql).

## Verify

```bash
curl http://127.0.0.1:8091/health
curl http://127.0.0.1:8091/api/threat-scores
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
| M5.5 score write-back | [#169](https://github.com/onixus/bsdm-proxy/issues/169) ✅ |
