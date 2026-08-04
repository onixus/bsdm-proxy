# Pilot ML path (one model)

Day-2+ pilot path for **async** threat scoring: one `ml-worker` process, one
model (`ueba_zscore_v0`), ClickHouse feature store + optional write-back for
proxy enrich. **Not** day-1 Hybrid stand-up; enable after analytics is healthy.

Related: [ml-security.md](../analytics/ml-security.md) ·
[ADR 0003](../adr/0003-ml-worker-feature-store.md) ·
[pilot-alerts.md](pilot-alerts.md) ·
[pilot-deployment.md](pilot-deployment.md).

---

## Day-1 vs day-2+

| Include | Exclude |
|---|---|
| `--profile ml` single container | Multi-model / multi-process fleet |
| `ML_MODEL=ueba_zscore_v0` | phishing / beacon / flight_risk in the same process |
| Write-back + `GET /api/threat-scores` | Hot-path ML inference inside proxy |
| Enrich-only proxy poll (optional) | Blocking on ML scores by default (`BLOCK=0`) |
| Lab smoke health + metrics | Full SIEM product / labeled ML ops |

Rule alerts stay in **alert-worker** ([pilot-alerts.md](pilot-alerts.md)).
ML is a separate detection layer on ClickHouse history.

---

## Recommended pilot model: UEBA z-score

| Setting | Pilot value | Why |
|---|---|---|
| `ML_MODEL` | `ueba_zscore_v0` | Default in compose; unsupervised on client_ip windows |
| `ML_ENTITY_TYPES` | `client_ip` | Matches forward-proxy identity without username |
| `ML_MIN_REQUESTS` | `5` | Easier with thin lab traffic (prod often `10`) |
| `ML_POLL_INTERVAL_SECS` | `60` | Faster feedback than default 120s |
| Fallback | `anomaly_stub_v0` behaviour | When baseline has too few samples |

Other models (`phishing_lexical_v0`, `cc_beacon_v0`, …) are valid but **not**
the pilot default — run a second process only if you intentionally expand scope.

---

## Enable

### 1. Prerequisites

- ClickHouse healthy with analytics events (`http_cache` has rows after traffic).
- ML DDL applied (compose init or):

```bash
clickhouse-client --multiquery < scripts/clickhouse/ml_features.sql
```

### 2. Start ml-worker

```bash
# Optional pilot env pack:
# set -a; source config/pilot-ml.env.example; set +a

docker compose -f docker-compose.yml -f docker-compose.pilot.yml \
  --profile ml up -d --build ml-worker

curl -fsS http://127.0.0.1:8091/health
# {"status":"ok","service":"ml-worker"}
```

Cargo (dev):

```bash
CLICKHOUSE_URL=http://127.0.0.1:8123 \
  ML_MODEL=ueba_zscore_v0 \
  ML_ENTITY_TYPES=client_ip \
  ML_MIN_REQUESTS=5 \
  ML_POLL_INTERVAL_SECS=60 \
  METRICS_PORT=8091 \
  cargo run -p ml-worker --release
```

### 3. Optional: proxy enrich (not block)

```bash
# On proxy process / compose override:
export THREAT_SCORE_ENABLED=true
export THREAT_SCORE_POLL_URL=http://ml-worker:8091/api/threat-scores   # docker
# host: http://127.0.0.1:8091/api/threat-scores
export THREAT_SCORE_WARN_THRESHOLD=0.7
export THREAT_SCORE_BLOCK_THRESHOLD=0   # enrich threat_sources only
```

Leave `THREAT_SCORE_ENABLED` unset/false for pilot day-2 if you only want CH
tables + Grafana panels.

---

## Acceptance smoke

```bash
ML_URL=http://127.0.0.1:8091 \
CLICKHOUSE_URL=http://127.0.0.1:8123 \
./scripts/run-ml-pilot-smoke.sh
```

What it checks:

1. `GET /health` → ok  
2. `GET /api/threat-scores` → JSON (may be empty `[]` / `{}` without scores yet)  
3. `GET /metrics` includes `bsdm_ml_worker_cycles_total`  
4. Optional: ClickHouse `entity_features` / `ml_scores` reachable (warn if empty)

Empty scores with healthy worker = pass until there is enough traffic for
`ML_MIN_REQUESTS` windows.

---

## Operator surfaces

| Surface | What to look for |
|---|---|
| `curl :8091/api/threat-scores` | Active write-back snapshot |
| Prometheus / metrics | `bsdm_ml_worker_cycles_total`, `*_scores_written_total` |
| Grafana CH dashboard | Top anomalous entities (UEBA) + threat score cache panels |
| ClickHouse | `bsdm.ml_scores`, `bsdm.entity_features`, `bsdm.threat_score_cache` |

Ad-hoc SQL: `scripts/clickhouse/m5_ueba_queries.sql`,
`scripts/clickhouse/m5_writeback_queries.sql`.

---

## Honesty / known limits

1. **One process = one model.** Second model ⇒ second `ml-worker` with another
   `ML_MODEL` / metrics port.
2. **Baseline cold start.** Early cycles use stub-like scoring until population
   stats exist (`ML_BASELINE_MIN_SAMPLES` or `ML_BASELINE_PATH` artifact).
3. **Not a security boundary by itself.** Prefer ACL/DNS/SNI for enforcement;
   ML enriches detection.
4. **Proxy block on ML is off** unless you deliberately set
   `THREAT_SCORE_BLOCK_THRESHOLD` &gt; 0 (not recommended for first pilot week).
5. **Experimental freeze** elsewhere (WASM/ICAP/DLP/eBPF) is unrelated — ML is
   Beta, profile-gated.

---

## Env pack

See [`config/pilot-ml.env.example`](../../config/pilot-ml.env.example). Full
variable catalogue: [ml-security.md](../analytics/ml-security.md).
