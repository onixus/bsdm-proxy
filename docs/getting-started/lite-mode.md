# Lite mode (Strategic Phase 1)

Standalone caching HTTPS proxy with optional SQLite Search API — **no Kafka or ClickHouse**.

See [roadmap.md](roadmap.md) (Lite Mode).

## One-command start

```bash
./scripts/gen-ca.sh
docker compose -f docker-compose.lite.yml up -d --build
```

| Service | Port | Notes |
|---------|------|--------|
| proxy | 1488 | Forward proxy, MITM, L1 + spill |
| proxy metrics | 9090 | `/health`, `/metrics` |
| cache-indexer | 8080 | `INDEX_STORE=sqlite`, `/api/search`, `POST /api/events` |

Proxy posts `CacheEvent` JSON to `EVENT_SINK_URL` (Kafka unset).

## Verify

```bash
curl http://127.0.0.1:9090/health
curl --cacert certs/ca.crt -x http://127.0.0.1:1488 https://httpbin.org/get
sleep 1
curl 'http://127.0.0.1:8080/api/search?domain=httpbin.org&limit=5'
```

## Indexer stores

| `INDEX_STORE` | Needs | Notes |
|---------------|-------|--------|
| `sqlite` | `SQLITE_PATH` | Default for Lite compose |
| `memory` | — | Ring buffer; tests / ephemeral |
| `clickhouse` | `CLICKHOUSE_*` | Full-stack default; Kafka optional |

| Env | Default | Description |
|-----|---------|-------------|
| `SQLITE_PATH` | `/var/lib/cache-indexer/events.db` | File or `:memory:` |
| `SQLITE_MAX_ROWS` | `1000000` | Prune oldest when exceeded |
| `KAFKA_BROKERS` | unset = off | Optional Kafka → store |
| `EVENT_SINK_URL` | — | Proxy → `POST /api/events` |
| `EVENT_SINK_TOKEN` / `INGEST_API_TOKEN` | — | Optional Bearer |

## Full analytics stack

Root [`docker-compose.yml`](../docker-compose.yml): Kafka → ClickHouse → Grafana / `alert-worker`.

## Roadmap leftovers

- [x] `cache-indexer` without mandatory Kafka/ClickHouse (`INDEX_STORE` + HTTP ingest)
- [x] SQLite / in-memory metadata store
- [x] Cargo features to drop `rdkafka` from Lite binary (B21 / #52) — `cargo build --no-default-features --features auth-basic -p bsdm-proxy`
