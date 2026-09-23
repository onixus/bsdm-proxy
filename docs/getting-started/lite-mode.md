# Lite mode

Standalone caching HTTPS proxy with optional SQLite Search API — **no Kafka or ClickHouse**.

Зрелость профиля — [project-status.md](../project-status.md).

## One-command start

```bash
./scripts/gen-ca.sh
docker compose -f deploy/compose/docker-compose.lite.yml up -d --build
```

| Service | Port | Notes |
|---------|------|--------|
| proxy | 3128 | Forward proxy, MITM, L1 + spill |
| proxy metrics | 9090 | `/health`, `/metrics` |
| cache-indexer | 8080 | `INDEX_STORE=sqlite`, `/api/search`, `POST /api/events` |

Proxy posts `CacheEvent` JSON to `EVENT_SINK_URL` (Kafka unset).

## Verify

```bash
curl http://127.0.0.1:9090/health
curl --cacert certs/ca.crt -x http://127.0.0.1:3128 https://httpbin.org/get
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
| `SQLITE_MAX_ROWS` | `1000000` | Prune oldest rows atomically when exceeded |
| `SQLITE_WRITE_QUEUE_CAPACITY` | `64` | Maximum queued HTTP/Kafka ingest requests waiting for the SQLite writer |
| `SQLITE_BATCH_MAX_EVENTS` | `500` | Target ceiling for opportunistically coalesced events per writer transaction; one large request is never split |
| `SQLITE_BUSY_TIMEOUT_MS` | `5000` | How long SQLite waits for a database lock before returning an error |
| `KAFKA_BROKERS` | unset = off | Optional Kafka → store |
| `EVENT_SINK_URL` | — | Proxy → `POST /api/events` |
| `EVENT_SINK_TOKEN` / `INGEST_API_TOKEN` | — | Optional Bearer |

## SQLite concurrency model

Lite mode keeps SQLite out of Tokio worker threads:

```text
HTTP ingest / Kafka consumer
          │
          ▼
 bounded write-request queue
          │
          ▼
 dedicated blocking writer actor ── one transaction for queued requests
          │
          └── WAL database ── separate read connection via spawn_blocking
```

The writer is lossless within the process: when the bounded queue is full, ingest waits instead of dropping accepted events. HTTP `202` and Kafka offset commits are emitted only after SQLite commits the transaction. Under burst load, queued requests are combined into fewer transactions; under light load, the first request is committed immediately rather than waiting for a batching timer.

Watch these Prometheus metrics on the indexer `/metrics` endpoint:

- `cache_indexer_sqlite_writer_queue_depth`
- `cache_indexer_sqlite_writer_saturation_total`
- `cache_indexer_sqlite_writer_errors_total`
- `cache_indexer_sqlite_writer_batch_events`
- `cache_indexer_sqlite_writer_batch_requests`
- `cache_indexer_sqlite_writer_commit_duration_seconds`

A rising saturation counter with sustained queue depth means SQLite cannot keep up. Increase `SQLITE_BATCH_MAX_EVENTS` only while commit latency remains acceptable. Increasing queue capacity only extends the bounded burst buffer and does not fix sustained downstream overload.

## Full analytics stack

Root [`docker-compose.yml`](../../docker-compose.yml): Kafka → ClickHouse → Grafana / `alert-worker`.

## Roadmap leftovers

- [x] `cache-indexer` without mandatory Kafka/ClickHouse (`INDEX_STORE` + HTTP ingest)
- [x] SQLite / in-memory metadata store
- [x] Bounded SQLite writer actor with isolated WAL reads
- [x] Cargo features to drop `rdkafka` from Lite binary (B21 / #52) — `cargo build --no-default-features --features auth-basic -p bsdm-proxy`