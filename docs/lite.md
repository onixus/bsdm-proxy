# Lite mode (Strategic Phase 1)

Standalone caching HTTPS proxy without Kafka, ClickHouse, Prometheus, Grafana, or `cache-indexer`.

See [strategic-roadmap.md](strategic-roadmap.md) Phase 1.

## One-command start

```bash
./scripts/gen-ca.sh
docker compose -f docker-compose.lite.yml up -d --build
```

| Service | Port | Notes |
|---------|------|--------|
| proxy | 1488 | Forward proxy, MITM on, L1 + spill volume |
| metrics | 9090 | `/health`, `/ready`, `/metrics` (no Grafana needed) |

Kafka is **not** configured (`KAFKA_BROKERS` unset) — events are not published.

## Verify

```bash
curl http://127.0.0.1:9090/health
curl --cacert certs/ca.crt -x http://127.0.0.1:1488 https://httpbin.org/get
curl --cacert certs/ca.crt -x http://127.0.0.1:1488 https://httpbin.org/get   # expect cache HIT on 2nd
curl http://127.0.0.1:9090/metrics | grep bsdm_proxy_cache
```

## Defaults

| Env | Lite default |
|-----|----------------|
| `MITM_ENABLED` | `true` (needs `./certs` from `gen-ca.sh`) |
| `CACHE_CAPACITY` | `5000` |
| `CACHE_SPILL_DIR` | `/var/cache/bsdm-spill` (named volume) |
| Auth / ACL / categorization | off |

## Full analytics stack

Use root [`docker-compose.yml`](../docker-compose.yml) when you need Kafka → ClickHouse → Search API / Grafana / `alert-worker`.

## Roadmap leftovers (not in this slice)

- [ ] `cache-indexer` without mandatory Kafka/ClickHouse
- [ ] SQLite / in-memory metadata store
- [ ] Cargo features to drop `rdkafka` from Lite binary (related: B21 / #52)
