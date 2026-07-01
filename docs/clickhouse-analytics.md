# ClickHouse analytics (M3+)

Стек ретропоиска на ClickHouse. См. [ADR 0002](adr/0002-clickhouse-analytics.md) (Accepted).

## Быстрый старт

```bash
docker compose up -d --build

# Проверка схемы
curl 'http://127.0.0.1:8123/?query=SHOW+TABLES+FROM+bsdm'

# Трафик через прокси (события уходят в Kafka)
curl -x http://127.0.0.1:1488 http://httpbin.org/get

curl 'http://127.0.0.1:8123/?query=SELECT+count()+FROM+bsdm.http_cache'
curl 'http://127.0.0.1:8080/api/search?limit=5'
```

Grafana: http://localhost:3000 (admin/admin) — **BSDM HTTP Traffic (ClickHouse)** + proxy metrics dashboards.

Search API: `http://localhost:8080/api/search` — см. [search-api.md](search-api.md).

## Схема

`scripts/clickhouse/http_cache.sql` — таблица `bsdm.http_cache`, TTL 42 дня, партиции по дню.

Поля соответствуют `bsdm-events::CacheEvent` (включая `threat_sources`, `acl_action`).

## Примеры SQL (M3)

```sql
-- Кто ходил на домен за 30 дней
SELECT ts, username, client_ip, url, method, status, cache_status
FROM bsdm.http_cache
WHERE domain = 'example.com'
  AND ts >= now() - INTERVAL 30 DAY
ORDER BY ts DESC
LIMIT 1000;

-- Top domains per user (7 дней)
SELECT username, domain, count() AS requests, sum(response_size) AS bytes
FROM bsdm.http_cache
WHERE ts >= now() - INTERVAL 7 DAY AND username IS NOT NULL
GROUP BY username, domain
ORDER BY requests DESC
LIMIT 50;
```

## cache-indexer

`cache-indexer` пишет только в ClickHouse (Kafka → JSONEachRow INSERT).

| Переменная | Default | Описание |
|------------|---------|----------|
| `METRICS_PORT` | `8080` | `/metrics`, `/health`, `/api/search` |
| `SEARCH_API_ENABLED` | `true` | REST search over ClickHouse |
| `SEARCH_API_TOKEN` | — | Bearer auth for `/api/search` |
| `SEARCH_API_MAX_LIMIT` | `10000` | Max rows per search |
| `SEARCH_API_DEFAULT_DAYS` | `30` | Default lookback |
| `CLICKHOUSE_URL` | `http://clickhouse:8123` | HTTP interface |
| `CLICKHOUSE_DATABASE` | `bsdm` | База |
| `CLICKHOUSE_TABLE` | `http_cache` | Таблица |
| `CLICKHOUSE_USER` / `CLICKHOUSE_PASSWORD` | — | Basic auth (опц.) |

Метрики: `cache_indexer_inserts_total{backend="clickhouse"}`, `cache_indexer_insert_errors_total{backend}`, `cache_indexer_batch_duration_seconds`.

## Миграция OpenSearch → ClickHouse (завершена)

| Фаза | Статус |
|------|--------|
| 0 | CH schema + indexer ([#114](https://github.com/onixus/bsdm-proxy/issues/114)) |
| 1 | Dual-write + reconciliation |
| 2 | Grafana + Search API ([#129](https://github.com/onixus/bsdm-proxy/issues/129), [#130](https://github.com/onixus/bsdm-proxy/issues/130)) |
| 3 | Default compose ([#132](https://github.com/onixus/bsdm-proxy/issues/132)) |
| 4 | Remove OpenSearch code ([#134](https://github.com/onixus/bsdm-proxy/issues/134)) |

Epic: [#125](https://github.com/onixus/bsdm-proxy/issues/125).

## k8s

См. [k8s-architecture.md](k8s-architecture.md) — ClickHouse Operator / Altinity chart в analytics namespace.
