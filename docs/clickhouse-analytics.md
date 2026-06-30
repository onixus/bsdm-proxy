# ClickHouse analytics (M3+)

Стек ретропоиска на ClickHouse вместо OpenSearch. См. [ADR 0002](adr/0002-clickhouse-analytics.md).

## Быстрый старт

```bash
docker compose -f docker-compose.clickhouse.yml up -d --build

# Проверка схемы
curl 'http://127.0.0.1:8123/?query=SHOW+TABLES+FROM+bsdm'

# Трафик через прокси (события уходят в Kafka)
curl -x http://127.0.0.1:1488 http://httpbin.org/get

# После реализации CH indexer — строки появятся в bsdm.http_cache
curl 'http://127.0.0.1:8123/?query=SELECT+count()+FROM+bsdm.http_cache'
```

Grafana: http://localhost:3000 (admin/admin) — добавьте datasource ClickHouse (`http://clickhouse:8123`).

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

## Реализация indexer

Отслеживается в [#114](https://github.com/onixus/bsdm-proxy/issues/114) — `INDEXER_BACKEND=clickhouse` в cache-indexer.

| Фаза | Действие |
|------|----------|
| 1 | Этот compose + ADR 0002 |
| 2 | `INDEXER_BACKEND=clickhouse` в cache-indexer |
| 3 | Grafana SQL dashboards (замена OSD) |
| 4 | Search API на ClickHouse HTTP |

Kafka остаётся bus на фазе 1–2; NATS — опционально позже (ADR 0002).

## k8s

См. [k8s-architecture.md](k8s-architecture.md) — в analytics namespace заменить OpenSearch StatefulSet на ClickHouse Operator / Altinity chart.
