# ADR 0002: ClickHouse analytics store (OpenSearch successor)

## Status

Accepted (2026-06)

## Context

BSDM analytics pipeline:

```
proxy → Kafka (CacheEvent JSON) → cache-indexer → ClickHouse → Grafana / Search API
```

Roadmap M3–M5 workloads:

| Milestone | Query pattern | Best store |
|-----------|---------------|------------|
| M3 Retro-search | domain/user + time filter, top-N | Columnar SQL |
| M4 Threat analytics | windows, periodic patterns, GROUP BY | ClickHouse |
| M5 ML | batch feature extraction | ClickHouse |

Corporate medium: **~4M events/day**, 42-day retention ([capacity-planning.md](../capacity-planning.md)).

OpenSearch was RAM-heavy and optimized for full-text search; BSDM queries are **structured analytics**. Migration completed in phases 0–4 ([#125](https://github.com/onixus/bsdm-proxy/issues/125)).

**Kafka vs NATS:** evaluated in parallel — bus unchanged in phase 1 (see Decision 2).

## Decision

### 1. ClickHouse as primary analytics store

- `cache-indexer` writes to ClickHouse (`bsdm.http_cache`).
- Schema: `scripts/clickhouse/http_cache.sql` — `MergeTree`, daily partitions, 42-day TTL.
- Dashboards: Grafana + ClickHouse datasource; Search API on cache-indexer admin port.

### 2. Keep Kafka in phase 1–2; NATS optional later

| Bus | When |
|-----|------|
| Kafka | Default — multi-consumer M4/M5, existing `rdkafka` integration |
| NATS JetStream | Optional lab/k8s profile via `EventBus` abstraction (phase 3) |

### 3. Migration (completed)

1. `docker-compose.clickhouse.yml` + schema
2. cache-indexer ClickHouse backend + dual-write validation
3. Search API + Grafana CH dashboards
4. Default compose on ClickHouse
5. Remove OpenSearch backend ([#134](https://github.com/onixus/bsdm-proxy/issues/134))

## Consequences

**Positive:** lower cost/RAM, SQL retro-search, M4/M5 fit, simpler Search API, single analytics store.

**Negative:** lose KQL/OSD (replaced by Grafana SQL); fuzzy URL search weaker in CH.

## Alternatives rejected

- NATS + OpenSearch only — does not fix analytics store mismatch
- Both bus + store at once — too risky
- TimescaleDB / Loki — weaker for this event shape and scale

## References

- [clickhouse-analytics.md](../clickhouse-analytics.md)
- [search-api.md](../search-api.md)
- [roadmap.md](../roadmap.md) M3–M5
- `bsdm-events::CacheEvent`
