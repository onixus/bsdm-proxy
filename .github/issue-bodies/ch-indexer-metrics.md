## Summary

**Phase 1** — Prometheus metrics for `cache-indexer` per backend (OpenSearch / ClickHouse / dual).

Part of OpenSearch → ClickHouse migration.

## Scope

- HTTP `/metrics` on cache-indexer (new small metrics server) **or** log-based counters (prefer metrics endpoint for k8s)
- Counters: `cache_indexer_inserts_total{backend="opensearch|clickhouse"}`, `cache_indexer_insert_errors_total{backend}`
- Histogram: batch flush duration
- Grafana panel examples in `docs/clickhouse-analytics.md`

## Acceptance criteria

- [ ] Metrics visible after indexer run in compose
- [ ] Document scrape config snippet for Prometheus

## Depends on

- #114
