## Summary

Parent tracker for **replacing OpenSearch with ClickHouse** as the analytics store (ADR 0002). Proxy data plane unchanged; migration affects `cache-indexer`, compose, dashboards, Search API, k8s docs.

## Target architecture

```
proxy → Kafka → cache-indexer (INDEXER_BACKEND=clickhouse) → ClickHouse
                                                          → Grafana / Search API
```

## Phases

| Phase | Focus | Issues |
|-------|--------|--------|
| 0 | CH schema + indexer backend | #114 (PR #123) |
| 1 | Dual-write + validation | #125, #126, #127 |
| 2 | UI/API on CH | #110 → CH scope, #128, #129 |
| 3 | Default compose cutover | #130, #131 |
| 4 | Remove OS code | #132 |
| 5 | k8s / production | #133 |

## Done when

- [ ] Default `docker compose up` uses ClickHouse (no OpenSearch)
- [ ] M3 gate: «кто ходил на domain X за 30 дней» via Grafana or Search API
- [ ] `opensearch` crate removed or feature-gated
- [ ] `docs/architecture.md` / k8s docs describe CH only

## References

- [ADR 0002](docs/adr/0002-clickhouse-analytics.md)
- [clickhouse-analytics.md](docs/clickhouse-analytics.md)
- [roadmap.md M3](docs/roadmap.md)
