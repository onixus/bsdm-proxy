## Summary

**Phase 3** — make **ClickHouse the default** analytics store in `docker-compose.yml` (replace OpenSearch services).

## Scope

- Add `clickhouse` + `cache-indexer` with `INDEXER_BACKEND=clickhouse` to main compose
- Remove (or move to profile): `opensearch`, `opensearch-dashboards`, `dashboards-setup`, `opensearch-data` volume
- Update `README.md` quick start analytics section
- Update `docs/architecture.md` diagrams

## Acceptance criteria

- [ ] `docker compose up -d --build` → proxy traffic → `SELECT count() FROM bsdm.http_cache` > 0
- [ ] E2E / smoke CI still green (no OS dependency)
- [ ] `docker-compose.clickhouse.yml` merged or deprecated with note

## Depends on

- #125 dual-write validation (recommended)
- #128 Grafana CH dashboards
- Search API optional for M3 gate but recommended

## Blocks

- #132 Remove OpenSearch backend code
