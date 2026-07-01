## Summary

**Phase 3** — optional **legacy OpenSearch compose profile** for one release cycle during cutover.

## Scope

- `docker compose --profile legacy-opensearch up` restores OS + OSD + OS indexer
- Document deprecation timeline in `docs/clickhouse-analytics.md` and CHANGELOG
- `INDEXER_BACKEND=opensearch` only via legacy profile env file

## Acceptance criteria

- [ ] Profile documented in README
- [ ] Removal date target noted (e.g. v0.5.0)

## Depends on

- #130 default compose on ClickHouse
