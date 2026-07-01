## Summary

**Phase 1** — dual-write in `cache-indexer`: consume Kafka once, insert into **both** OpenSearch and ClickHouse during migration validation.

Part of OpenSearch → ClickHouse migration (epic #TBD).

## Motivation

Validate row parity and insert reliability before removing OpenSearch from the default compose path.

## Scope

- Env: `INDEXER_BACKEND=dual` (or `DUAL_WRITE_CLICKHOUSE=true` with `opensearch` default)
- On CH insert failure: configurable policy (`warn` vs `fail`) — default `warn` during migration
- Reuse `bsdm-events::json_each_row_lines` + existing OpenSearch bulk path
- Document in `packaging/config/cache-indexer.env.example`

## Acceptance criteria

- [ ] Lab: proxy traffic → both stores receive events
- [ ] `event_id` present in both backends for same Kafka batch
- [ ] Unit test for dual flush (mock OS + mock CH HTTP)
- [ ] No regression when `INDEXER_BACKEND=opensearch` or `clickhouse` alone

## Depends on

- #114 ClickHouse indexer backend

## Blocks

- Default compose cutover (#130)

## References

- ADR 0002 phase 2: dual-write validation
