## Summary

**Phase 1** — script/CI job to compare OpenSearch vs ClickHouse event counts during dual-write migration.

## Scope

- `scripts/reconcile-os-ch-events.sh` (or Python):
  - Query OS: `count` + optional `cardinality` on `event_id` for time window
  - Query CH: `SELECT count(), count(DISTINCT event_id) FROM bsdm.http_cache WHERE ts ...`
- Exit non-zero if drift > threshold (default 0.1%)
- Document usage in `docs/clickhouse-analytics.md` migration section

## Acceptance criteria

- [ ] Runs against lab compose with `INDEXER_BACKEND=dual`
- [ ] README section «Migration validation»

## Depends on

- Dual-write issue (#125)
