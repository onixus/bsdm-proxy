## Summary

**Phase 2** — implement Search API on **ClickHouse HTTP**, superseding OpenSearch-based design in #110.

## Motivation

#110 was scoped for OpenSearch. Per ADR 0002 the Search API must query ClickHouse SQL.

## Scope

- Thin REST service (could live in proxy metrics port or separate binary — TBD in design)
- Parameterized queries: domain, username, time range, limit
- Auth bearer token (reuse ACL API pattern)
- CSV/JSON export for SOC
- `docs/search-api.md`

## Acceptance criteria

- [ ] `GET /api/search?domain=example.com&from=...&to=...` returns rows from CH
- [ ] No `opensearch` crate dependency in Search API path
- [ ] Integration test with compose fixture

## Related

- #110 (update title/body to CH — manual follow-up if issue edit blocked)
- Epic migration tracker

## Depends on

- #114 ClickHouse indexer
