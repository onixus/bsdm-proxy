## Summary

**Phase 4** — remove OpenSearch backend and dependencies from the codebase (breaking change).

## Scope

- Delete `cache-indexer/src/opensearch.rs` (or `feature = "opensearch"` unmaintained for one release — prefer delete)
- Remove `opensearch` from `cache-indexer/Cargo.toml` and workspace
- Move or delete `bsdm-events` OS helpers (`index_mappings`, `ism_policy_body`) — keep only if legacy profile needs them
- Delete `opensearch-dashboards/`, `OPENSEARCH_UPGRADE.md`
- Remove OS env vars from packaging

## Acceptance criteria

- [ ] `cargo build -p cache-indexer` without opensearch crate
- [ ] `cargo test --workspace` green
- [ ] CHANGELOG breaking change entry
- [ ] ADR 0002 status → Accepted

## Depends on

- #130 default compose on CH
- #131 legacy profile shipped (or explicit decision to hard-cut)

## Target version

v0.5.x or after one release with legacy profile
