# ADR 0003: ML worker + ClickHouse feature store (M5)

**Status:** Accepted
**Date:** 2026-07-16
**Relates:** [#46](https://github.com/onixus/bsdm-proxy/issues/46) (B15), [roadmap M5](../roadmap.md), [ADR 0002](0002-clickhouse-analytics.md)

## Context

M4 delivers **rule-based** threat analytics via `alert-worker` (ClickHouse SQL → webhook / Grafana).
M5 needs **ML / scoring** (anomaly, phishing, C&C) without putting inference on the proxy hot path ([architecture.md](../architecture/overview.md)).

B15 originally said “read OpenSearch/Kafka”. Analytics storage is now **ClickHouse-only** (ADR 0002). Alerting exists as `alert-worker`; scoring does not.

## Decision

1. **Async CH-backed `ml-worker`** (new crate), sibling to `alert-worker`:
   - Poll `bsdm.http_cache`
   - Aggregate **entity features** into `bsdm.entity_features`
   - Compute **scores** into `bsdm.ml_scores` (v0 = heuristic stub; later real models)
   - Optionally POST findings to the same SIEM webhook shape as alert-worker
2. **Feature store = ClickHouse tables** (not a separate OLTP store). Batch SQL aggregation is the first extractor; Materialized Views optional later.
3. **Proxy stays ML-free** on the hot path until a proven async score + TTL cache design (M5.5). Doc stub `ML_ENABLED` remains unimplemented.
4. **`alert-worker` stays rules-only**; do not merge ML into it. Share patterns (CH HTTP client, metrics, webhook JSON), not a shared library yet.

## Consequences

- New workspace member `ml-worker`, compose profile `ml`, packaging unit/env.
- M5.1 shipped scaffolding + stub scorer; M5.2 adds unsupervised `ueba_zscore_v0` (population baseline / optional JSON artifact). Later: phishing/C&C models, optional ONNX.
- Closes the design half of B15/#46; implementation tracked under M5 epic issues.

## Non-goals (M5.1)

- ONNX / Python training in-repo
- Inline proxy scoring
- New Kafka consumer (CH poll is enough)
- DLP / ICAP
