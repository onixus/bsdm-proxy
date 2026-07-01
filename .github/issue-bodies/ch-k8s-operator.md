## Summary

**Phase 5** — update **k8s deployment docs and Helm** for ClickHouse analytics plane (replace OpenSearch StatefulSet).

## Scope

- `docs/k8s-architecture.md`: analytics namespace with ClickHouse Operator / Altinity chart
- `charts/bsdm/`: values for CH URL, indexer `INDEXER_BACKEND=clickhouse`
- Sizing: CH storage vs former OS 64Gi guidance
- Backup/DR: partition freeze / S3 vs OS snapshots

## Acceptance criteria

- [ ] k8s doc diagram: Kafka → indexer → ClickHouse
- [ ] Helm values example for analytics subchart or external CH reference
- [ ] No OpenSearch as required component in k8s path

## Depends on

- #130 production compose path on CH

## References

- [clickhouse-analytics.md](docs/clickhouse-analytics.md) k8s section
