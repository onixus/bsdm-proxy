## Summary

**Phase 2** — replace OpenSearch Dashboards saved objects with **Grafana + ClickHouse datasource** (provisioned).

Part of OpenSearch → ClickHouse migration.

## Scope

- `grafana/provisioning/datasources/clickhouse.yml` (URL from env)
- Dashboard JSON: **BSDM HTTP Traffic** equivalent
  - Traffic to domain (variable `$domain`)
  - Top domains per user (7d)
  - Blocked / deny events with `threat_sources`
- Wire into `docker-compose.clickhouse.yml` (and later default compose)

## Acceptance criteria

- [ ] Fresh `docker compose -f docker-compose.clickhouse.yml up` → Grafana shows CH dashboards without manual setup
- [ ] Parity checklist vs `opensearch-dashboards/setup-saved-objects.sh` scenarios

## Depends on

- #114, data in `bsdm.http_cache`

## Blocks

- Removing OSD from default compose (#130)

## References

- Existing OSD setup: `opensearch-dashboards/setup-saved-objects.sh`
- SQL examples: `docs/clickhouse-analytics.md`
