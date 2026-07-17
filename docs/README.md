# Документация BSDM-Proxy (Wiki)

Центральное оглавление. Страницы wiki — в каталоге `docs/`.

**Текущая версия:** 0.5.0 · M1–M5 done · Unreleased: DX/AI · Analytics: Kafka → ClickHouse (или Lite: HTTP → SQLite) · [roadmap](roadmap.md)

## Начало работы

| Документ | Описание |
|----------|----------|
| [README.md](../README.md) | Обзор, быстрый старт, конфигурация |
| [deployment.md](deployment.md) | Docker, native package, Kubernetes |
| [docker.md](docker.md) | Docker Compose, сборка образов |
| [kubernetes.md](kubernetes.md) | Манифесты, probes, managed services |
| [k8s-architecture.md](k8s-architecture.md) | HA топология, CHI Operator, Helm analytics |
| [packaging/README.md](../packaging/README.md) | Release-пакет (systemd) |
| [development.md](development.md) | Сборка, тесты, CI, релиз |
| [structure.md](structure.md) | Структура репозитория |
| [licensing.md](licensing.md) | Лицензии и third-party |
| [CHANGELOG.md](../CHANGELOG.md) | История изменений |
| [releases/v0.5.0.md](releases/v0.5.0.md) | **Release notes 0.5.0** (M4) |
| [releases/v0.3.2.md](releases/v0.3.2.md) | Release notes 0.3.2 |
| [releases/v0.3.1.md](releases/v0.3.1.md) | Release notes 0.3.1 (ClickHouse migration) |
| [releases/v0.3.0.md](releases/v0.3.0.md) | Release notes 0.3.0 (M2) |
| [capacity-planning.md](capacity-planning.md) | Планирование ёмкости |

## Функциональность

| Документ | Описание |
|----------|----------|
| [authentication.md](authentication.md) | Basic, LDAP, NTLM, Kerberos |
| [logging.md](logging.md) | `RUST_LOG`, уровни |
| [performance.md](performance.md) | Тюнинг RPS, bench |
| [semantic-cache.md](semantic-cache.md) | LLM / semantic cache prep |
| [acl.md](acl.md) | ACL + REST API |
| [control-plane.md](control-plane.md) | DX: stats, purge, hierarchy/TLS reload, ACL CRUD |
| [wasm-plugins.md](wasm-plugins.md) | Wasmtime request hooks (feature `wasm`) |
| [dns-sinkhole.md](dns-sinkhole.md) | Optional DNS RPZ-lite sidecar |
| [adr/0004-dns-sinkhole-sidecar.md](adr/0004-dns-sinkhole-sidecar.md) | ADR: DNS as sidecar, not in proxy |
| [categorization.md](categorization.md) | UT1 Blacklists, metrics, OTX |
| [hierarchical-caching.md](hierarchical-caching.md) | ICP/HTCP hierarchy |
| [clickhouse-analytics.md](clickhouse-analytics.md) | ClickHouse analytics |
| [alerting.md](alerting.md) | Alert worker + Grafana/AM (M4) |
| [ml-security.md](ml-security.md) | ML worker + feature store (M5) |
| [adr/0003-ml-worker-feature-store.md](adr/0003-ml-worker-feature-store.md) | ADR: CH feature store |
| [search-api.md](search-api.md) | REST Search API |
| [benchmarks-httparchive.md](benchmarks-httparchive.md) | HTTP Archive CDN URL workload |
| [../admin-console/README.md](../admin-console/README.md) | Admin Console (Vite UI) |

## Архитектура и roadmap

| Документ | Описание |
|----------|----------|
| [architecture.md](architecture.md) | Архитектура, потоки данных, блокеры |
| [BLOCKERS.md](BLOCKERS.md) | Реестр блокеров B1–B26 (все ✅) |
| [issue-tracker.md](issue-tracker.md) | Статус GitHub issues (open / close / next) |
| [roadmap.md](roadmap.md) | Milestones Squid + ретропоиск + ML (M1–M5) |
| [strategic-roadmap.md](strategic-roadmap.md) | Стратегия: Lite, DX, Wasm, AI-трафик |
| [lite.md](lite.md) | Lite: proxy + SQLite (`docker-compose.lite.yml`) |
| [swg-backlog-mapping.md](swg-backlog-mapping.md) | Mapping vs SWG vendors |
| [adr/0001-tiered-sharded-l1-cache.md](adr/0001-tiered-sharded-l1-cache.md) | ADR tiered L1 |
| [adr/0002-clickhouse-analytics.md](adr/0002-clickhouse-analytics.md) | ADR ClickHouse |

*Удалённые документы:* `OPTIMIZATIONS.md` → см. [performance.md](performance.md); `HIERARCHICAL_CACHING_README.md` → [hierarchical-caching.md](hierarchical-caching.md).*
