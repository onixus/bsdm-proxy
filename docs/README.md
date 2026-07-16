# Документация BSDM-Proxy (Wiki)

Центральное оглавление. Страницы wiki — в каталоге `docs/`.

**Текущая версия:** 0.5.0 · Analytics: Kafka → ClickHouse · [roadmap](roadmap.md)

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
| [acl.md](acl.md) | ACL + REST API |
| [categorization.md](categorization.md) | UT1 Blacklists, metrics, OTX |
| [hierarchical-caching.md](hierarchical-caching.md) | ICP/HTCP hierarchy |
| [clickhouse-analytics.md](clickhouse-analytics.md) | ClickHouse analytics |
| [alerting.md](alerting.md) | Alert worker + Grafana/AM (M4) |
| [search-api.md](search-api.md) | REST Search API |

## Архитектура и roadmap

| Документ | Описание |
|----------|----------|
| [architecture.md](architecture.md) | Архитектура, потоки данных, блокеры |
| [BLOCKERS.md](BLOCKERS.md) | Реестр блокеров B1–B25 |
| [roadmap.md](roadmap.md) | Milestones Squid + ретропоиск + ML (M1–M5) |
| [strategic-roadmap.md](strategic-roadmap.md) | Стратегия: Lite, DX, Wasm, AI-трафик |
| [lite.md](lite.md) | Lite mode: `docker-compose.lite.yml` |
| [swg-backlog-mapping.md](swg-backlog-mapping.md) | Mapping vs SWG vendors |
| [adr/0001-tiered-sharded-l1-cache.md](adr/0001-tiered-sharded-l1-cache.md) | ADR tiered L1 |
| [adr/0002-clickhouse-analytics.md](adr/0002-clickhouse-analytics.md) | ADR ClickHouse |

*Удалённые документы:* `OPTIMIZATIONS.md` → см. [performance.md](performance.md); `HIERARCHICAL_CACHING_README.md` → [hierarchical-caching.md](hierarchical-caching.md).*
