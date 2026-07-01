# Документация BSDM-Proxy

Оглавление документации проекта.

## Начало работы

| Документ | Описание |
|----------|----------|
| [README.md](../README.md) | Обзор, быстрый старт, конфигурация |
| [packaging/README.md](../packaging/README.md) | Установка из release-пакета |
| [development.md](development.md) | Сборка, тесты, CI, релиз |
| [CHANGELOG.md](../CHANGELOG.md) | История изменений |
| [releases/v0.3.0.md](releases/v0.3.0.md) | **Release notes 0.3.0** |
| [releases/v0.2.3-test.md](releases/v0.2.3-test.md) | Release notes 0.2.3-test (superseded) |
| [capacity-planning.md](capacity-planning.md) | **Планирование ёмкости (корп. сценарии)** |

## Функциональность

| Документ | Описание |
|----------|----------|
| [authentication.md](authentication.md) | Аутентификация (Basic, LDAP, NTLM, Kerberos, LDAP groups) |
| [logging.md](logging.md) | Логирование (`RUST_LOG`, уровни, troubleshooting) |
| [performance.md](performance.md) | Тюнинг RPS (`PERF_FAST_CACHE_HIT`, `WORKER_COUNT`, bench) |
| [acl.md](acl.md) | Списки контроля доступа (ACL) |
| [clickhouse-analytics.md](clickhouse-analytics.md) | ClickHouse analytics (ADR 0002) |
| [search-api.md](search-api.md) | REST Search API over ClickHouse |

## Архитектура и roadmap

| Документ | Описание |
|----------|----------|
| [architecture.md](architecture.md) | **Архитектура, потоки данных, блокеры B1–B25** |
| [BLOCKERS.md](BLOCKERS.md) | Реестр блокеров (чеклист) |
| [roadmap.md](roadmap.md) | Roadmap и milestones (Squid + ретропоиск + ML) |
| [hierarchical-caching.md](hierarchical-caching.md) | Иерархический кеш, ICP, peer management |
| [HIERARCHICAL_CACHING_README.md](HIERARCHICAL_CACHING_README.md) | Краткий обзор hierarchical caching |
| [OPTIMIZATIONS.md](../OPTIMIZATIONS.md) | Оптимизации Hyper + quick_cache |

## Инфраструктура

| Документ | Описание |
|----------|----------|
| [docker-compose.yml](../docker-compose.yml) | Полный стек (proxy, Kafka, ClickHouse, monitoring) |
| [docker-compose.legacy-opensearch.yml](../docker-compose.legacy-opensearch.yml) | Legacy OpenSearch override (deprecated) |
| [docker-compose.redis-l2.yml](../docker-compose.redis-l2.yml) | Демо Redis L2 (2 proxy + Redis) |
| [OPENSEARCH_UPGRADE.md](../OPENSEARCH_UPGRADE.md) | Обновление OpenSearch |
| [web-config/README.md](../web-config/README.md) | Web UI для генерации конфигурации |

## Конфигурационные файлы

| Файл | Назначение |
|------|------------|
| [config/acl-rules.example.json](../config/acl-rules.example.json) | Пример ACL-правил |
| [packaging/config/bsdm-proxy.env.example](../packaging/config/bsdm-proxy.env.example) | Переменные окружения proxy |
| [prometheus/prometheus.yml](../prometheus/prometheus.yml) | Scrape config для Prometheus |
| [grafana/dashboards/bsdm-proxy.json](../grafana/dashboards/bsdm-proxy.json) | Grafana dashboard (Prometheus) |
| [grafana/clickhouse/dashboards/bsdm-http-traffic-ch.json](../grafana/clickhouse/dashboards/bsdm-http-traffic-ch.json) | Grafana HTTP Traffic (ClickHouse) |

## Версии

| Версия | Тип | Описание |
|--------|-----|----------|
| **0.3.0** | stable | M2 Squid parity — [notes](releases/v0.3.0.md) · [CHANGELOG](../CHANGELOG.md) |
| 0.2.3-test | test pre-release | M2 partial (L2, HTTP/2, compression) — [notes](releases/v0.2.3-test.md) |
| 0.2.2b | beta | Иерархический кеш, optional MITM CA — [GitHub Releases](https://github.com/onixus/bsdm-proxy/releases/tag/v0.2.2b) |

**Новое в 0.3.0:** Hierarchy Phase 4 (discovery, digest, HTCP), NTLM/Kerberos, LDAP group enrichment, REST ACL API, negative caching.
