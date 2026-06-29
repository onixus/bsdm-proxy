# Документация BSDM-Proxy

Оглавление документации проекта.

## Начало работы

| Документ | Описание |
|----------|----------|
| [README.md](../README.md) | Обзор, быстрый старт, конфигурация |
| [packaging/README.md](../packaging/README.md) | Установка из release-пакета |
| [development.md](development.md) | Сборка, тесты, CI, релиз |
| [releases/v0.2.3-test.md](releases/v0.2.3-test.md) | **Release notes 0.2.3-test** |

## Функциональность

| Документ | Описание |
|----------|----------|
| [authentication.md](authentication.md) | Аутентификация прокси (Basic, LDAP; NTLM — M2) |
| [logging.md](logging.md) | Логирование (`RUST_LOG`, уровни, troubleshooting) |
| [acl.md](acl.md) | Списки контроля доступа (ACL) |
| [categorization.md](categorization.md) | Категоризация URL и threat intelligence |

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
| [docker-compose.yml](../docker-compose.yml) | Полный стек (proxy, Kafka, OpenSearch, monitoring) |
| [docker-compose.test.yml](../docker-compose.test.yml) | Минимальный стек для smoke-тестов |
| [docker-compose.redis-l2.yml](../docker-compose.redis-l2.yml) | Демо Redis L2 (2 proxy + Redis) |
| [OPENSEARCH_UPGRADE.md](../OPENSEARCH_UPGRADE.md) | Обновление OpenSearch |
| [web-config/README.md](../web-config/README.md) | Web UI для генерации конфигурации |

## Конфигурационные файлы

| Файл | Назначение |
|------|------------|
| [config/acl-rules.example.json](../config/acl-rules.example.json) | Пример ACL-правил |
| [packaging/config/bsdm-proxy.env.example](../packaging/config/bsdm-proxy.env.example) | Переменные окружения proxy |
| [prometheus/prometheus.yml](../prometheus/prometheus.yml) | Scrape config для Prometheus |
| [grafana/dashboards/bsdm-proxy.json](../grafana/dashboards/bsdm-proxy.json) | Grafana dashboard |

## Версии

| Версия | Тип | Описание |
|--------|-----|----------|
| **0.2.3-test** | test pre-release | M2: L2 Redis, HTTP/2 upstream, at-rest compression — [notes](releases/v0.2.3-test.md) |
| 0.2.2b | beta | Иерархический кеш, optional MITM CA — [GitHub Releases](https://github.com/onixus/bsdm-proxy/releases/tag/v0.2.2b) |

**Новое в 0.2.3-test:** Redis L2, `UPSTREAM_HTTP2_ENABLED`, `CACHE_COMPRESSION` (zstd/brotli), ACL TimeWindow/group, rate limiting, `ProxyService` в lib.
