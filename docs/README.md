# Документация BSDM-Proxy (Wiki)

Центральное оглавление документации проекта. Все страницы wiki хранятся в каталоге `docs/` репозитория.

## Начало работы

| Документ | Описание |
|----------|----------|
| [README.md](../README.md) | Обзор проекта, быстрый старт, конфигурация |
| [deployment.md](deployment.md) | **Развёртывание:** Docker, native package, Kubernetes |
| [docker.md](docker.md) | Docker Compose, сборка образов, troubleshooting |
| [kubernetes.md](kubernetes.md) | Kubernetes: манифесты, probes, managed services |
| [packaging/README.md](../packaging/README.md) | Установка из release-пакета (systemd) |
| [development.md](development.md) | Сборка, тесты, CI, релиз |
| [structure.md](structure.md) | **Структура репозитория** |
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
| [architecture.md](architecture.md) | Архитектура, потоки данных, блокеры B1–B26 |
| [BLOCKERS.md](BLOCKERS.md) | Реестр блокеров (чеклист) |
| [roadmap.md](roadmap.md) | Roadmap и milestones (Squid + ретропоиск + ML) |
| [hierarchical-caching.md](hierarchical-caching.md) | Иерархический кеш, ICP, peer management |
| [HIERARCHICAL_CACHING_README.md](HIERARCHICAL_CACHING_README.md) | Краткий обзор hierarchical caching |
| [OPTIMIZATIONS.md](../OPTIMIZATIONS.md) | Оптимизации Hyper + quick_cache |

## Инфраструктура

| Документ | Описание |
|----------|----------|
| [docker-compose.yml](../docker-compose.yml) | Полный стек (proxy, Kafka, ClickHouse, monitoring) |
| [docker-compose.redis-l2.yml](../docker-compose.redis-l2.yml) | Демо Redis L2 (2 proxy + Redis) |
| [web-config/README.md](../web-config/README.md) | Web UI для генерации конфигурации |

## Конфигурационные файлы

| Файл | Назначение |
|------|------------|
| [config/acl-rules.example.json](../config/acl-rules.example.json) | Пример ACL-правил |
| [config/acl-rules.test.json](../config/acl-rules.test.json) | ACL для тестового compose |
| [packaging/config/bsdm-proxy.env.example](../packaging/config/bsdm-proxy.env.example) | Переменные окружения proxy |
| [prometheus/prometheus.yml](../prometheus/prometheus.yml) | Scrape config для Prometheus |
| [grafana/dashboards/bsdm-proxy.json](../grafana/dashboards/bsdm-proxy.json) | Grafana dashboard (Prometheus) |
| [grafana/dashboards/bsdm-http-traffic-ch.json](../grafana/dashboards/bsdm-http-traffic-ch.json) | Grafana HTTP Traffic (ClickHouse) |

## Версии и тесты

| Параметр | Значение |
|----------|----------|
| Текущая версия | **0.3.0** — [release notes](releases/v0.3.0.md) · [CHANGELOG](../CHANGELOG.md) |
| Rust (минимум) | `1.88+` |
| Тестов в workspace | `cargo test --workspace --all-targets` |
| Analytics backend | ClickHouse (`bsdm.http_cache`) |
| Helm chart | `charts/bsdm/` |

## Быстрые команды

```bash
# Сборка
cargo build --release -p bsdm-proxy --bin proxy

# Все тесты
cargo test --workspace --all-targets

# Docker полный стек
docker compose up -d --build

# Pre-push
./scripts/pre-push-check.sh
```
