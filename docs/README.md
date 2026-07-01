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

## Функциональность

| Документ | Описание |
|----------|----------|
| [authentication.md](authentication.md) | Аутентификация прокси (Basic, LDAP; NTLM — backlog) |
| [acl.md](acl.md) | Списки контроля доступа (ACL) |
| [categorization.md](categorization.md) | Категоризация URL и threat intelligence |

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
| [docker-compose.yml](../docker-compose.yml) | Полный стек (proxy, Kafka, OpenSearch, monitoring) |
| [docker-compose.test.yml](../docker-compose.test.yml) | Минимальный стек для smoke-тестов |
| [OPENSEARCH_UPGRADE.md](../OPENSEARCH_UPGRADE.md) | Обновление OpenSearch |
| [web-config/README.md](../web-config/README.md) | Web UI для генерации конфигурации |

## Конфигурационные файлы

| Файл | Назначение |
|------|------------|
| [config/acl-rules.example.json](../config/acl-rules.example.json) | Пример ACL-правил |
| [config/acl-rules.test.json](../config/acl-rules.test.json) | ACL для тестового compose |
| [packaging/config/bsdm-proxy.env.example](../packaging/config/bsdm-proxy.env.example) | Переменные окружения proxy |
| [prometheus/prometheus.yml](../prometheus/prometheus.yml) | Scrape config для Prometheus |
| [grafana/dashboards/bsdm-proxy.json](../grafana/dashboards/bsdm-proxy.json) | Grafana dashboard |

## Версии и тесты

| Параметр | Значение |
|----------|----------|
| Версия в Cargo | `0.2.3-test` |
| Последний release tag | `0.2.2b` |
| Rust (минимум) | `1.88+` |
| Тестов в workspace | 75 (`cargo test --workspace --all-targets`) |
| OpenSearch в compose | `3.7.0` |

**Новое в dev (`0.2.3-test`):** документация deployment/docker/k8s, исправлен Dockerfile (workspace `e2e`, Rust stable), актуализированы блокеры B11/B17.

**В `0.2.2b`:** иерархический кеш (ICP + peer fetch), optional MITM CA, pre-push hook.

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
