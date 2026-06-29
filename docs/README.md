# Документация BSDM-Proxy

Оглавление документации проекта.

## Начало работы

| Документ | Описание |
|----------|----------|
| [README.md](../README.md) | Обзор, быстрый старт, конфигурация |
| [packaging/README.md](../packaging/README.md) | Установка из release-пакета |
| [development.md](development.md) | Сборка, тесты, CI, релиз |

## Функциональность

| Документ | Описание |
|----------|----------|
| [authentication.md](authentication.md) | Аутентификация прокси (Basic, LDAP, NTLM) |
| [acl.md](acl.md) | Списки контроля доступа (ACL) |
| [categorization.md](categorization.md) | Категоризация URL и threat intelligence |

## Архитектура и roadmap

| Документ | Описание |
|----------|----------|
| [roadmap.md](roadmap.md) | **Roadmap и milestones** (Squid + ретропоиск + ML) |
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
| [packaging/config/bsdm-proxy.env.example](../packaging/config/bsdm-proxy.env.example) | Переменные окружения proxy |
| [prometheus/prometheus.yml](../prometheus/prometheus.yml) | Scrape config для Prometheus |
| [grafana/dashboards/bsdm-proxy.json](../grafana/dashboards/bsdm-proxy.json) | Grafana dashboard |

## Версии

Текущая beta-версия: **0.2.2b** — [GitHub Releases](https://github.com/onixus/bsdm-proxy/releases)
