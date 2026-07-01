# Структура репозитория

Актуальная карта каталогов BSDM-Proxy v0.3.1.

## Cargo workspace

| Крейт | Путь | Назначение |
|-------|------|------------|
| `bsdm-proxy` | `proxy/` | HTTPS forward proxy (MITM, cache, auth, ACL, Kafka producer) |
| `cache-indexer` | `cache-indexer/` | Kafka consumer → ClickHouse, Search API, `/metrics` |
| `bsdm-events` | `bsdm-events/` | Общие типы событий (`CacheEvent`) для proxy и indexer |
| `e2e` | `e2e/` | Smoke и E2E тесты (subprocess proxy + mock upstream) |

Корневой [`Cargo.toml`](../Cargo.toml) объявляет workspace и shared dependencies.

## Дерево каталогов

```
bsdm-proxy/
├── proxy/                  # Основной прокси
│   └── src/
│       ├── main.rs         # HTTP server, cache, Kafka
│       ├── lib.rs          # acl, auth, categorization, hierarchy, icp, peers
│       ├── peer_fetch.rs, hierarchy_config.rs, cache_key.rs
│       └── tls.rs, metrics.rs, policy_config.rs
├── cache-indexer/          # Kafka → ClickHouse indexer + Search API
├── bsdm-events/            # Shared event schema
├── e2e/                    # Integration tests
├── charts/bsdm/            # Helm chart (K8s proxy Deployment)
├── config/                 # Примеры ACL-правил
├── packaging/              # Release tarball, systemd units, install.sh
├── scripts/                # build-package, pre-push-check, clickhouse SQL
├── docs/                   # Wiki / документация
├── grafana/                # Provisioning: datasources + dashboards
├── prometheus/             # Scrape config
├── web-config/             # Web UI для генерации .env / compose
├── certs/                  # MITM CA (gitignored, генерируется локально)
├── Dockerfile              # Multi-stage: proxy + cache-indexer targets
├── docker-compose.yml      # Полный стек (proxy, Kafka, ClickHouse, monitoring)
├── docker-compose.*.yml    # Профили: test, redis-l2, hierarchy, ha
└── AGENTS.md               # Инструкции для Cursor Cloud Agent
```

## Docker Compose профили

| Файл | Сервисы |
|------|---------|
| `docker-compose.yml` | proxy, cache-indexer, kafka, zookeeper, clickhouse, prometheus, grafana |
| `docker-compose.test.yml` | Минимальный стек для smoke/E2E |
| `docker-compose.redis-l2.yml` | 2× proxy + Redis L2 |
| `docker-compose.hierarchy.yml` | Multi-instance + ICP |
| `docker-compose.ha.yml` | HA lab sketch |

## Инфраструктура и конфигурация

| Путь | Назначение |
|------|------------|
| `grafana/datasources.yml` | Prometheus + ClickHouse datasources |
| `grafana/dashboards/` | Proxy metrics + HTTP Traffic (ClickHouse) |
| `scripts/clickhouse/http_cache.sql` | Схема `bsdm.http_cache` |
| `packaging/config/*.env.example` | Примеры env для native install |
| `config/acl-rules.*.json` | Примеры ACL |

## CI и автоматизация

| Путь | Назначение |
|------|------------|
| `.github/workflows/` | CI: build, test, clippy, release |
| `.githooks/pre-push` | fmt + clippy перед push |
| `scripts/pre-push-check.sh` | Локальная проверка перед push |

## Удалённые / устаревшие компоненты

Следующие элементы **удалены** в v0.3.0–v0.3.1:

| Было | Замена |
|------|--------|
| OpenSearch backend | ClickHouse (`bsdm.http_cache`) |
| `docker-compose.clickhouse.yml` | ClickHouse в основном `docker-compose.yml` |
| `grafana/clickhouse/` (дубликат) | `grafana/dashboards/` + `grafana/datasources.yml` |
| `README.md_old`, `SDBM/` | — |
| `.github/issue-bodies/ch-*.md` | Миграция завершена ([#125](https://github.com/onixus/bsdm-proxy/issues/125)) |

См. [ADR 0002](adr/0002-clickhouse-analytics.md) · [clickhouse-analytics.md](clickhouse-analytics.md) · [licensing.md](licensing.md)
