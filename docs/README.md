# Документация BSDM-Proxy

Каноническая документация проекта хранится в `README.md` и каталоге `docs/`.
GitHub Wiki является автоматически обновляемым зеркалом этих файлов.

Перед использованием опциональной функции проверьте
[матрицу зрелости](project-status.md).

## Начало работы

| Документ | Назначение |
|---|---|
| [Deployment](getting-started/deployment.md) | Docker Compose, native package и Kubernetes |
| [Пилот на 100 пользователей](getting-started/pilot-deployment.md) | 12 vCPU / 24 GiB / 200 GB, хранение до 5 суток |
| [Lite mode](getting-started/lite-mode.md) | Proxy + SQLite без Kafka/ClickHouse |
| [Configuration](ops-and-dev/configuration.md) | Основные переменные окружения |

## Архитектура

| Документ | Назначение |
|---|---|
| [Overview](architecture/overview.md) | Компоненты, request path и data flow |
| [Capacity planning](architecture/capacity-planning.md) | Формулы, пилотный профиль и масштабирование |
| [Performance](architecture/performance.md) | Benchmarks и production tuning |
| [Hierarchy](architecture/hierarchical-caching.md) | L1/L2, ICP, HTCP и peer selection |
| [Repository structure](architecture/structure.md) | Cargo workspace и инфраструктура |

## Функции proxy

| Документ | Зрелость |
|---|---|
| [Authentication](features/authentication.md) | Basic — основной; LDAP/NTLM/Kerberos — beta |
| [ACL](features/acl-policy.md) | основной |
| [Categorization](features/categorization.md) | основной/beta по источнику |
| [Control plane](features/control-plane.md) | REST — основной; gRPC — beta |
| [Semantic cache](features/semantic-cache.md) | beta |
| [DNS sinkhole, DoH, DoT](features/dns-sinkhole.md) | beta |
| [WASM plugins](features/wasm-plugins.md) | experimental |
| [ICAP](features/icap-inspection.md) | experimental |

## Аналитика и detection

| Документ | Назначение |
|---|---|
| [ClickHouse retro-search](analytics/clickhouse-retrosearch.md) | Схема, ingest и Search API |
| [Threat alerting](analytics/alerting.md) | alert-worker и SIEM webhook |
| [ML security](analytics/ml-security.md) | Features, models и write-back |

## Эксплуатация и разработка

| Документ | Назначение |
|---|---|
| [Kubernetes](ops-and-dev/k8s-architecture.md) | Helm и разделение data/analytics plane |
| [Logging and metrics](ops-and-dev/logging.md) | Логи, Prometheus и диагностика |
| [Benchmarks](ops-and-dev/benchmarks.md) | Методика и опубликованные результаты |
| [Development](ops-and-dev/development.md) | Build, test и release workflow |
| [Licensing](ops-and-dev/licensing.md) | Third-party licenses |
| [Documentation maintenance](maintenance.md) | Правила обновления и Wiki sync |

## Архитектурные решения и история

- [ADR 0001: Tiered sharded L1](adr/0001-tiered-sharded-l1-cache.md)
- [ADR 0002: ClickHouse analytics](adr/0002-clickhouse-analytics.md)
- [ADR 0003: ML feature store](adr/0003-ml-worker-feature-store.md)
- [ADR 0004: DNS sinkhole](adr/0004-dns-sinkhole-sidecar.md)
- [Roadmap](roadmap.md)
- [Release notes](releases/)

Исторические release notes сохраняют версии и ограничения соответствующего
релиза. Их не следует использовать как актуальную deployment-инструкцию.

## По ролям

- **Пилот / DevOps:** Pilot deployment → Configuration → Logging → Capacity.
- **Security / SOC:** Project status → ClickHouse → Alerting → ML.
- **Разработчик:** Architecture → Repository structure → Development.

## Правила

1. Код и `proxy/Cargo.toml` определяют текущую версию и доступные параметры.
2. `project-status.md` определяет зрелость функций.
3. Roadmap описывает планы, но не подтверждает production readiness.
4. Изменения в Wiki вносятся через канонические файлы этого каталога.
