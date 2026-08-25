# Документация BSDM-Proxy

Каноническая документация проекта хранится в `README.md` и каталоге `docs/`.
[GitHub Wiki](https://github.com/onixus/bsdm-proxy/wiki) предоставляет
автоматически обновляемую навигацию по этим файлам.

Перед использованием опциональной функции проверьте
[матрицу зрелости](project-status.md).

## Начало работы

| Документ | Назначение |
|---|---|
| [Deployment](getting-started/deployment.md) | Docker Compose, native package и Kubernetes |
| [Пилот Hybrid (100 users)](getting-started/pilot-deployment.md) | Selective MITM compose + acceptance checklist (#270) |
| [Pilot authentication](getting-started/pilot-auth.md) | Basic users file, smoke, OIDC out-of-scope note |
| [Pilot DNS sinkhole](getting-started/pilot-dns.md) | UDP first hop :5353, dig smoke, load-test DNS share |
| [Pilot alerts](getting-started/pilot-alerts.md) | decision_source UX + alert-worker pilot rule pack |
| [Pilot ML](getting-started/pilot-ml.md) | Одна модель, write-back и smoke test |
| [Pilot agent](getting-started/pilot-agent.md) | Phase C lab spike и приёмка |
| [Agent fleet](getting-started/pilot-agent-fleet.md) | MDM/GPO/Jamf packaging scaffolding |
| [BSDM Connect Client](getting-started/bsdm-connect-client.md) | Альтернативный клиент на Rust для AmneziaWG и BSDM |
| [Split Routing & Agent UI](getting-started/agent-ui-and-split-routing.md) | Разграничение маршрутов по доменам, PAC и мобильный UI |
| [Hybrid load-test profile](ops-and-dev/load-test-selective-mitm.md) | 100-user SNI/MITM/DNS probe + results archive (#269) |
| [Control plane security](ops-and-dev/control-plane-security.md) | Tokens, bind, network policy for pilot (#271) |
| [Backup & restore](ops-and-dev/backup-restore.md) | ClickHouse dumps + CA archive rollback drill |
| [Lite mode](getting-started/lite-mode.md) | Proxy + SQLite без Kafka/ClickHouse |
| [Configuration](ops-and-dev/configuration.md) | Основные переменные окружения |

## Архитектура

| Документ | Назначение |
|---|---|
| [Overview](architecture/overview.md) | Компоненты, request path и data flow |
| [Agent contract](architecture/agent-contract.md) | Спецификация взаимодействия локального агента v0.1 |
| [Capacity planning](architecture/capacity-planning.md) | Формулы, пилотный профиль и масштабирование |
| [Performance](architecture/performance.md) | Benchmarks и production tuning |
| [Hierarchy](architecture/hierarchical-caching.md) | L1/L2, ICP, HTCP и peer selection |
| [Repository structure](architecture/structure.md) | Cargo workspace и инфраструктура |

## Функции proxy

| Документ | Зрелость |
|---|---|
| [Authentication](features/authentication.md) | Basic/OIDC — основной; LDAP/NTLM/Kerberos — beta |
| [ACL](features/acl-policy.md) | основной |
| [ACL в Admin Console](features/acl-console.md) | Policies: категории vs домены |
| [Categorization](features/categorization.md) | основной/beta по источнику |
| [Control plane](features/control-plane.md) | REST — основной; gRPC — beta |
| [Certificate Pinning exceptions](features/certificate-pinning.md) | Управляемый bypass-реестр, reload и аудит |
| [Admin Console security](features/admin-console-security.md) | Trust boundaries и mutation token gate |
| [Semantic cache](features/semantic-cache.md) | beta |
| [DNS sinkhole, DoH, DoT](features/dns-sinkhole.md) | основной |
| [Threat intel collector](features/threat-intel-collector.md) | beta — мониторинг в Shadow Mode, без блокировки |
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
| [Control plane security](ops-and-dev/control-plane-security.md) | Tokens, bind и network policy |
| [Backup & restore](ops-and-dev/backup-restore.md) | ClickHouse и MITM CA rollback drill |
| [Pilot go / no-go](ops-and-dev/pilot-go-no-go-template.md) | Шаблон решения по итогам 4-й недели пилота |
| [CA lifecycle](ops-and-dev/ca-lifecycle.md) | Выпуск, ротация и отзыв CA |
| [Hybrid load test](ops-and-dev/load-test-selective-mitm.md) | Selective MITM, DNS и auth workload |
| [Load-test results](ops-and-dev/load-test-results/README.md) | Хранение и интерпретация отчётов |
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
- [ADR 0005: Local policy agent](adr/0005-local-policy-agent-vs-tunnel-first.md)
- [ADR 0006: One supported operator console](adr/0006-single-operator-console.md)
- [ADR 0007: Safe selective MITM & circuit breaker](adr/0007-mitm-circuit-breaker.md)
- [ADR 0008: Threat Intelligence Shadow Mode](adr/0008-threat-intel-shadow-mode.md)
- [Roadmap](roadmap.md)
- [Latest release notes (v0.9.13)](releases/v0.9.13.md)
- [Release history](releases/)

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
