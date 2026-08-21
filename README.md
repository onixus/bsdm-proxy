# BSDM-Proxy

[![Build Status](https://github.com/onixus/bsdm-proxy/actions/workflows/rust.yml/badge.svg)](https://github.com/onixus/bsdm-proxy/actions/workflows/rust.yml)
[![E2E Tests](https://github.com/onixus/bsdm-proxy/actions/workflows/e2e.yml/badge.svg)](https://github.com/onixus/bsdm-proxy/actions/workflows/e2e.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.9.13-blue.svg)](https://github.com/onixus/bsdm-proxy/releases)

BSDM-Proxy — кеширующий HTTP/HTTPS forward proxy на Rust с MITM TLS,
аутентификацией, ACL, категоризацией, аналитикой трафика и опциональными
security-модулями.

Текущая версия workspace: **`0.9.13`**.

> Проект содержит функции разной зрелости. Перед развёртыванием прочитайте
> [матрицу статуса](docs/project-status.md): наличие кода или UI не означает
> production-ready.

> HTTPS MITM допустим только в управляемой среде, с информированием пользователей,
> контролем доступа к CA key и соблюдением применимого законодательства.

## Основные возможности

| Область | Возможности |
|---|---|
| Proxy | HTTP forward proxy, CONNECT, HTTPS MITM, HTTP/2 upstream |
| Кеш | Sharded L1, mmap spill, compression, revalidation, Redis L2, hierarchy |
| Политики | Basic/LDAP/NTLM/Kerberos auth, ACL, categorization, rate limiting |
| Аналитика | Kafka, cache-indexer, ClickHouse, Search API, Grafana |
| Detection | alert-worker, UEBA/phishing/beacon ML, threat-score write-back |
| Threat Intel | threat-intel (scheduled IOC collection: OpenPhish, PhishStats, Phishing.Database, URLhaus) |
| Extensions | DNS sinkhole/DoH/DoT, semantic cache, WASM, ICAP, AWG |
| Operations | REST/gRPC control plane, Prometheus, Helm, systemd packaging, interactive installer |
| Operator UI | Admin Console at `/admin/` (single supported UI) |

Большинство optional/experimental-компонентов выключено по умолчанию. Исключения,
включая встроенные DLP-паттерны, перечислены в
[ограничениях](docs/project-status.md#известные-ограничения).

## Архитектура

```mermaid
flowchart LR
    Client["Клиент"] --> Proxy["BSDM-Proxy"]
    Proxy --> Upstream["Upstream"]
    Proxy --> Kafka["Kafka"]
    Kafka --> Indexer["cache-indexer"]
    Indexer --> CH[("ClickHouse")]
    Proxy --> Prom["Prometheus"]
    CH --> Grafana["Grafana"]
    Prom --> Grafana
```

Основные порты:

| Компонент | Порт | Назначение |
|---|---:|---|
| proxy | 3128 | HTTP proxy / CONNECT |
| proxy control | 9090 | `/health`, `/ready`, `/metrics`, REST control API, `/admin/` |
| cache-indexer | 8080 | `/health`, `/metrics`, `/api/search` |
| alert-worker | 8090 | `/health`, `/metrics` |
| ml-worker | 8091 | `/health`, `/metrics` |
| dns-sinkhole | 8092 | `/health`, `/metrics` (DNS on 5353/udp) |
| threat-intel | 8093 | `/health`, `/metrics` (feed collector) |
| ICP | 3130/udp | cache hierarchy, opt-in |
| Kafka | 9092 | cache events |
| ClickHouse | 8123 / 9000 | HTTP / native |
| Prometheus | 9091 | compose UI |
| Grafana | 3000 | dashboards |

Подробности: [архитектура](docs/architecture/overview.md) и
[структура репозитория](docs/architecture/structure.md).

## Быстрый старт

### Интерактивная установка

```bash
./install.sh
```

### Lite: proxy + SQLite

Подходит для локальной разработки и проверки MITM без Kafka/ClickHouse:

```bash
./scripts/gen-ca.sh
docker compose -f deploy/compose/docker-compose.lite.yml up -d --build

curl http://127.0.0.1:9090/health
curl --cacert certs/ca.crt \
  -x http://127.0.0.1:3128 \
  https://httpbin.org/get
curl 'http://127.0.0.1:8080/api/search?limit=5'
```

Подробнее: [Lite mode](docs/getting-started/lite-mode.md).

### Analytics stack

```bash
./scripts/gen-ca.sh
docker compose up -d --build
docker compose ps
```

Команда запускает proxy, Kafka, Zookeeper, ClickHouse, cache-indexer,
Prometheus, Alertmanager и Grafana. Дополнительные профили:

```bash
docker compose --profile threat-intel up -d --build
docker compose --profile alerts --profile ml up -d --build
docker compose --profile dns-sinkhole up -d --build
docker compose --profile icap up -d
```

Это не означает, что все optional-функции включены и сконфигурированы. См.
[deployment guide](docs/getting-started/deployment.md).

### Пилот на 100 пользователей

Референс для пилота без DLP, reverse proxy, ICAP, ClamAV и HA, с хранением до
5 суток:

- **12 vCPU**;
- **24 GiB RAM**;
- **200 GB NVMe**;
- **1 Gbit/s** network.

Расчёт, TTL и критерии приёмки:
[Pilot deployment](docs/getting-started/pilot-deployment.md).
Готовые Compose overrides находятся в `deploy/compose/docker-compose.pilot.yml`.

## Сборка

Требования:

- Rust stable, совместимый с зависимостями workspace;
- `libssl-dev`, `pkg-config`, `cmake`, `librdkafka-dev`, `libclang-dev`.

```bash
cargo build --release --workspace
```

Основные Cargo features proxy:

| Feature | Назначение |
|---|---|
| `kafka` | Kafka event pipeline, включён по умолчанию |
| `auth-ldap`, `auth-ntlm`, `auth-kerberos` | дополнительные auth backend |
| `grpc` | gRPC control plane |
| `wasm` | Wasmtime request hook |

Lite build:

```bash
cargo build --release \
  -p bsdm-proxy --bin proxy \
  --no-default-features --features auth-basic
```

## Проверки

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
python3 scripts/check-doc-links.py
```

E2E:

```bash
./scripts/run-smoke-tests.sh
./scripts/run-e2e-tests.sh
```

Подробности: [Development guide](docs/ops-and-dev/development.md).

## Документация

| Документ | Назначение |
|---|---|
| [GitHub Wiki](https://github.com/onixus/bsdm-proxy/wiki) | Навигация, тематические хабы и зеркала канонических страниц |
| [Documentation index](docs/README.md) | Полная карта документации |
| [Project status](docs/project-status.md) | Зрелость и ограничения функций |
| [Agent contract](docs/architecture/agent-contract.md) | Протокол взаимодействия локального агента v0.1 |
| [ADR 0005: Hybrid Policy Agent](docs/adr/0005-local-policy-agent-vs-tunnel-first.md) | Архитектурное решение гибридной фильтрации |
| [ADR 0006: Single Operator Console](docs/adr/0006-single-operator-console.md) | Единая поддерживаемая операторская UI |
| [Pilot deployment](docs/getting-started/pilot-deployment.md) | 100 пользователей, TTL 5 дней |
| [Capacity planning](docs/architecture/capacity-planning.md) | Формулы и масштабирование |
| [Configuration](docs/ops-and-dev/configuration.md) | Переменные окружения |
| [CA lifecycle](docs/ops-and-dev/ca-lifecycle.md) | Хранение, ротация и аварийный отзыв MITM CA |
| [Architecture](docs/architecture/overview.md) | Компоненты и потоки |
| [Roadmap](docs/roadmap.md) | Стратегия развития |
| [Documentation maintenance](docs/maintenance.md) | Правила и Wiki sync |

Wiki генерируется из `docs/`; изменения в сгенерированные страницы напрямую не
вносятся.

## Лицензия

[MIT License](LICENSE). Состав и лицензии сторонних компонентов:
[NOTICE](NOTICE) и [licensing](docs/ops-and-dev/licensing.md).
