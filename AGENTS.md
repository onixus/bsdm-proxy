# AGENTS.md

## Project Overview

BSDM-Proxy — высокопроизводительный корпоративный прокси-сервер (Secure Web Gateway),
написанный на Rust. Основные возможности: MITM TLS-инспекция, многоуровневое
кэширование (L1 in-memory / L2 Redis), ACL/policy engine, аутентификация
(Basic/LDAP/NTLM/Kerberos), Prometheus-метрики и опциональный аналитический пайплайн
Kafka → cache-indexer → ClickHouse. Дополнительные сервисы: `alert-worker` (вебхук-алерты),
`ml-worker` (UEBA-скоринг), `dns-sinkhole` (UDP RPZ-lite DNS-sайдкар).

## Workspace Crates

| Crate | Binary | Purpose |
|---|---|---|
| `proxy/` | `proxy` | Ядро прокси: HTTP/HTTPS forward proxy, MITM, auth, ACL, cache, events |
| `cache-indexer/` | `cache-indexer` | Kafka → SQLite/ClickHouse аналитический индексатор |
| `alert-worker/` | `alert-worker` | Обработка инцидентов ИБ, дедупликация, вебхук-рассылка |
| `ml-worker/` | `ml-worker` | ML feature-store скоринг (phishing, beacon detection, UEBA) |
| `dns-sinkhole/` | `dns-sinkhole` | UDP RPZ-lite DNS-сайдкар |
| `bsdm-events/` | *(lib)* | Shared `CacheEvent` и типы событий |
| `bsdm-wasm-sdk/` | *(lib)* | SDK для написания WASM-плагинов |
| `e2e/` | *(lib)* | End-to-end тестовый харнесс с in-process mock upstream |

### Inter-crate dependencies

```
proxy         → bsdm-events  (emits CacheEvent)
cache-indexer → bsdm-events  (consumes CacheEvent from Kafka)
ml-worker     → bsdm-events  (scoring input types)
alert-worker  → bsdm-events  (alert trigger types)
```

## Build & Run

### Quick commands (Makefile)

```bash
make setup        # Сгенерировать CA-сертификаты для MITM
make build        # cargo build --release --workspace
make run          # Запустить proxy локально (default features)
make run-lite     # Запустить proxy без Kafka
make test         # cargo test --workspace
make lint         # cargo fmt --all && cargo clippy ...
make docker-lite  # Docker Compose: proxy + SQLite Search API
make docker-full  # Docker Compose: полный стек (Kafka, CH, Prometheus, Grafana)
```

### Manual run

```bash
# Генерация CA (обязательно при MITM_ENABLED=true)
./scripts/gen-ca.sh

# Запуск proxy
HTTP_PORT=3128 METRICS_PORT=9090 cargo run -p bsdm-proxy --bin proxy

# Проверка
curl http://127.0.0.1:9090/health
curl -x http://127.0.0.1:3128 http://httpbin.org/get

# HTTPS через MITM
curl --cacert certs/ca.crt -x http://127.0.0.1:3128 https://httpbin.org/uuid
```

## Testing

- `cargo test --workspace` — запускает все юнит- и интеграционные тесты.
  Не требует Docker, Kafka или ClickHouse.
- E2E-харнесс (`e2e/src/lib.rs`) поднимает `proxy` как субпроцесс с in-process
  mock upstream. Требует outbound localhost networking.
- Для plain forward-proxy тестирования без MITM: `MITM_ENABLED=false`.
- Полный Docker-стек (`docker-compose.yml`) нужен только для end-to-end тестирования
  аналитического пайплайна и дашбордов.

## Environment

### Toolchain & system dependencies

- **Rust 1.85+** (Edition 2021). Более ранние версии не скомпилируют часть зависимостей.
- System packages (Linux): `libssl-dev pkg-config cmake librdkafka-dev libclang-dev`
  (см. `docs/ops-and-dev/development.md`).

### MITM certificates

При `MITM_ENABLED=true` (по умолчанию) требуются `./certs/ca.key` и `./certs/ca.crt`.
Они git-ignored и НЕ в репозитории — сгенерируй через `./scripts/gen-ca.sh`.
Для тестирования без MITM: `MITM_ENABLED=false`.

### Key environment variables

| Variable | Default | Description |
|---|---|---|
| `HTTP_PORT` | `3128` | Порт прокси |
| `METRICS_PORT` | `9090` | Порт Prometheus-метрик |
| `MITM_ENABLED` | `true` | Включить TLS MITM-инспекцию |
| `AUTH_ENABLED` | `false` | Включить аутентификацию |
| `AGENT_DEVICES_PATH` | — | JSON-файл для персистенции устройств |
| `REDIS_URL` | — | URL Redis для L2-кэша |

## Feature Flags

| Flag | Default | Enables |
|---|---|---|
| `auth-basic` | ✅ | Basic-аутентификация |
| `kafka` | ✅ | Kafka event pipeline (`pipeline.rs`) |
| `auth-ldap` | — | LDAP/AD backend (`auth/ldap.rs`) |
| `auth-ntlm` | — | NTLM handshake (`auth/basic.rs`) |
| `auth-kerberos` | — | Kerberos/SPNEGO (`auth/basic.rs`) |
| `auth-all` | — | Все auth-бэкенды |
| `grpc` | — | gRPC control plane (`control_grpc.rs`) |
| `wasm` | — | WASM plugin hooks (`proxy_service/icap_wasm.rs`) |
| `acl` | — | ACL engine |
| `categorization` | — | URL categorization (включает `acl`) |

## Repository Layout

```
proxy/          — ядро прокси-сервера
cache-indexer/  — Kafka → SQLite/ClickHouse индексатор
alert-worker/   — обработка инцидентов, вебхуки
ml-worker/      — ML-скоринг (UEBA, phishing, beacon)
dns-sinkhole/   — DNS RPZ-lite сайдкар
bsdm-events/    — shared event types (lib)
bsdm-wasm-sdk/  — SDK для WASM-плагинов (lib)
e2e/            — E2E тестовый харнесс
admin-console/  — веб-интерфейс администрирования (Vue/TypeScript)
trust-ui/       — UI доверенных сертификатов
web-config/     — легковесные страницы блокировки (vanilla HTML/CSS/JS)
docs/           — документация проекта
scripts/        — утилиты: бенчмарки, миграции, генерация сертификатов
charts/         — Helm-чарты для Kubernetes
grafana/        — дашборды и конфигурации алертинга
config/         — конфигурационные файлы
packaging/      — скрипты сборки Linux-пакетов
```
