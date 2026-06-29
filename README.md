# BSDM-Proxy

**B**usiness **S**ecure **D**ata **M**onitoring Proxy

Высокопроизводительный кеширующий HTTPS-прокси на [Hyper](https://hyper.rs/) с [quick_cache](https://crates.io/crates/quick_cache), MITM TLS, аутентификацией, ACL и интеграцией с Kafka, OpenSearch, Prometheus и Grafana.

[![Build Status](https://github.com/onixus/bsdm-proxy/actions/workflows/rust.yml/badge.svg)](https://github.com/onixus/bsdm-proxy/actions/workflows/rust.yml)
[![E2E Tests](https://github.com/onixus/bsdm-proxy/actions/workflows/e2e.yml/badge.svg)](https://github.com/onixus/bsdm-proxy/actions/workflows/e2e.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.2.2b-blue.svg)](https://github.com/onixus/bsdm-proxy/releases/tag/v0.2.2b)
[![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org)

> **Текущая версия:** `0.2.2b` (beta) — см. [Releases](https://github.com/onixus/bsdm-proxy/releases)

⚠️ **MITM-прокси для HTTPS.** Используйте только в корпоративной среде с согласия пользователей и в рамках законодательства.

## Возможности

| Область | Возможности |
|---------|-------------|
| **Прокси** | HTTP/HTTPS forward proxy, MITM TLS (порты 443/8443), HTTP CONNECT, кеш L1 |
| **Безопасность** | Proxy-аутентификация (Basic / LDAP / NTLM), ACL, категоризация URL |
| **Наблюдаемость** | Prometheus (20+ метрик), Grafana, `/health`, `/ready`, `/metrics` |
| **Аналитика** | Kafka → cache-indexer → OpenSearch |
| **Эксплуатация** | Graceful shutdown, настраиваемые порты, release-пакет + systemd |

## Архитектура

```
┌─────────┐         ┌──────────────────────────┐         ┌──────────────┐
│ Клиент  │◄───────►│  BSDM-Proxy              │◄───────►│   Upstream   │
│         │  HTTPS  │  Auth → ACL → Cache      │  HTTPS  │    Server    │
└─────────┘         └────────────┬─────────────┘         └──────────────┘
                                 │
                        :9090 /metrics
                    ┌────────────┴────────────┐
             ┌──────▼──────┐           ┌──────▼──────┐
             │ quick_cache │           │   Kafka     │
             │   (L1)      │           │  (async)    │
             └─────────────┘           └──────┬──────┘
                                              │
                    ┌─────────────────────────┼─────────────────┐
             ┌──────▼─────────┐        ┌──────▼──────┐   ┌──────▼──────┐
             │ Cache-Indexer  │        │ Prometheus  │   │  Grafana    │
             └──────┬─────────┘        └─────────────┘   └─────────────┘
             ┌──────▼─────────┐
             │  OpenSearch    │
             └────────────────┘
```

## Компоненты

| Компонент | Порт | Описание |
|-----------|------|----------|
| **proxy** | 1488 | HTTPS-прокси, MITM, кеш, метрики |
| **metrics** | 9090 | `/health`, `/ready`, `/metrics` |
| **cache-indexer** | — | Kafka → OpenSearch |
| **Kafka** | 9092 | Очередь событий кеша |
| **OpenSearch** | 9200 | Поиск и аналитика |
| **Prometheus** | 9091 | Сбор метрик |
| **Grafana** | 3000 | Дашборды (`admin` / `admin`) |

## Быстрый старт (Docker)

### 1. CA для MITM

```bash
mkdir -p certs && cd certs
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=RU/ST=Moscow/L=Moscow/O=BSDM/CN=BSDM Root CA"
cd ..
```

### 2. Запуск стека

```bash
docker compose up -d
docker compose ps
```

### 3. Доверие клиенту к CA

**Linux:**
```bash
sudo cp certs/ca.crt /usr/local/share/ca-certificates/bsdm-ca.crt
sudo update-ca-certificates
```

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain certs/ca.crt
```

### 4. Проверка

```bash
curl -x http://localhost:1488 https://httpbin.org/get
curl http://localhost:9090/health
curl http://localhost:9090/metrics | grep bsdm_proxy
```

## Установка (native package)

Сборка пакета из исходников:

```bash
./scripts/build-package.sh
```

Архив: `dist/bsdm-proxy-0.2.2b-linux-<arch>.tar.gz`

Установка:

```bash
tar xzf dist/bsdm-proxy-0.2.2b-linux-x86_64.tar.gz
cd bsdm-proxy-0.2.2b-linux-x86_64
sudo ./install.sh --create-user --systemd
sudo cp certs/ca.key certs/ca.crt /certs/
sudo systemctl start bsdm-proxy
```

Подробнее: [packaging/README.md](packaging/README.md)

## Сборка из исходников

```bash
# Зависимости (Debian/Ubuntu)
sudo apt-get install -y libssl-dev pkg-config cmake librdkafka-dev libclang-dev

cargo build --release -p bsdm-proxy --bin proxy -p cache-indexer --bin cache-indexer
```

Бинарники: `target/release/proxy`, `target/release/cache-indexer`

## Конфигурация

### Proxy — основные переменные

| Переменная | По умолчанию | Описание |
|-----------|-------------|----------|
| `HTTP_PORT` | `1488` | Порт прокси |
| `METRICS_PORT` | `9090` | Порт health/metrics |
| `MITM_ENABLED` | `true` | MITM для портов 443 и 8443 |
| `KAFKA_BROKERS` | — | Kafka (опционально) |
| `CACHE_CAPACITY` | `10000` | Размер L1-кеша |
| `CACHE_TTL_SECONDS` | `3600` | TTL кеша (сек) |
| `MAX_CACHE_BODY_SIZE` | `10485760` | Макс. размер body (байт) |
| `SHUTDOWN_TIMEOUT_SECONDS` | `30` | Таймаут graceful shutdown |
| `UPSTREAM_CA_CERT` | — | PEM самоподписанного CA для upstream TLS (тесты/lab) |
| `RUST_LOG` | `info` | Уровень логов |

CA для MITM читается из `/certs/ca.key` и `/certs/ca.crt` (fallback: `./certs/`).

### Аутентификация

| Переменная | Описание |
|-----------|----------|
| `AUTH_ENABLED` | `true` / `false` |
| `AUTH_BACKEND` | `basic`, `ldap`, `ntlm` |
| `AUTH_REALM` | Realm для `Proxy-Authenticate` |
| `AUTH_CACHE_TTL` | TTL кеша сессий (сек) |

→ [docs/authentication.md](docs/authentication.md)

### ACL и категоризация

| Переменная | Описание |
|-----------|----------|
| `ACL_ENABLED` | Включить ACL |
| `ACL_DEFAULT_ACTION` | `allow`, `deny`, `redirect` |
| `ACL_RULES_PATH` | Путь к JSON с правилами |
| `ACL_AUTO_RELOAD` | Автоперезагрузка правил |
| `ACL_RELOAD_INTERVAL` | Интервал перезагрузки (сек) |
| `CATEGORIZATION_ENABLED` | Категоризация URL |
| `SHALLALIST_PATH` | Путь к Shallalist |
| `CUSTOM_DB_PATH` | Пользовательская БД категорий |

Пример правил: [config/acl-rules.example.json](config/acl-rules.example.json)

→ [docs/acl.md](docs/acl.md) · [docs/categorization.md](docs/categorization.md)

### Cache-indexer

| Переменная | По умолчанию | Описание |
|-----------|-------------|----------|
| `KAFKA_BROKERS` | `kafka:9092` | Брокеры Kafka |
| `KAFKA_TOPIC` | `cache-events` | Топик |
| `KAFKA_GROUP_ID` | `cache-indexer-group` | Consumer group |
| `OPENSEARCH_URL` | `http://opensearch:9200` | URL OpenSearch |

## Мониторинг

### Endpoints

| URL | Ответ |
|-----|-------|
| `GET /health` | `{"status":"ok"}` |
| `GET /ready` | `{"status":"ready"}` или `draining` при shutdown |
| `GET /metrics` | Prometheus text format |

### Примеры PromQL

```promql
# Cache hit rate
bsdm_proxy_cache_hits_total /
  (bsdm_proxy_cache_hits_total + bsdm_proxy_cache_misses_total)

# P95 latency
histogram_quantile(0.95,
  rate(bsdm_proxy_request_duration_seconds_bucket[5m])
)
```

Grafana: http://localhost:3000 → **BSDM Proxy Dashboard** (7 панелей, auto-provisioned).

## Тестирование

Перед push: `./scripts/pre-push-check.sh` (или `./scripts/install-git-hooks.sh` для auto hook).

```bash
# Unit + integration (workspace)
cargo test --workspace

# Smoke (health, metrics, HTTP forward)
./scripts/run-smoke-tests.sh

# E2E (auth, ACL, cache, MITM, CONNECT)
./scripts/run-e2e-tests.sh

# Docker test stack
docker compose -f docker-compose.test.yml up -d
./scripts/run-smoke-tests.sh --external
```

CI: [rust.yml](.github/workflows/rust.yml) (fmt, clippy, build, test) и [e2e.yml](.github/workflows/e2e.yml).

→ [docs/development.md](docs/development.md)

## Документация

| Документ | Содержание |
|----------|------------|
| [docs/README.md](docs/README.md) | Оглавление документации |
| [docs/authentication.md](docs/authentication.md) | LDAP, NTLM, Basic Auth |
| [docs/acl.md](docs/acl.md) | Правила доступа, приоритеты |
| [docs/categorization.md](docs/categorization.md) | Shallalist, URLhaus, PhishTank |
| [docs/architecture.md](docs/architecture.md) | Архитектура и блокеры |
| [docs/roadmap.md](docs/roadmap.md) | Roadmap и milestones |
| [packaging/README.md](packaging/README.md) | Release-пакет и systemd |
| [OPTIMIZATIONS.md](OPTIMIZATIONS.md) | Оптимизации v2.0 |
| [docker-compose.yml](docker-compose.yml) | Полный стек |

## Roadmap

Цель: **альтернатива Squid с ретропоиском и ML** для аномалий, фишинга и C&C.

Полный план: **[docs/roadmap.md](docs/roadmap.md)**

| Milestone | Версия | Фокус | Статус |
|-----------|--------|-------|--------|
| **M1** Foundation | v0.2.x | Прокси, ACL, категоризация, observability | ~90% |
| **M2** Squid parity | v0.3.x | Иерархия, L2, rate limit, полный ACL | Planned |
| **M3** Retro-search | v0.4.x | OpenSearch dashboards, поиск по истории | Planned |
| **M4** Threat analytics | v0.5.x | Rule-based алерты, C&C heuristics | Planned |
| **M5** ML security | v1.0.x | ML anomaly, phishing, C&C detection | Planned |

### M1 — Foundation (v0.2.x, текущий)

- [x] Prometheus + Grafana + health checks
- [x] Graceful shutdown
- [x] Proxy authentication (Basic / LDAP; NTLM — в backlog M2)
- [x] ACL + URL categorization
- [x] E2E / smoke test harness
- [x] Release packaging (`0.2.2b`)
- [ ] Rate limiting per user/IP
- [ ] Hierarchical caching — Phase 3 integration

### M2 — Squid parity (v0.3.x)

- [ ] Redis L2 cache
- [ ] HTTP/2 upstream client
- [ ] Compression (Brotli/Zstd)
- [ ] ACL TimeWindow + group rules
- [ ] NTLM auth
- [ ] Hierarchy Phase 4 (discovery, digest, HTCP)

### M3–M5

- [ ] **M3:** индексация threat-полей, OpenSearch Dashboards, saved searches
- [ ] **M4:** rule-based anomaly alerts, C&C beacon heuristics, SIEM export
- [ ] **M5:** ML pipeline, anomaly/phishing/C&C models

## Лицензия

MIT License — Copyright (c) 2025 BSDM-Proxy Contributors

---

**Disclaimer:** Используйте только в легальных целях с согласия всех сторон.
