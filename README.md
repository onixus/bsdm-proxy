# BSDM-Proxy

**B**usiness **S**ecure **D**ata **M**onitoring Proxy

Высокопроизводительный кеширующий HTTPS-прокси на [Hyper](https://hyper.rs/) с [quick_cache](https://crates.io/crates/quick_cache), MITM TLS, аутентификацией, ACL и интеграцией с Kafka, OpenSearch, Prometheus и Grafana.

[![Build Status](https://github.com/onixus/bsdm-proxy/actions/workflows/rust.yml/badge.svg)](https://github.com/onixus/bsdm-proxy/actions/workflows/rust.yml)
[![E2E Tests](https://github.com/onixus/bsdm-proxy/actions/workflows/e2e.yml/badge.svg)](https://github.com/onixus/bsdm-proxy/actions/workflows/e2e.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.3.0-blue.svg)](https://github.com/onixus/bsdm-proxy/releases)
[![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org)

> **Текущая версия:** `0.3.0` (релиз M2) · в разработке **M2.5** (data plane throughput) и **M3** (retro-search) — см. [Releases](https://github.com/onixus/bsdm-proxy/releases) · [CHANGELOG](CHANGELOG.md) · [roadmap](docs/roadmap.md)

⚠️ **MITM-прокси для HTTPS.** Используйте только в корпоративной среде с согласия пользователей и в рамках законодательства.

## Возможности

| Область | Возможности |
|---------|-------------|
| **Прокси** | HTTP/HTTPS forward proxy, MITM TLS (443/8443), HTTP CONNECT, **tiered L1** (inline + mmap spill, шарды), **streaming MISS**, Redis L2, **иерархический кеш** (ICP/HTCP), HTTP/2 upstream (опц.) |
| **Безопасность** | Proxy-auth (Basic / LDAP / NTLM / Kerberos), **connection-level auth cache**, ACL + REST API, **policy decision cache**, категоризация URL, rate limiting |
| **Производительность** | Multi-worker accept (`WORKER_COUNT`), perf fast path (`PERF_FAST_CACHE_HIT`), HTTP Archive bench profiles (`BENCH_PROFILE=warm\|cold`) |
| **Наблюдаемость** | Prometheus (20+ метрик), Grafana, `/health`, `/ready`, `/metrics` |
| **Аналитика** | Kafka → cache-indexer → OpenSearch (целевой store: ClickHouse) |
| **Эксплуатация** | Graceful shutdown, Helm chart `charts/bsdm/`, release-пакет + systemd |

## Архитектура

```
┌─────────┐         ┌──────────────────────────────────────┐         ┌──────────────┐
│ Клиент  │◄───────►│  BSDM-Proxy                          │◄───────►│   Upstream   │
│         │  HTTPS  │  Auth → ACL → L1 → [ICP → peer]      │  HTTPS  │    Server    │
└─────────┘         └────────────┬─────────────────────────┘         └──────────────┘
                                 │
                        :9090 /metrics
                    ┌────────────┴────────────┐
             ┌──────▼──────┐           ┌──────▼──────┐
             │ tiered L1   │           │   Kafka     │
             │ (shards +   │           │  (async)    │
             │ mmap spill) │           └──────┬──────┘
             └──────┬──────┘                  │
                    │ ICP :3130 (UDP)         │
             ┌──────▼──────┐                  │
             │ sibling /   │                  │
             │ parent peer │                  │
             └─────────────┘                  │
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
| **proxy** | 1488 | HTTPS-прокси, MITM, кеш L1, иерархия (опционально) |
| **ICP** | 3130 | UDP-запросы между cache peers (при `HIERARCHY_ENABLED=true`) |
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

Архив: `dist/bsdm-proxy-0.3.0-linux-<arch>.tar.gz`

Установка:

```bash
tar xzf dist/bsdm-proxy-0.3.0-linux-x86_64.tar.gz
cd bsdm-proxy-0.3.0-linux-x86_64
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
| `CACHE_CAPACITY` | `10000` | Размер L1-кеша (на шард) |
| `CACHE_SHARDS` | `16` | Число шардов L1 (`quick_cache` на шард) |
| `CACHE_SPILL_THRESHOLD_BYTES` | `262144` | Тела ≥ порога — в mmap spill (`0` = только inline) |
| `CACHE_SPILL_DIR` | `{tmp}/bsdm-cache-spill` | Каталог spill-файлов (dir `0o700`, files `0o600` на Unix) |
| `STREAMING_MISS_ENABLED` | `true` | Tee upstream MISS → client при записи в L1 |
| `CACHE_TTL_SECONDS` | `3600` | Fallback TTL кеша (сек), если нет `max-age` |
| `MAX_CACHE_BODY_SIZE` | `10485760` | Макс. размер body (байт) |
| `NEGATIVE_CACHE_ENABLED` | `true` | Кешировать upstream 403/404 |
| `NEGATIVE_CACHE_TTL_SECONDS` | `120` | TTL negative cache (сек) |
| `CACHE_HONOR_CACHE_CONTROL` | `true` | Учитывать `Cache-Control`, ETag, revalidate |
| `SHUTDOWN_TIMEOUT_SECONDS` | `30` | Таймаут graceful shutdown |
| `UPSTREAM_CA_CERT` | — | PEM самоподписанного CA для upstream TLS (тесты/lab) |
| `UPSTREAM_HTTP2_ENABLED` | `false` | HTTP/2 ALPN для upstream HTTPS |
| `CACHE_COMPRESSION` | `off` | At-rest сжатие кеша: `zstd`, `brotli`, `off` |
| `CACHE_COMPRESS_MIN_BYTES` | `1024` | Мин. размер body для сжатия в кеше |
| `CACHE_COMPRESS_ZSTD_LEVEL` | `3` | Уровень Zstd (1–22) |
| `RUST_LOG` | `info,bsdm_proxy=debug`¹ | Фильтр логов ([docs/logging.md](docs/logging.md)) |

CA для MITM читается из `/certs/ca.key` и `/certs/ca.crt` (fallback: `./certs/`).

¹ Если `RUST_LOG` не задана — fallback в коде; для production задайте `RUST_LOG=info,bsdm_proxy=info` (см. [docs/logging.md](docs/logging.md)).

### Аутентификация

| Переменная | Описание |
|-----------|----------|
| `AUTH_ENABLED` | `true` / `false` |
| `AUTH_BACKEND` | `basic` (default), `ldap` (`auth-ldap`), `ntlm` (`auth-ntlm`), `kerberos` (`auth-kerberos`) |
| `AUTH_REALM` | Realm для `Proxy-Authenticate` |
| `AUTH_CACHE_TTL` | TTL кеша сессий (сек) |
| `AUTH_CONN_CACHE_TTL_SECONDS` | `300` | Кеш успешной `Proxy-Authorization` на keep-alive TCP (`0` = выкл.) |

→ [docs/authentication.md](docs/authentication.md)

### ACL и категоризация

| Переменная | Описание |
|-----------|----------|
| `ACL_ENABLED` | Включить ACL |
| `ACL_DEFAULT_ACTION` | `allow`, `deny`, `redirect` |
| `ACL_RULES_PATH` | Путь к JSON с правилами |
| `ACL_AUTO_RELOAD` | Автоперезагрузка правил |
| `ACL_RELOAD_INTERVAL` | Интервал перезагрузки (сек) |
| `ACL_API_TOKEN` | Bearer-токен для REST API `/api/acl/*` (опционально) |
| `CATEGORIZATION_ENABLED` | Категоризация URL |
| `POLICY_DECISION_CACHE_TTL_SECONDS` | `120` | Кеш решений ACL+cat по `(principal, domain)` (`0` = выкл.) |
| `POLICY_DECISION_CACHE_MAX_KEYS` | `10000` | Макс. ключей policy cache |
| `SHALLALIST_PATH` | Путь к Shallalist |
| `CUSTOM_DB_PATH` | Пользовательская БД категорий |

Пример правил: [config/acl-rules.example.json](config/acl-rules.example.json)

→ [docs/acl.md](docs/acl.md) · [docs/categorization.md](docs/categorization.md)

### Rate limiting (опционально)

Token-bucket лимиты на IP и аутентифицированного пользователя. Метрика: `bsdm_proxy_rate_limit_rejected_total{limit_type="ip|user"}`.

| Переменная | По умолчанию | Описание |
|-----------|-------------|----------|
| `RATE_LIMIT_ENABLED` | `false` | Включить rate limiting |
| `RATE_LIMIT_IP_RPS` | `100` | Запросов/сек на IP |
| `RATE_LIMIT_IP_BURST` | `200` | Burst на IP |
| `RATE_LIMIT_USER_RPS` | `50` | Запросов/сек на пользователя |
| `RATE_LIMIT_USER_BURST` | `100` | Burst на пользователя |
| `RATE_LIMIT_MAX_KEYS` | `10000` | Макс. отслеживаемых ключей |

### Redis L2 cache (опционально)

Распределённый кеш между инстансами прокси. Порядок: **L1 → Redis L2 → hierarchy → origin**.

| Переменная | По умолчанию | Описание |
|-----------|-------------|----------|
| `REDIS_L2_ENABLED` | `false` | Включить Redis L2 |
| `REDIS_URL` | `redis://127.0.0.1:6379` | URL Redis |
| `REDIS_KEY_PREFIX` | `bsdm:http:` | Префикс ключей (тот же `SHA256(method:url)`) |

Метрики: `bsdm_proxy_cache_l2_hits_total`, `bsdm_proxy_cache_l2_misses_total`, `bsdm_proxy_cache_l2_errors_total`.  
Ответ при L2 hit: заголовок `x-cache-status: L2-HIT`.

Демо: `docker compose -f docker-compose.redis-l2.yml up -d --build`

### At-rest compression (опционально)

Прозрачное сжатие тел cacheable-ответов в L1/L2. Клиент всегда получает распакованный ответ.

| Переменная | По умолчанию | Описание |
|-----------|-------------|----------|
| `CACHE_COMPRESSION` | `off` | `zstd`, `brotli` или `off` |
| `CACHE_COMPRESS_MIN_BYTES` | `1024` | Сжимать только если body ≥ N байт |
| `CACHE_COMPRESS_ZSTD_LEVEL` | `3` | Уровень Zstd |

Ответы с заголовком `Content-Encoding` не сжимаются повторно.

### Иерархический кеш (опционально)

Включается через `HIERARCHY_ENABLED=true`. После промаха L1: ICP-запрос к siblings → выбор parent → HTTP fetch через peer → fallback на origin.

| Переменная | По умолчанию | Описание |
|-----------|-------------|----------|
| `HIERARCHY_ENABLED` | `false` | Включить иерархию |
| `CACHE_PARENTS` | — | Parent peers: `host:port[:weight]` |
| `CACHE_SIBLINGS` | — | Sibling peers: `host:port[:weight][:icp_port]` |
| `CACHE_SELECTION_STRATEGY` | `round-robin` | `round-robin`, `weighted`, `closest`, `hash` |
| `ICP_BIND` | `0.0.0.0:3130` | Адрес ICP-сервера (UDP) |
| `ICP_CLIENT_BIND` | `0.0.0.0:0` | Bind для ICP-клиента |
| `ICP_PEER_PORT` | `3130` | ICP-порт siblings по умолчанию |
| `ICP_TIMEOUT_MS` | `100` | Таймаут ICP-запроса (мс) |
| `ICP_SERVER_ENABLED` | `true` | Запускать локальный ICP-сервер |
| `PARENT_TIMEOUT_SECONDS` | `5` | Таймаут HTTP-запроса к peer |
| `ICP_MAX_SIBLING_QUERIES` | `10` | Макс. параллельных ICP-запросов |

→ [docs/hierarchical-caching.md](docs/hierarchical-caching.md)

### Performance tuning (опционально)

Multi-worker accept и fast path для bench/lab. Полный список: [docs/performance.md](docs/performance.md).

| Переменная | По умолчанию | Описание |
|-----------|-------------|----------|
| `WORKER_COUNT` | `1` | Число accept-loop с `SO_REUSEPORT` (Linux) |
| `PERF_FAST_CACHE_HIT` | `false` | L1 HIT до ACL/policy/Kafka (bench) |
| `TCP_SNDBUF_BYTES` | `524288` | `SO_SNDBUF` на клиентских сокетах (`0` = не менять) |
| `METRICS_SAMPLE_RATE` | `0` | `N` → histograms для 1 из N запросов (`0` = все) |
| `HTTP_PRESERVE_HEADER_CASE` | `true` | `false` убирает preserve case (bench) |

HTTP Archive sites bench (70 сайтов × 20 warm repeats):

```bash
./scripts/run-httparchive-benchmark.sh                    # BENCH_PROFILE=warm (default)
BENCH_PROFILE=cold ./scripts/compare-squid-bsdm-httparchive.sh
```

Профили `warm` / `cold` → `WORKER_COUNT` 1 / 4: [`scripts/bench-profile.sh`](scripts/bench-profile.sh). См. [docs/benchmarks-httparchive.md](docs/benchmarks-httparchive.md).

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

# HTTP Archive sites bench (mock upstream + proxy)
./scripts/run-httparchive-benchmark.sh
cargo test -p bsdm-proxy-e2e --test httparchive
```

CI: [rust.yml](.github/workflows/rust.yml) (fmt, clippy, build, test) и [e2e.yml](.github/workflows/e2e.yml).

→ [docs/development.md](docs/development.md)

## Документация

| Документ | Содержание |
|----------|------------|
| [docs/README.md](docs/README.md) | Оглавление документации |
| [docs/authentication.md](docs/authentication.md) | Basic, LDAP, NTLM, Kerberos |
| [docs/logging.md](docs/logging.md) | Логирование (`RUST_LOG`, уровни, просмотр) |
| [docs/performance.md](docs/performance.md) | Тюнинг RPS, `WORKER_COUNT`, bench profiles |
| [docs/benchmarks-httparchive.md](docs/benchmarks-httparchive.md) | HTTP Archive Top 1k benchmarks |
| [docs/k8s-architecture.md](docs/k8s-architecture.md) | Kubernetes / HA deployment |
| [docs/acl.md](docs/acl.md) | Правила доступа, приоритеты |
| [docs/categorization.md](docs/categorization.md) | Shallalist, URLhaus, PhishTank |
| [docs/hierarchical-caching.md](docs/hierarchical-caching.md) | Иерархический кеш, ICP, peers |
| [docs/architecture.md](docs/architecture.md) | Архитектура и блокеры |
| [docs/roadmap.md](docs/roadmap.md) | Roadmap и milestones |
| [docs/capacity-planning.md](docs/capacity-planning.md) | Планирование ёмкости (корп. сценарии) |
| [CHANGELOG.md](CHANGELOG.md) | История изменений |
| [docs/releases/v0.3.0.md](docs/releases/v0.3.0.md) | Release notes 0.3.0 |
| [packaging/README.md](packaging/README.md) | Release-пакет и systemd |
| [OPTIMIZATIONS.md](OPTIMIZATIONS.md) | Оптимизации v2.0 |
| [docker-compose.yml](docker-compose.yml) | Полный стек |

## Roadmap

Цель: **альтернатива Squid с ретропоиском и ML** для аномалий, фишинга и C&C.

Полный план: **[docs/roadmap.md](docs/roadmap.md)** · SWG gap mapping: [docs/swg-backlog-mapping.md](docs/swg-backlog-mapping.md)

| Milestone | Версия | Фокус | Статус |
|-----------|--------|-------|--------|
| **M1** Foundation | v0.2.x | Прокси, ACL, категоризация, observability | ✅ Done |
| **M2** Squid parity | v0.3.x | L2, ACL API, NTLM/Kerberos, hierarchy Phase 4 | ✅ Done |
| **M2.5** Data plane | v0.3.1 | Tiered L1, streaming MISS, auth/policy cache, bench | ~95% |
| **M3** Retro-search | v0.4.x | OpenSearch/ClickHouse, dashboards, Search API | ~60% |
| **M4** Threat analytics | v0.5.x | Rule-based алерты, C&C heuristics | ~5% |
| **M5** ML security | v1.0.x | ML anomaly, phishing, C&C detection | ~0% |

### M2.5 — в работе (последний P0)

- [x] Tiered L1 (mmap spill + shards), P0 perf, k8s/Helm docs
- [x] Streaming MISS, connection auth cache, policy decision cache
- [x] HTTP Archive bench profiles (`BENCH_PROFILE=warm|cold`)
- [x] Spill files `mode 0o600` + private `CACHE_SPILL_DIR` ([#98](https://github.com/onixus/bsdm-proxy/issues/98))

**Gate M2.5:** warm goodput на HTTP Archive sites bench ≥ Squid −5%.

## Лицензия

MIT License — Copyright (c) 2025 BSDM-Proxy Contributors

---

**Disclaimer:** Используйте только в легальных целях с согласия всех сторон.
