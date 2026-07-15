# BSDM-Proxy [![Build Status](https://github.com/onixus/bsdm-proxy/actions/workflows/rust.yml/badge.svg)](https://github.com/onixus/bsdm-proxy/actions/workflows/rust.yml)

**B**usiness **S**ecure **D**ata **M**onitoring Proxy

Высокопроизводительный кеширующий HTTPS-прокси на [Hyper](https://hyper.rs/) с [quick_cache](https://crates.io/crates/quick_cache), MITM TLS, аутентификацией, ACL и интеграцией с Kafka, ClickHouse, Prometheus и Grafana.


[![E2E Tests](https://github.com/onixus/bsdm-proxy/actions/workflows/e2e.yml/badge.svg)](https://github.com/onixus/bsdm-proxy/actions/workflows/e2e.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.3.2-blue.svg)](https://github.com/onixus/bsdm-proxy/releases)
[![Rust](https://img.shields.io/badge/rust-1.88+-orange.svg)](https://www.rust-lang.org)

> **Текущая версия:** `0.3.2` · M2.5/M3 done · M4 threat analytics started — см. [Releases](https://github.com/onixus/bsdm-proxy/releases) · [CHANGELOG](CHANGELOG.md) · [roadmap](docs/roadmap.md)

⚠️ **MITM-прокси для HTTPS.** Используйте только в корпоративной среде с согласия пользователей и в рамках законодательства.

## Возможности

| Область | Возможности |
|---------|-------------|
| **Прокси** | HTTP/HTTPS forward proxy, MITM TLS (443/8443), HTTP CONNECT, **tiered L1** (inline + mmap spill, шарды), **streaming MISS**, Redis L2, **иерархический кеш** (ICP/HTCP), HTTP/2 upstream (опц.) |
| **Безопасность** | Proxy-auth (Basic / LDAP / NTLM / Kerberos), **connection-level auth cache**, ACL + REST API, **policy decision cache**, категоризация URL, rate limiting |
| **Производительность** | Multi-worker accept (`WORKER_COUNT`), perf fast path (`PERF_FAST_CACHE_HIT`), HTTP Archive bench profiles (`BENCH_PROFILE=warm\|cold`) |
| **Наблюдаемость** | Prometheus (proxy + cache-indexer), Grafana (Prometheus + ClickHouse), `/health`, `/ready`, `/metrics` |
| **Аналитика** | Kafka → cache-indexer → **ClickHouse** (`bsdm.http_cache`); Grafana **HTTP Traffic**; REST **Search API** (`/api/search`) |
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
             │  ClickHouse    │
             └────────────────┘
```

## Компоненты

| Компонент | Порт | Описание |
|-----------|------|----------|
| **proxy** | 1488 | HTTPS-прокси, MITM, кеш L1, иерархия (опционально) |
| **ICP** | 3130 | UDP-запросы между cache peers (при `HIERARCHY_ENABLED=true`) |
| **metrics** | 9090 | `/health`, `/ready`, `/metrics` |
| **cache-indexer** | 8080 | Kafka → ClickHouse, `/api/search` |
| **Kafka** | 9092 | Очередь событий кеша |
| **ClickHouse** | 8123 / 9000 | Аналитика HTTP-трафика |
| **Prometheus** | 9091 | Сбор метрик |
| **Grafana** | 3000 | Дашборды proxy + HTTP Traffic (`admin` / `admin`) |

## Быстрый старт (Docker)

### Lite — только прокси (без Kafka / ClickHouse)

```bash
./scripts/gen-ca.sh
docker compose -f docker-compose.lite.yml up -d --build
curl --cacert certs/ca.crt -x http://127.0.0.1:1488 https://httpbin.org/get
curl http://127.0.0.1:9090/health
```

Подробнее: [docs/lite.md](docs/lite.md) · Strategic Phase 1: [docs/strategic-roadmap.md](docs/strategic-roadmap.md)

### Полный стек (analytics)

#### 1. CA для MITM

```bash
./scripts/gen-ca.sh   # или вручную openssl — см. ниже
```

<details>
<summary>Ручная генерация CA</summary>

```bash
mkdir -p certs && cd certs
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=RU/ST=Moscow/L=Moscow/O=BSDM/CN=BSDM Root CA"
cd ..
```

</details>

#### 2. Запуск стека

```bash
docker compose up -d --build
docker compose ps
```

Подробнее: [docs/docker.md](docs/docker.md) · [docs/deployment.md](docs/deployment.md)

#### 3. Доверие клиенту к CA

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

#### 4. Проверка

```bash
curl -x http://localhost:1488 https://httpbin.org/get
curl http://localhost:9090/health
curl http://localhost:9090/metrics | grep bsdm_proxy

# Analytics (after ~5s)
curl 'http://localhost:8123/?query=SELECT+count()+FROM+bsdm.http_cache'
curl 'http://localhost:8080/api/search?limit=5'
```

Grafana: http://localhost:3000 → **BSDM HTTP Traffic (ClickHouse)** и **BSDM Proxy Dashboard**.

### Compose-профили

| Файл | Назначение |
|------|------------|
| [docker-compose.lite.yml](docker-compose.lite.yml) | **Lite:** один proxy (MITM + L1), без analytics |
| [docker-compose.yml](docker-compose.yml) | Полный стек: proxy, Kafka, ClickHouse, cache-indexer, Prometheus, Grafana |
| [docker-compose.test.yml](docker-compose.test.yml) | Минимальный стек для smoke/E2E |
| [docker-compose.redis-l2.yml](docker-compose.redis-l2.yml) | Два proxy + Redis L2 |
| [docker-compose.hierarchy.yml](docker-compose.hierarchy.yml) | Multi-instance + ICP |
## Установка (native package)

Сборка пакета из исходников:

```bash
./scripts/build-package.sh
```

Архив: `dist/bsdm-proxy-0.3.2-linux-<arch>.tar.gz`

Установка:

```bash
tar xzf dist/bsdm-proxy-0.3.2-linux-x86_64.tar.gz
cd bsdm-proxy-0.3.2-linux-x86_64
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
| `UT1_ENABLED` | Включить локальную БД категорий ([UT1 Blacklists](https://dsi.ut-capitole.fr/blacklists/)) |
| `UT1_PATH` | Путь к распакованным спискам (`blacklists/<category>/domains`) |
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

### Cache-indexer (ClickHouse)

`cache-indexer` — единственный backend аналитики: Kafka → `INSERT` в `bsdm.http_cache` (JSONEachRow). Admin HTTP на `METRICS_PORT`:

| Endpoint | Описание |
|----------|----------|
| `GET /health` | `{"status":"ok"}` |
| `GET /metrics` | `cache_indexer_*` Prometheus metrics |
| `GET /api/search` | Retro-search (JSON/CSV), см. [docs/search-api.md](docs/search-api.md) |

| Переменная | По умолчанию | Описание |
|-----------|-------------|----------|
| `KAFKA_BROKERS` | `kafka:9092` | Брокеры Kafka |
| `KAFKA_TOPIC` | `cache-events` | Топик |
| `KAFKA_GROUP_ID` | `cache-indexer-group` | Consumer group |
| `CLICKHOUSE_URL` | `http://clickhouse:8123` | HTTP interface ClickHouse |
| `CLICKHOUSE_DATABASE` | `bsdm` | База |
| `CLICKHOUSE_TABLE` | `http_cache` | Таблица |
| `CLICKHOUSE_USER` / `CLICKHOUSE_PASSWORD` | — | Basic auth (опц.) |
| `METRICS_PORT` | `8080` | Admin port |
| `SEARCH_API_ENABLED` | `true` | REST `/api/search` |
| `SEARCH_API_TOKEN` | — | Bearer auth (опц.) |
| `SEARCH_API_MAX_LIMIT` | `10000` | Макс. строк в ответе |
| `SEARCH_API_DEFAULT_DAYS` | `30` | Lookback по умолчанию |

Пример retro-search:

```bash
curl 'http://localhost:8080/api/search?domain=example.com&days=7&limit=100'
curl 'http://localhost:8080/api/search?format=csv&limit=50' -o traffic.csv
```

Grafana использует plugin [`grafana-clickhouse-datasource`](https://grafana.com/grafana/plugins/grafana-clickhouse-datasource/) (native `:9000`, SQL по `bsdm.http_cache`). Provisioning: `grafana/datasources.yml`, dashboard `grafana/dashboards/bsdm-http-traffic-ch.json`.

→ [docs/search-api.md](docs/search-api.md) · [docs/clickhouse-analytics.md](docs/clickhouse-analytics.md) · [ADR 0002](docs/adr/0002-clickhouse-analytics.md)

## Мониторинг

### Proxy (`:9090`)

| URL | Ответ |
|-----|-------|
| `GET /health` | `{"status":"ok"}` |
| `GET /ready` | `{"status":"ready"}` или `draining` при shutdown |
| `GET /metrics` | Prometheus text format |

### cache-indexer (`:8080`)

| URL | Ответ |
|-----|-------|
| `GET /health` | `{"status":"ok"}` |
| `GET /metrics` | `cache_indexer_inserts_total`, `cache_indexer_insert_errors_total`, … |
| `GET /api/search` | JSON/CSV retro-search ([docs/search-api.md](docs/search-api.md)) |

### Примеры PromQL

```promql
# Cache hit rate
bsdm_proxy_cache_hits_total /
  (bsdm_proxy_cache_hits_total + bsdm_proxy_cache_misses_total)

# P95 latency
histogram_quantile(0.95,
  rate(bsdm_proxy_request_duration_seconds_bucket[5m])
)

# Indexer insert rate
rate(cache_indexer_inserts_total{backend="clickhouse"}[5m])
```

Grafana: http://localhost:3000 → **BSDM Proxy Dashboard** (Prometheus) и **BSDM HTTP Traffic (ClickHouse)**.

## Тестирование

Перед push: `./scripts/pre-push-check.sh` (или `./scripts/install-git-hooks.sh` для auto hook).

```bash
# Unit + integration + smoke + e2e (75 тестов)
cargo test --workspace --all-targets

# Smoke (health, metrics, HTTP forward)
./scripts/run-smoke-tests.sh

# E2E (auth, ACL, cache, MITM, CONNECT)
./scripts/run-e2e-tests.sh

# Docker test stack
docker compose -f docker-compose.test.yml up -d --build
./scripts/run-smoke-tests.sh --external
# E2E --external: cache HIT для HTTPS не ожидается (MITM_ENABLED=false)

# HTTP Archive sites bench (mock upstream + proxy)
./scripts/run-httparchive-benchmark.sh
cargo test -p bsdm-proxy-e2e --test httparchive
```

CI: [rust.yml](.github/workflows/rust.yml) (fmt, clippy, build, test, cargo-audit) и [e2e.yml](.github/workflows/e2e.yml).

→ [docs/development.md](docs/development.md)

## Документация (Wiki)

| Документ | Содержание |
|----------|------------|
| [docs/README.md](docs/README.md) | **Оглавление wiki** |
| [docs/deployment.md](docs/deployment.md) | Развёртывание: Docker, native, k8s |
| [docs/docker.md](docs/docker.md) | Docker Compose, сборка образов, troubleshooting |
| [docs/lite.md](docs/lite.md) | Lite: standalone proxy compose |
| [docs/kubernetes.md](docs/kubernetes.md) | Kubernetes: манифесты, probes, Helm chart |
| [docs/k8s-architecture.md](docs/k8s-architecture.md) | Kubernetes / HA deployment |
| [docs/development.md](docs/development.md) | Сборка, тесты, CI |
| [docs/authentication.md](docs/authentication.md) | Basic, LDAP, NTLM, Kerberos |
| [docs/logging.md](docs/logging.md) | Логирование (`RUST_LOG`, уровни, просмотр) |
| [docs/performance.md](docs/performance.md) | Тюнинг RPS, `WORKER_COUNT`, bench profiles |
| [docs/benchmarks-httparchive.md](docs/benchmarks-httparchive.md) | HTTP Archive Top 1k benchmarks |
| [docs/acl.md](docs/acl.md) | Правила доступа, REST API |
| [docs/categorization.md](docs/categorization.md) | UT1 Blacklists, OTX, custom DB |
| [docs/hierarchical-caching.md](docs/hierarchical-caching.md) | Иерархический кеш, ICP, HTCP |
| [docs/licensing.md](docs/licensing.md) | Лицензии, third-party, AGPL-заметки |
| [NOTICE](NOTICE) | Реестр third-party компонентов |
| [docs/clickhouse-analytics.md](docs/clickhouse-analytics.md) | ClickHouse analytics, compose, SQL |
| [docs/alerting.md](docs/alerting.md) | Alert worker → SIEM/webhook (B19) |
| [docs/search-api.md](docs/search-api.md) | REST Search API (`/api/search`) |
| [docs/adr/0002-clickhouse-analytics.md](docs/adr/0002-clickhouse-analytics.md) | ADR: ClickHouse как analytics store |
| [docs/architecture.md](docs/architecture.md) | Архитектура и блокеры |
| [docs/roadmap.md](docs/roadmap.md) | Roadmap и milestones (M1–M5) |
| [docs/strategic-roadmap.md](docs/strategic-roadmap.md) | Стратегия: Lite, DX, Wasm, AI |
| [docs/capacity-planning.md](docs/capacity-planning.md) | Планирование ёмкости (корп. сценарии) |
| [CHANGELOG.md](CHANGELOG.md) | История изменений |
| [docs/releases/v0.3.2.md](docs/releases/v0.3.2.md) | Release notes 0.3.2 |
| [docs/releases/v0.3.1.md](docs/releases/v0.3.1.md) | Release notes 0.3.1 |
| [packaging/README.md](packaging/README.md) | Release-пакет и systemd |
| [docker-compose.yml](docker-compose.yml) | Полный стек |

## Roadmap

Цель: **альтернатива Squid с ретропоиском и ML** для аномалий, фишинга и C&C.

План работ (M1–M5): **[docs/roadmap.md](docs/roadmap.md)** · Стратегия (Lite / DX / Wasm / AI): **[docs/strategic-roadmap.md](docs/strategic-roadmap.md)** · SWG: [docs/swg-backlog-mapping.md](docs/swg-backlog-mapping.md)

### Engineering milestones

| Milestone | Версия | Фокус | Статус |
|-----------|--------|-------|--------|
| **M1** Foundation | v0.2.x | Прокси, ACL, категоризация, observability | ✅ Done |
| **M2** Squid parity | v0.3.x | L2, ACL API, NTLM/Kerberos, hierarchy Phase 4 | ✅ Done |
| **M2.5** Data plane | v0.3.1–0.3.2 | Tiered L1, streaming MISS, P1 hot path | ✅ Done |
| **M3** Retro-search | v0.3.1+ | ClickHouse, Grafana, Search API, k8s CHI | ✅ Done |
| **M4** Threat analytics | v0.5.x | Rule-based алерты, C&C heuristics | ~40% |
| **M5** ML security | v1.0.x | ML anomaly, phishing, C&C detection | ~0% |

Кратко: **M3 closed** (proxy → Kafka → ClickHouse → Grafana/`/api/search`). **M4** — categorization metrics shipped; alerts/heuristics next.

### Стратегические фазы

Вектор рыночной ценности и удобства (детально — [strategic-roadmap.md](docs/strategic-roadmap.md)):

| Фаза | Фокус |
|------|--------|
| **1. Lite** | Прокси без обязательных Kafka/ClickHouse; SQLite Search API; `docker-compose.lite.yml` ([docs/lite.md](docs/lite.md)) |
| **2. DX** | Control Plane API, hot reload, cache purge, lite metrics без Grafana |
| **3. Wasm** | Wasmtime-плагины, SDK, модульность ядра |
| **4. AI-трафик** | Token-bucket RL, semantic cache для LLM, request coalescing |

Порядок по умолчанию: Lite → DX → Wasm / AI.

## Лицензия

MIT License — Copyright (c) 2025 BSDM-Proxy Contributors

---

**Disclaimer:** Используйте только в легальных целях с согласия всех сторон.
