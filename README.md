# BSDM-Proxy

**B**usiness **S**ecure **D**ata **M**onitoring Proxy

Высокопроизводительный кеширующий HTTPS-прокси на базе [Hyper](https://hyper.rs/) с [quick_cache](https://crates.io/crates/quick_cache), интегрированный с Kafka, OpenSearch, Prometheus и Grafana для полноценного анализа и мониторинга HTTP-трафика.

[![Build Status](https://github.com/onixus/bsdm-proxy/actions/workflows/rust.yml/badge.svg)](https://github.com/onixus/bsdm-proxy/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust Version](https://img.shields.io/badge/rust-1.83+-orange.svg)](https://www.rust-lang.org)
[![Hyper](https://img.shields.io/badge/hyper-1.10-blue.svg)](https://hyper.rs/)
[![Prometheus](https://img.shields.io/badge/prometheus-enabled-brightgreen.svg)](https://prometheus.io/)
[![Grafana](https://img.shields.io/badge/grafana-dashboard-orange.svg)](https://grafana.com/)

## 🚀 v2.1: Hyper + quick_cache + Prometheus

**Текущая версия proxy: 2.1.0.** Ядро переписано на нативном Hyper (v2.0) с полным мониторингом:

| Метрика | v1.x (Pingora) | v2.0 (Hyper + monitoring) | Улучшение |
|---------|----------------|--------------------------|----------|
| **Cache HIT latency** | 1-2 мс | **0.1-0.2 мс** | **10x быстрее** |
| **Memory per entry** | ~500 bytes | **~120 bytes** | **4.2x меньше** |
| **HTTP CONNECT** | ⚠️ Workarounds | ✅ **Нативная поддержка** | **Новая функция** |
| **Prometheus metrics** | ❌ | ✅ **20+ метрик** | **Новая функция** |
| **Grafana dashboard** | ❌ | ✅ **7 панелей** | **Новая функция** |
| **Kafka latency** | 8-12 мс | **2-5 мс** | **3x быстрее** |

### 🔥 Ключевые особенности

- **Arc<str> вместо String**: Zero-cost cloning, 80% меньше аллокаций
- **Prometheus metrics**: 20+ метрик производительности (request rate, latency, cache hit rate)
- **Grafana dashboard**: 7 панелей с auto-refresh из коробки
- **Health checks**: `/health` и `/ready` endpoints
- **Connection pooling**: 50-70% быстрее к upstream
- **Async Kafka**: Fire-and-forget, не блокирует proxy

👉 Подробности в [OPTIMIZATIONS.md](OPTIMIZATIONS.md)

⚠️ **Предупреждение:** MITM-прокси для HTTPS. Используйте только в корпоративной среде с согласия пользователей.

## 🏗️ Архитектура

```
┌─────────┐         ┌──────────────────┐         ┌──────────────┐
│ Клиент  │◄───────►│  BSDM-Proxy      │◄───────►│   Upstream   │
│         │  HTTPS  │  (Hyper + cache) │  HTTPS  │    Server    │
└─────────┘         └────────┬─────────┘         └──────────────┘
                             │
                             │ :9090 /metrics
                    ┌────────┴────────┐
                    │                 │
             ┌──────▼──────┐   ┌─────▼──────┐
             │ quick_cache │   │   Kafka    │
             │ (in-memory) │   │ (async)    │
             └─────────────┘   └─────┬──────┘
                                     │
              ┌──────────────────────┴──────┐
              │                             │
       ┌──────▼─────────┐          ┌────────▼────────┐
       │ Cache-Indexer  │          │  Prometheus     │
       └──────┬─────────┘          │  (scrapes :9090)│
              │                    └────────┬────────┘
       ┌──────▼─────────┐                  │
       │  OpenSearch    │          ┌───────▼─────────┐
       │  (L2 Cache)    │          │    Grafana      │
       └────────────────┘          │  (dashboards)   │
                                   └─────────────────┘
```

## ✨ Возможности

### Прокси-сервер
- 🔐 **MITM TLS** с динамической генерацией сертификатов
- ⚡ **Sub-ms latency**: quick_cache обеспечивает 0.1-0.2 мс cache hits
- 💾 **L1+L2 caching**: quick_cache + OpenSearch
- 🔄 **HTTP CONNECT**: Нативная поддержка forward proxy
- 👤 **User analytics**: Basic Auth parsing

### Мониторинг
- 📊 **Prometheus**: 20+ метрик (request rate, latency p50/p95/p99, cache hit rate)
- 📈 **Grafana**: 7 панелей (auto-provisioned, auto-refresh 5s)
- 🏥 **Health checks**: `/health`, `/ready`, `/metrics` endpoints
- 🔍 **Real-time**: Sub-second visibility в производительность

### Аналитика
- 📊 **OpenSearch**: Full-text поиск, агрегации
- 📈 **Kafka**: Асинхронная индексация событий

## 📦 Компоненты

### 1. Proxy (порт 1488)
- HTTP forward proxy на Hyper 1.10 (MITM TLS к upstream)
- quick_cache L1 (10k entries, 1h TTL)
- Kafka producer (async fire-and-forget)
- **Metrics server** (порт 9090)

### 2. Cache Indexer
- Kafka → OpenSearch (батч 50 событий/5с)

### 3. Инфраструктура
- **Kafka** (порт 9092) — `confluentinc/cp-kafka:7.9.8`
- **OpenSearch** (порт 9200) — `opensearchproject/opensearch:3.7.0`
- **OpenSearch Dashboards** (порт 5601) — `opensearchproject/opensearch-dashboards:3.7.0`
- **Prometheus** (порт 9091) — `prom/prometheus:v3.12.0`
- **Grafana** (порт 3000) — `grafana/grafana:12.3.8` (логин: admin/admin)

## 🚀 Быстрый старт

### 1. Генерация CA сертификата

```bash
mkdir -p certs && cd certs
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=RU/ST=Moscow/L=Moscow/O=BSDM/CN=BSDM Root CA"
cd ..
```

### 2. Запуск

```bash
docker compose up -d
docker compose ps  # Проверка статуса
```

### 3. Установка CA сертификата

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

**Windows:** `certmgr.msc` → Доверенные корневые ЦС → Импорт `ca.crt`

### 4. Проверка

```bash
# Тест proxy
curl -x http://localhost:1488 https://httpbin.org/get

# Проверка метрик
curl http://localhost:9090/metrics | grep bsdm_proxy
curl http://localhost:9090/health

# Открыть dashboards
open http://localhost:9091  # Prometheus
open http://localhost:3000  # Grafana (admin/admin)
```

## 📊 Prometheus Metrics

### Доступные метрики

**Request Metrics:**
- `bsdm_proxy_requests_total{method,status,cache_status}` - counter
- `bsdm_proxy_requests_in_flight` - gauge
- `bsdm_proxy_request_duration_seconds` - histogram (p50/p95/p99)
- `bsdm_proxy_request_size_bytes` / `response_size_bytes` - histograms

**Cache Metrics:**
- `bsdm_proxy_cache_hits_total` / `misses_total` / `bypasses_total` - counters
- `bsdm_proxy_cache_entries` / `cache_size_bytes` - gauges
- `bsdm_proxy_cache_lookup_duration_seconds` - histogram

**Upstream Metrics:**
- `bsdm_proxy_upstream_requests_total{host,status}` - counter
- `bsdm_proxy_upstream_duration_seconds{host}` - histogram
- `bsdm_proxy_upstream_errors_total{host,error_type}` - counter
- `bsdm_proxy_upstream_connections_active` / `created_total` - gauge/counter

**System Metrics:**
- `bsdm_proxy_kafka_events_sent_total` / `send_errors_total` - counters
- `bsdm_proxy_tls_handshakes_total` - counter

### Примеры PromQL

```promql
# Cache hit rate
bsdm_proxy_cache_hits_total / 
  (bsdm_proxy_cache_hits_total + bsdm_proxy_cache_misses_total)

# Request rate per second
rate(bsdm_proxy_requests_total[1m])

# P95 latency
histogram_quantile(0.95, 
  rate(bsdm_proxy_request_duration_seconds_bucket[5m])
)

# Error rate
rate(bsdm_proxy_requests_total{status=~"5.."}[5m]) / 
  rate(bsdm_proxy_requests_total[5m])
```

## 📈 Grafana Dashboard

### Auto-provisioned Dashboard

Grafana dashboard загружается автоматически при старте:

1. Откройте: http://localhost:3000
2. Логин: `admin` / Пароль: `admin`
3. **Dashboards → BSDM Proxy Dashboard**

### 7 панелей:

1. **Request Rate** - req/s по методам и cache status
2. **Cache Hit Rate** - gauge с порогами (>80% = green)
3. **Requests In Flight** - активные запросы
4. **Request Latency** - p50/p95/p99 перцентили
5. **Cache Lookup Latency** - p99 скорость поиска в кеше
6. **Cache Statistics** - entries и размер в MB
7. **Upstream Connections** - активные соединения

**Features:**
- Auto-refresh каждые 5 секунд
- Time range: Last 15 minutes (configurable)
- Color-coded thresholds

## ⚙️ Конфигурация

### Proxy Environment Variables

| Переменная | По умолчанию | Описание |
|-----------|-------------|----------|
| `KAFKA_BROKERS` | `kafka:9092` | Kafka брокеры |
| `CACHE_CAPACITY` | `10000` | L1 кеш (записей) |
| `CACHE_TTL_SECONDS` | `3600` | TTL кеша (сек) |
| `MAX_CACHE_BODY_SIZE` | `10485760` | Макс body (bytes) |
| `HTTP_PORT` | `1488` | Порт proxy |
| `METRICS_PORT` | `9090` | Порт метрик |
| `RUST_LOG` | `info` | Уровень логов |

### Примеры

**Высокая нагрузка:**
```yaml
services:
  proxy:
    environment:
      - CACHE_CAPACITY=100000
      - CACHE_TTL_SECONDS=1800
      - MAX_CACHE_BODY_SIZE=1048576
```

**Низкая память:**
```yaml
services:
  proxy:
    environment:
      - CACHE_CAPACITY=5000
      - MAX_CACHE_BODY_SIZE=524288
```

## 🔍 OpenSearch Аналитика

```bash
# Поиск по user
curl "http://localhost:9200/http-cache/_search?q=username:john"

# Cache hits/misses
curl -X GET "http://localhost:9200/http-cache/_search" -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "aggs": {
    "cache_status": {"terms": {"field": "cache_status"}}
  }
}'

# Топ медленных запросов
curl "http://localhost:9200/http-cache/_search?q=request_duration_ms:>1000&sort=request_duration_ms:desc"
```

## 📊 Производительность

### Бенчмарки (v2.1)

- **L1 cache latency**: 0.1-0.2 мс
- **Throughput**: 100,000+ req/s
- **Kafka latency**: 2-5 мс
- **Memory per entry**: ~120 bytes
- **Metrics export**: <1 мс

### vs Pingora (v1.x)

```bash
# 1000 запросов к кешу
time for i in {1..1000}; do curl -s -x http://localhost:1488 https://httpbin.org/get > /dev/null; done

# Pingora: ~2.5s (2.5ms avg)
# Hyper:   ~0.8s (0.8ms avg) — 3x faster!
```

## 🗺️ Roadmap

### v2.1 (текущая)
- [x] Prometheus metrics
- [x] Health checks
- [x] Grafana dashboard
- [x] Обновление зависимостей и Docker-образов
- [ ] Graceful shutdown
- [ ] Rate limiting per user/IP
- [ ] **Hierarchical caching** 🚧 **In Progress**
  - [x] Peer management
  - [x] ICP protocol (RFC 2186)
  - [x] Selection strategies
  - [x] Hierarchy manager
  - [ ] Integration (Phase 3)

### v2.2 (Q2 2026)
- [ ] Redis L2 cache
- [ ] HTTP/2 upstream client
- [ ] Compression (Brotli/Zstd)
- [ ] Advanced alerting

### v3.0 (Q3 2026)
- [ ] Machine Learning anomaly detection
- [ ] Threat Intelligence integration
- [ ] io_uring (для Linux 5.1+)

## 📚 Документация

- [Wiki](https://github.com/onixus/bsdm-proxy/wiki) — установка и быстрый старт
- [OPTIMIZATIONS.md](OPTIMIZATIONS.md) — детали оптимизаций
- [OPENSEARCH_UPGRADE.md](OPENSEARCH_UPGRADE.md) — обновление OpenSearch
- [docs/authentication.md](docs/authentication.md) — Basic/LDAP/NTLM
- [docs/acl.md](docs/acl.md) — правила доступа
- [docs/hierarchical-caching.md](docs/hierarchical-caching.md) — Squid-style hierarchy
- [docker-compose.yml](docker-compose.yml) — конфигурация стека

## 📝 Лицензия

MIT License - Copyright (c) 2025-2026 BSDM-Proxy Contributors

---

**⚠️ Disclaimer:** Используйте только в легальных целях с согласия всех сторон.
