# Docker и Docker Compose

Руководство по контейнеризации BSDM-Proxy.

> См. также: [deployment.md](deployment.md) · [docker-compose.yml](../docker-compose.yml) · [docker-compose.test.yml](../docker-compose.test.yml)

---

## Compose-файлы

| Файл | Назначение | Сервисы |
|------|------------|---------|
| `docker-compose.yml` | Полный стек | proxy, cache-indexer, kafka, zookeeper, opensearch, opensearch-dashboards, dashboards-setup, prometheus, grafana |
| `docker-compose.test.yml` | Smoke/E2E external | upstream (httpbin), proxy |

---

## Сборка образов

Dockerfile — multi-stage: `rust:1-alpine` (builder) → `alpine:3.21` (runtime).

```bash
# Только proxy
docker build --target proxy -t bsdm-proxy:proxy .

# Только cache-indexer
docker build --target cache-indexer -t bsdm-proxy:indexer .

# Через compose
docker compose build proxy cache-indexer
```

### Требования к сборке

- В builder копируются все workspace members: `proxy`, `cache-indexer`, `e2e` (нужен для `cargo build` workspace).
- Rust в образе: `rust:1-alpine` (stable ≥ 1.88).
- Статическая линковка musl: `librdkafka-dev`, `openssl-dev`, и др. (см. Dockerfile).

### Локальная сборка бинарника + runtime-образ (обход долгой Docker-сборки)

```bash
cargo build --release -p bsdm-proxy --bin proxy

cat > /tmp/Dockerfile.proxy-local <<'EOF'
FROM ubuntu:24.04
RUN apt-get update -qq && apt-get install -y -qq ca-certificates wget \
  && rm -rf /var/lib/apt/lists/*
COPY target/release/proxy /usr/local/bin/proxy
EXPOSE 1488 9090
CMD ["proxy"]
EOF

docker build -f /tmp/Dockerfile.proxy-local -t bsdm-proxy:local .
```

---

## Полный стек

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f proxy
```

### Переменные proxy (compose defaults)

| Переменная | Значение в compose | Описание |
|-----------|-------------------|----------|
| `MITM_ENABLED` | `true` | MITM для 443/8443 |
| `AUTH_ENABLED` | `false` | Аутентификация выкл. |
| `ACL_ENABLED` | `false` | ACL выкл. |
| `KAFKA_BROKERS` | `kafka:9092` | Kafka |
| `CACHE_CAPACITY` | `10000` | L1 cache |
| `RUST_LOG` | `info,bsdm_proxy=debug` | Логи |

CA монтируется из `./certs/` → `/certs/`.

### Health checks

| Сервис | Проверка |
|--------|----------|
| proxy | `curl -f http://localhost:9090/health` |
| kafka | `kafka-broker-api-versions --bootstrap-server localhost:9092` |
| opensearch | `curl -f http://localhost:9200/_cluster/health` |
| opensearch-dashboards | `curl -f http://localhost:5601/api/status` |
| prometheus | `wget --spider http://localhost:9090/-/healthy` |
| grafana | `curl -f http://localhost:3000/api/health` |

---

## Тестовый стек

```bash
docker compose -f docker-compose.test.yml up -d --build

# Smoke (health, metrics, HTTP forward)
./scripts/run-smoke-tests.sh --external

# E2E external — только cache HIT для HTTPS при MITM_ENABLED=false не ожидается
./scripts/run-e2e-tests.sh --external
```

**Важно:** в test compose `MITM_ENABLED=false`. HTTPS-запросы идут через CONNECT-туннель; заголовок `x-cache-status: HIT` для HTTPS **не появится**. Для проверки кэша:

```bash
./scripts/run-e2e-tests.sh   # in-process, с MITM mock upstream
```

### Метрика `bsdm_proxy_requests_total`

Счётчик Prometheus появляется в `/metrics` **после первого HTTP-запроса** через proxy. До этого smoke-скрипт может не найти метрику — сделайте тестовый запрос:

```bash
curl -x http://127.0.0.1:1488 http://httpbin.org/get
curl http://127.0.0.1:9090/metrics | grep bsdm_proxy_requests_total
```

---

## Volumes и данные

| Volume | Сервис | Данные |
|--------|--------|--------|
| `opensearch-data` | opensearch | Индексы |
| `prometheus-data` | prometheus | TSDB |
| `grafana-data` | grafana | Дашборды, настройки |

Очистка:

```bash
docker compose down -v   # удаляет volumes
```

---

## Troubleshooting

### `docker compose build` падает на workspace member `e2e`

Убедитесь, что в Dockerfile есть `COPY e2e ./e2e`.

### Ошибка rustc version / зависимости

Обновите базовый образ builder до `rust:1-alpine` (≥ 1.88). Зависимости `icu_*`, `time`, `serde_with` требуют современный stable.

### Kafka не подключается к Zookeeper

Проверьте сеть Docker: `docker network inspect workspace_bsdm-net`. На хостах с ограниченным iptables/nftables bridge-сеть может не работать — используйте нормальный Docker host или k8s.

### Proxy не может достучаться до интернета из контейнера

Проверьте egress и DNS внутри контейнера:

```bash
docker exec <proxy-container> wget -q -O- --timeout=5 http://httpbin.org/get
```

В проблемных средах временный обход: `--network host` (только для отладки).

### OpenSearch не стартует (memory)

Требуется `vm.max_map_count`:

```bash
sudo sysctl -w vm.max_map_count=262144
```

---

## Остановка

```bash
docker compose down
docker compose -f docker-compose.test.yml down
```
