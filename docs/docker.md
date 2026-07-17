# Docker и Docker Compose

Руководство по контейнеризации BSDM-Proxy.

> См. также: [deployment.md](deployment.md) · [clickhouse-analytics.md](clickhouse-analytics.md)

---

## Compose-файлы

| Файл | Назначение |
|------|------------|
| `docker-compose.lite.yml` | **Lite:** proxy + SQLite indexer (MITM + L1 spill), без Kafka/CH |
| `docker-compose.yml` | Полный стек: proxy, cache-indexer, kafka, zookeeper, clickhouse, prometheus, **alertmanager**, grafana; optional `alert-worker` (`--profile alerts`), `ml-worker` (`--profile ml`), `icap` (`--profile icap`), `dns-sinkhole` (`--profile dns-sinkhole`) || `docker-compose.test.yml` | Smoke/E2E external (upstream + proxy) |
| `docker-compose.redis-l2.yml` | Два proxy + Redis L2 |
| `docker-compose.hierarchy.yml` | Multi-instance + ICP |
| `docker-compose.ha.yml` | HA lab |

---

## Сборка образов

Dockerfile — multi-stage: `rust:1-alpine` (builder) → `alpine:3.21` (runtime).

```bash
docker build --target proxy -t bsdm-proxy:proxy .
docker build --target cache-indexer -t bsdm-proxy:indexer .
docker build --target alert-worker -t bsdm-proxy:alert-worker .
docker compose build proxy cache-indexer
```

### Требования к сборке

- Workspace members в builder: `bsdm-events`, `proxy`, `cache-indexer`, `alert-worker`, `e2e`.
- Rust: `rust:1-alpine` (stable ≥ 1.88).
- Статическая линковка musl (см. Dockerfile).

---

## Lite (proxy + SQLite Search API)

```bash
./scripts/gen-ca.sh
docker compose -f docker-compose.lite.yml up -d --build
```

Сервисы: `proxy` + `cache-indexer` (`INDEX_STORE=sqlite`, `EVENT_SINK_URL`). Без Kafka/ClickHouse. Docs: [lite.md](lite.md).

## Полный стек

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f proxy
```

### Alert worker (SIEM webhook)

```bash
ALERT_WEBHOOK_URL=https://siem.example/hooks/bsdm \
  docker compose --profile alerts up -d --build alert-worker
```

Docs: [alerting.md](alerting.md).

### ICAP sidecar (AV / URL)

```bash
docker compose --profile icap up -d icap
# Proxy env: ICAP_ENABLED=true ICAP_URL=icap://icap:1344/srv_clamav
```

Docs: [icap.md](icap.md).

### DNS sinkhole sidecar

```bash
docker compose --profile dns-sinkhole up -d --build dns-sinkhole
# dig @127.0.0.1 -p 5353 blocked.test A +short
```

Docs: [dns-sinkhole.md](dns-sinkhole.md).

### Grafana / Alertmanager (M4)

Always-on with the full stack:

| Endpoint | URL |
|----------|-----|
| Grafana Alerting | http://localhost:3000/alerting/list |
| Alertmanager | http://localhost:9093 |
| Prometheus alerts | http://localhost:9091/alerts |

Set `ALERT_WEBHOOK_URL` so Alertmanager (and `alert-worker`) forward to SIEM.

### Health checks

| Сервис | Проверка |
|--------|----------|
| proxy | `wget -q -O- http://127.0.0.1:9090/health \| grep -q ok` |
| kafka | `kafka-broker-api-versions --bootstrap-server localhost:9092` |
| clickhouse | HTTP `:8123/ping` |
| alert-worker | `wget … /health` (profile `alerts`) |
| alertmanager | `wget … /-/healthy` |
| prometheus | `wget --spider http://localhost:9090/-/healthy` |
| grafana | `curl -f http://localhost:3000/api/health` |

Proxy runtime включает **wget** (не curl) — healthchecks в compose используют wget.

---

## Тестовый стек

```bash
docker compose -f docker-compose.test.yml up -d --build
./scripts/run-smoke-tests.sh --external
```

**Ограничения external-режима:**
- `MITM_ENABLED=false` — HTTPS не кэшируется (CONNECT-туннель).
- `bsdm_proxy_requests_total` появляется после первого запроса.
- `./scripts/run-e2e-tests.sh --external` — cache HIT для HTTPS может не пройти; используйте in-process `./scripts/run-e2e-tests.sh`.

### Демо: hierarchy / Redis L2

```bash
docker compose -f docker-compose.hierarchy.yml up -d --build
docker compose -f docker-compose.redis-l2.yml up -d --build
```

См. [development.md](development.md).

---

## Volumes

| Volume | Сервис |
|--------|--------|
| `clickhouse-data` | clickhouse |
| `prometheus-data` | prometheus |
| `grafana-data` | grafana |

```bash
docker compose down -v   # удаляет volumes
```

---

## Troubleshooting

### `docker compose build` — workspace member missing

Проверьте Dockerfile: `COPY bsdm-events`, `COPY e2e`, и др.

### rustc / зависимости

Builder: `rust:1-alpine` (≥ 1.88).

### Kafka ↔ Zookeeper

Проверьте bridge-сеть Docker. На хостах с ограниченным iptables используйте нормальный Docker host или k8s.

### Proxy egress из контейнера

```bash
docker exec <proxy> wget -q -O- --timeout=5 http://httpbin.org/get
```

В проблемных средах: `--network host` (только отладка).

---

## Остановка

```bash
docker compose down
docker compose -f docker-compose.test.yml down
```
