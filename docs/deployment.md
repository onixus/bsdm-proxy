# Развёртывание BSDM-Proxy

Обзор способов запуска: Docker Compose, native package, Kubernetes.

> См. также: [docker.md](docker.md) · [kubernetes.md](kubernetes.md) · [k8s-architecture.md](k8s-architecture.md) · [packaging/README.md](../packaging/README.md)

---

## Сравнение вариантов

| Вариант | Когда использовать | Плюсы | Минусы |
|---------|-------------------|-------|--------|
| **Docker Compose** | Dev, lab, небольшой прод | Быстрый старт, полный стек | Нужна сборка образов, один хост |
| **Native package** | Bare metal / VM без Docker | systemd, минимум зависимостей | Ручная настройка Kafka/CH |
| **Kubernetes + Helm** | Прод, HA, масштабирование | Оркестрация, probes, chart `charts/bsdm/` | Сложнее, образы всё равно нужны |

---

## Docker Compose (рекомендуется для dev/lab)

### Lite — только прокси

```bash
./scripts/gen-ca.sh
docker compose -f docker-compose.lite.yml up -d --build
```

Один caching HTTPS proxy (MITM + L1), без Kafka/ClickHouse. Подробнее: [lite.md](lite.md).

### Полный стек

```bash
# 1. CA для MITM (если MITM_ENABLED=true)
./scripts/gen-ca.sh

# 2. Запуск
docker compose up -d --build
docker compose ps
```

**Сервисы:** proxy, cache-indexer, Kafka, Zookeeper, ClickHouse, Prometheus, Grafana.

Дополнительные compose-файлы: [docker.md](docker.md#compose-файлы).

### Минимальный тестовый стек

```bash
docker compose -f docker-compose.test.yml up -d --build
./scripts/run-smoke-tests.sh --external
```

В `docker-compose.test.yml`: `MITM_ENABLED=false` — HTTPS идёт через CONNECT-туннель **без кэширования**. Для проверки cache HIT используйте in-process E2E: `./scripts/run-e2e-tests.sh`.

---

## Native package (systemd)

```bash
./scripts/build-package.sh

tar xzf dist/bsdm-proxy-0.5.0-linux-x86_64.tar.gz
cd bsdm-proxy-0.5.0-linux-x86_64
sudo ./install.sh --create-user --systemd
sudo cp /path/to/ca.key /path/to/ca.crt /certs/
sudo systemctl enable --now bsdm-proxy
```

Порты: proxy `1488`, metrics `9090`, cache-indexer admin `8080`, ICP `3130/udp` (opt-in).

Подробнее: [packaging/README.md](../packaging/README.md)

---

## Kubernetes (прод)

k8s решает оркестрацию и сетевое взаимодействие между сервисами, но **не заменяет** сборку образов и настройку приложения.

```bash
helm install bsdm ./charts/bsdm -n bsdm-proxy --create-namespace
# prod:
helm install bsdm ./charts/bsdm -f charts/bsdm/values-prod.yaml -n bsdm-proxy --create-namespace
```

| Ресурс | Компонент | Примечание |
|--------|-----------|------------|
| Helm chart `charts/bsdm/` | proxy Deployment | порты 1488, 9090 |
| Deployment | cache-indexer | admin `:8080`, Search API |
| StatefulSet / managed | Kafka, ClickHouse | часто проще managed вне кластера |
| ServiceMonitor | metrics | scrape proxy + indexer |

Подробнее: [kubernetes.md](kubernetes.md) · [k8s-architecture.md](k8s-architecture.md)

---

## Порты и endpoints

| Сервис | Порт | Endpoint / протокол |
|--------|------|---------------------|
| Proxy HTTP/HTTPS | 1488 | HTTP proxy, CONNECT |
| Proxy metrics / health | 9090 | `/health`, `/ready`, `/metrics` |
| cache-indexer admin | 8080 | `/health`, `/metrics`, `/api/search` |
| ICP | 3130/udp | межкешевые запросы (opt-in) |
| Kafka | 9092 | cache-events |
| ClickHouse HTTP | 8123 | REST / SQL |
| ClickHouse native | 9000 | Grafana datasource |
| Prometheus | 9091 | UI (в compose) |
| Grafana | 3000 | UI (`admin` / `admin`) |

---

## Проверка после развёртывания

```bash
curl http://localhost:9090/health
curl http://localhost:9090/ready
curl -x http://localhost:1488 http://httpbin.org/get

# Analytics (после трафика через proxy)
curl 'http://localhost:8123/?query=SELECT+count()+FROM+bsdm.http_cache'
curl 'http://localhost:8080/api/search?limit=5'
```

---

## Зависимости между сервисами

```
proxy ──► Kafka ──► cache-indexer ──► ClickHouse (bsdm.http_cache)
  │                                        ▲
  └──► :9090/metrics ──► Prometheus ──► Grafana (CH + Prometheus)
```

---

## Версии

| Артефакт | Версия |
|----------|--------|
| Текущий release | **0.5.0** |
| Kafka (compose) | Confluent `7.9.8` |
| ClickHouse (compose) | см. `docker-compose.yml` |
| Rust (минимум) | `1.88+` |
| Helm chart | `charts/bsdm/` |
