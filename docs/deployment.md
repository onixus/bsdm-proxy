# Развёртывание BSDM-Proxy

Обзор способов запуска: Docker Compose, native package, Kubernetes.

> См. также: [docker.md](docker.md) · [kubernetes.md](kubernetes.md) · [packaging/README.md](../packaging/README.md)

---

## Сравнение вариантов

| Вариант | Когда использовать | Плюсы | Минусы |
|---------|-------------------|-------|--------|
| **Docker Compose** | Dev, lab, небольшой прод | Быстрый старт, полный стек | Нужна сборка образов, один хост |
| **Native package** | Bare metal / VM без Docker | systemd, минимум зависимостей | Ручная настройка Kafka/OS |
| **Kubernetes** | Прод, HA, масштабирование | Оркестрация, probes, rolling update | Сложнее, образы всё равно нужны |

---

## Docker Compose (рекомендуется для dev/lab)

### Полный стек

```bash
# 1. CA для MITM (если MITM_ENABLED=true)
mkdir -p certs && cd certs
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=RU/ST=Moscow/L=Moscow/O=BSDM/CN=BSDM Root CA"
cd ..

# 2. Запуск
docker compose up -d --build
docker compose ps
```

**Сервисы:** proxy, cache-indexer, Kafka, Zookeeper, OpenSearch, OpenSearch Dashboards, Prometheus, Grafana.

Подробнее: [docker.md](docker.md)

### Минимальный тестовый стек

```bash
docker compose -f docker-compose.test.yml up -d --build
./scripts/run-smoke-tests.sh --external
```

В `docker-compose.test.yml`: `MITM_ENABLED=false` — HTTPS идёт через CONNECT-туннель **без кэширования**. Для проверки cache HIT используйте in-process E2E: `./scripts/run-e2e-tests.sh`.

---

## Native package (systemd)

```bash
# Сборка пакета
./scripts/build-package.sh

# Установка (версия из proxy/Cargo.toml)
tar xzf dist/bsdm-proxy-0.2.3test-linux-x86_64.tar.gz
cd bsdm-proxy-0.2.3test-linux-x86_64
sudo ./install.sh --create-user --systemd
sudo cp /path/to/ca.key /path/to/ca.crt /certs/
sudo systemctl enable --now bsdm-proxy
```

Порты по умолчанию: proxy `1488`, metrics `9090`, ICP `3130/udp` (при `HIERARCHY_ENABLED=true`).

Подробнее: [packaging/README.md](../packaging/README.md)

---

## Kubernetes (прод)

k8s решает оркестрацию и сетевое взаимодействие между сервисами, но **не заменяет** сборку образов и настройку приложения.

Минимальная схема:

| Ресурс | Компонент | Примечание |
|--------|-----------|------------|
| Deployment + Service | `proxy` | порты 1488, 9090; readiness на `/ready` |
| Deployment | `cache-indexer` | без внешних портов |
| StatefulSet / managed | Kafka, OpenSearch | часто проще managed-сервисы вне кластера |
| ServiceMonitor | metrics | scrape `:9090/metrics` |
| Ingress / Gateway | proxy | для клиентов |

Подробнее: [kubernetes.md](kubernetes.md)

---

## Порты и endpoints

| Сервис | Порт | Endpoint / протокол |
|--------|------|---------------------|
| Proxy HTTP/HTTPS | 1488 | HTTP proxy, CONNECT |
| Metrics / health | 9090 | `/health`, `/ready`, `/metrics` |
| ICP | 3130/udp | межкешевые запросы (opt-in) |
| Kafka | 9092 | cache-events |
| OpenSearch | 9200 | REST API |
| OpenSearch Dashboards | 5601 | UI |
| Prometheus | 9091 | UI (в compose) |
| Grafana | 3000 | UI (`admin` / `admin`) |

---

## Проверка после развёртывания

```bash
# Health
curl http://localhost:9090/health    # {"status":"ok"}
curl http://localhost:9090/ready     # {"status":"ready"}

# Метрики (счётчики появляются после первых запросов)
curl http://localhost:9090/metrics | grep bsdm_proxy

# Проксирование
curl -x http://localhost:1488 http://httpbin.org/get

# OpenSearch (полный стек)
curl http://localhost:9200/_cluster/health
```

---

## Зависимости между сервисами

```
proxy ──► Kafka ──► cache-indexer ──► OpenSearch
  │
  └──► :9090/metrics ──► Prometheus ──► Grafana
```

Proxy стартует после healthy Kafka. cache-indexer — после Kafka и OpenSearch. dashboards-setup — после OpenSearch Dashboards.

---

## Версии в репозитории

| Артефакт | Версия |
|----------|--------|
| Cargo (proxy, cache-indexer) | `0.2.3-test` |
| Последний release tag | `0.2.2b` |
| OpenSearch (compose) | `3.7.0` |
| Kafka (compose) | Confluent `7.9.8` |
| Rust (минимум) | `1.88+` (рекомендуется stable latest) |
