# Развёртывание BSDM-Proxy

Текущая версия workspace: **`0.6.1-1`**.

Сначала выберите режим:

| Режим | Состав | Назначение |
|---|---|---|
| Lite | proxy + SQLite indexer | Dev, lab, edge |
| Analytics Compose | proxy + Kafka + ClickHouse + monitoring | Пилот |
| Native | systemd binaries + external dependencies | VM/bare metal |
| Kubernetes | Helm + external/in-cluster analytics | Масштабирование и HA |

Фактическая зрелость модулей: [Project status](../project-status.md).

## Подготовка CA

MITM требует CA keypair:

```bash
./scripts/gen-ca.sh
```

Установите `certs/ca.crt` в trust store тестовых клиентов. `ca.key` должен быть
доступен только proxy. Не коммитьте CA key в Git и не используйте lab CA в
production.

Без MITM:

```env
MITM_ENABLED=false
```

HTTPS в этом режиме идёт как CONNECT tunnel и не проходит HTTP body/cache path.

## Lite

```bash
./scripts/gen-ca.sh
docker compose -f docker-compose.lite.yml up -d --build
docker compose -f docker-compose.lite.yml ps
```

Проверка:

```bash
curl http://127.0.0.1:9090/health
curl --cacert certs/ca.crt \
  -x http://127.0.0.1:1488 \
  https://httpbin.org/get
curl 'http://127.0.0.1:8080/api/search?limit=5'
```

Подробнее: [Lite mode](lite-mode.md).

## Analytics Compose

Базовый стек:

```bash
./scripts/gen-ca.sh
docker compose up -d --build
docker compose ps
```

Состав: proxy, Kafka, Zookeeper, ClickHouse, cache-indexer, Prometheus,
Alertmanager и Grafana.

Профили:

```bash
docker compose --profile alerts up -d --build
docker compose --profile ml up -d --build
docker compose --profile dns-sinkhole up -d --build
docker compose --profile icap up -d
```

Профиль означает только запуск контейнера. Он не заменяет certificates, secrets,
zone files, model selection и проверку external endpoints.

Пилотный профиль на одном сервере:
[100 пользователей / 5 дней](pilot-deployment.md).

## Дополнительные Compose-сценарии

| Файл | Назначение |
|---|---|
| `docker-compose.lite.yml` | Proxy + SQLite |
| `docker-compose.test.yml` | Smoke/E2E stack |
| `docker-compose.pilot.yml` | Override ресурсов и retention для пилота на 100 пользователей |
| `docker-compose.redis-l2.yml` | Redis L2 example |
| `docker-compose.hierarchy.yml` | Multi-proxy hierarchy |
| `docker-compose.ha.yml` | Лабораторный HA sketch |
| `docker-compose.awg.yml` | Experimental AWG sidecar |

Не объединяйте overlays автоматически: проверьте network names, ports, volumes и
environment каждого файла.

## Native package

Сборка:

```bash
./scripts/build-package.sh
```

Имя архива зависит от версии workspace и архитектуры. Не копируйте историческое
имя из release notes; проверьте `dist/`:

```bash
ls -1 dist/
tar xzf dist/bsdm-proxy-<version>-linux-<arch>.tar.gz
cd bsdm-proxy-<version>-linux-<arch>
sudo ./install.sh --create-user --systemd
```

Скопируйте CA и настройте `/etc/bsdm-proxy` до запуска service.

Подробнее: [Packaging](../../packaging/README.md).

## Kubernetes

Default chart:

```bash
helm upgrade --install bsdm ../../charts/bsdm \
  --namespace bsdm-proxy \
  --create-namespace
```

Проверьте values перед применением: default resources и `values-prod.yaml`
являются примерами, а не универсальным сайзингом.

Analytics plane можно разместить отдельно:

```bash
helm upgrade --install bsdm-indexer ../../charts/bsdm \
  --namespace bsdm-analytics \
  --create-namespace \
  -f ../../charts/bsdm/values-analytics.yaml
```

Подробнее: [Kubernetes architecture](../ops-and-dev/k8s-architecture.md).

## Endpoints

| Компонент | Порт | Endpoint |
|---|---:|---|
| proxy | 1488 | HTTP proxy / CONNECT |
| proxy control | 9090 | `/health`, `/ready`, `/metrics` |
| cache-indexer | 8080 | `/health`, `/metrics`, `/api/search` |
| ICP | 3130/udp | hierarchy |
| Kafka | 9092 | cache-events |
| ClickHouse | 8123 / 9000 | HTTP / native |
| Prometheus | 9091 | Compose host port |
| Grafana | 3000 | UI |

В production не публикуйте Kafka, ClickHouse, Redis и unauthenticated control
endpoints в client network.

## Проверка

```bash
curl http://127.0.0.1:9090/health
curl http://127.0.0.1:9090/ready
curl -x http://127.0.0.1:1488 http://httpbin.org/get
curl 'http://127.0.0.1:8123/?query=SELECT+count()+FROM+bsdm.http_cache'
curl 'http://127.0.0.1:8080/api/search?limit=5'
```

Диагностика:

```bash
docker compose ps
docker compose logs --tail=200 proxy
docker compose logs --tail=200 cache-indexer
```

## Production checklist

- CA key защищён и имеет rotation/backup procedure;
- secrets не хранятся в Compose/values plaintext;
- control/search/metrics endpoints ограничены;
- Redis имеет `maxmemory`;
- Kafka и ClickHouse retention заданы явно;
- storage backup/restore проверен;
- optional features соответствуют [Project status](../project-status.md);
- full-path load test выполнен с production flags.
