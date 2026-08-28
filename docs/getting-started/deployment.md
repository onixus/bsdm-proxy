# Развёртывание BSDM-Proxy
 
Текущая версия workspace: **`0.9.13`**.

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
docker compose -f deploy/compose/docker-compose.lite.yml up -d --build
docker compose -f deploy/compose/docker-compose.lite.yml ps
```

Проверка:

```bash
curl http://127.0.0.1:9090/health
curl --cacert certs/ca.crt \
  -x http://127.0.0.1:3128 \
  https://httpbin.org/get
curl 'http://127.0.0.1:8080/api/search?limit=5'
```

Подробнее: [Lite mode](lite-mode.md).

## Analytics Compose

Базовый стек:

```bash
# 0. Обязательные секреты (стек fail-closed и не стартует без них)
export GRAFANA_ADMIN_PASSWORD='...'
export CONTROL_API_TOKEN="$(openssl rand -hex 32)"
export SEARCH_API_TOKEN="$(openssl rand -hex 32)"
# AUTH_ENABLED=true по умолчанию: подставьте свой файл пользователей
# (scripts/gen-basic-auth-user.sh), иначе смонтируется пример с публичными хешами.
export BASIC_AUTH_USERS_HOST=./config/basic-auth-users.json
./scripts/gen-ca.sh
docker compose up -d --build
docker compose ps
```

Базовый стек fail-closed: `AUTH_ENABLED=true`, `ACL_ENABLED=true`,
`CONTROL_API_ALLOW_INSECURE=false`,
`SEARCH_API_ALLOW_INSECURE=false`. Без `CONTROL_API_TOKEN` proxy и без
`SEARCH_API_TOKEN` cache-indexer завершаются на старте с сообщением, называющим
недостающую переменную. ACL включён и применяет deny-правила из
`config/bsdm-etc/acl-rules.json` (blocklist: всё, что не запрещено явно,
проходит). Одноразовый стенд без всего этого:
`deploy/compose/docker-compose.lite.yml`.

Состав: proxy, dns-sinkhole, Kafka, Zookeeper, ClickHouse, cache-indexer, Prometheus,
Alertmanager и Grafana.

Профили (опциональные модули):

```bash
# Threat Intelligence коллектор
docker compose --profile threat-intel up -d --build

# Детекция алертов и ML-скоринг
docker compose --profile alerts --profile ml up -d --build

# DNS Sinkhole
docker compose --profile dns-sinkhole up -d --build

# ICAP антивирусная проверка (ClamAV)
docker compose --profile icap up -d
```

Профиль означает только запуск контейнера. Он не заменяет certificates, secrets,
zone files, model selection и проверку external endpoints.

Пилотный профиль на одном сервере:
[100 пользователей / 5 дней](pilot-deployment.md).

## Дополнительные Compose-сценарии

| Файл | Назначение |
|---|---|
| `deploy/compose/docker-compose.lite.yml` | Proxy + SQLite |
| `deploy/compose/docker-compose.test.yml` | Smoke/E2E stack |
| `deploy/compose/docker-compose.pilot.yml` | Override ресурсов и retention для пилота на 100 пользователей |
| `deploy/compose/docker-compose.redis-l2.yml` | Redis L2 example |
| `deploy/compose/docker-compose.hierarchy.yml` | Multi-proxy hierarchy |
| `deploy/compose/docker-compose.ha.yml` | Лабораторный HA sketch |
| `deploy/compose/docker-compose.awg.yml` | Experimental AWG sidecar |

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
| proxy | 3128 | HTTP proxy / CONNECT |
| proxy control | 9090 | `/health`, `/ready`, `/metrics`, `/admin/` |
| cache-indexer | 8080 | `/health`, `/metrics`, `/api/search` |
| alert-worker | 8090 | `/health`, `/metrics` (детекция инцидентов) |
| ml-worker | 8091 | `/health`, `/metrics` (ML-скоринг) |
| dns-sinkhole | 8092 / 5353 | `/health`, `/metrics`, DoH/DoT и RPZ DNS (5353/udp) |
| threat-intel | 8093 | `/health`, `/metrics`, SOAR / ML API |
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
curl -x http://127.0.0.1:3128 http://httpbin.org/get
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
