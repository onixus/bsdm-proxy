# Пилот на 100 пользователей

Референсный профиль предназначен для функционального пилота на одном сервере без
HA. Он не является результатом нагрузочного теста: перед production нужно прогнать
собственный трафик и проверить latency, CPU, RSS, Kafka lag и ClickHouse merges.

## Границы пилота

В пилот входят:

- HTTP/HTTPS forward proxy и MITM;
- Basic/LDAP authentication, ACL, categorization и rate limiting;
- L1 cache, mmap spill и optional Redis L2;
- Kafka, cache-indexer, ClickHouse и Search API;
- alert-worker и выбранные модели ml-worker;
- Prometheus, Grafana и Alertmanager;
- optional DNS sinkhole, DoH/DoT, AWG и local semantic cache.

Из пилота исключены:

- DLP/CASB enforcement;
- reverse proxy/OIDC;
- ICAP и ClamAV;
- production HA и multi-cluster;
- обещания production SLA.

В текущем proxy DLP engine создаётся без отдельного feature switch. Для пилота
очистите паттерны через control API после каждого рестарта:

```bash
curl -X POST http://127.0.0.1:9090/api/security/dlp \
  -H 'Authorization: Bearer <CONTROL_API_TOKEN>' \
  -H 'Content-Type: application/json' \
  --data '[]'
```

Это временный обходной путь: состояние не сохраняется. До production нужен
постоянный `DLP_ENABLED=false` либо сохранение пустой конфигурации.

## Нагрузочная модель

| Параметр | Расчётное значение |
|---|---:|
| Именованные пользователи | 100 |
| Одновременно активные | 50–70 |
| Средняя нагрузка | 3–6 proxy requests/s |
| Расчётный пик | 50–100 proxy requests/s |
| События | до 500 000 в сутки |
| HTTPS MITM | до 100% трафика |
| Рабочий трафик | 100–200 Mbit/s |
| Кратковременный burst | до 500 Mbit/s |
| Горячее хранение | не более 5 суток |

Если фактический трафик включает массовые обновления ПО, большие загрузки или
длительные видеопотоки, главным фактором становится bandwidth и cache spill, а не
число пользователей.

## Ресурсы

| Профиль | vCPU | RAM | NVMe | Сеть |
|---|---:|---:|---:|---:|
| Минимальный функциональный | 8 | 16 GiB | 150 GB | 1 Gbit/s |
| **Рекомендуемый** | **12** | **24 GiB** | **200 GB** | **1 Gbit/s** |
| С запасом для нагрузочного теста | 12–16 | 32 GiB | 250 GB | 1 Gbit/s |

Рекомендуемый профиль — **12 vCPU, 24 GiB RAM, 200 GB NVMe** на одном Linux-хосте.

### Бюджет компонентов

| Компонент | vCPU | RAM | Диск |
|---|---:|---:|---:|
| proxy: MITM, auth, ACL, cache | 4 | 4 GiB | 25 GB spill |
| ClickHouse | 3 | 6 GiB | 40 GB |
| Kafka + Zookeeper | 1–2 | 2–3 GiB | 20 GB |
| cache-indexer | 0.5 | 512 MiB | — |
| alert-worker + ML workers | 1–2 | 2 GiB | 5 GB |
| Prometheus, Grafana, Alertmanager | 1–2 | 3 GiB | 20 GB |
| Redis L2, если включён | 1 | 2 GiB | 10 GB |
| DNS/AWG/local semantic index | 0.5–1 | до 1 GiB | 5 GB |
| ОС, логи, merges и резерв | — | 3–4 GiB | 50–70 GB |

Redis L2 и Qdrant не обязательны для одного proxy. Для проверки semantic cache
используйте local index; Qdrant добавляйте только для отдельного сценария приёмки.

## Compose override

Файл [`docker-compose.pilot.yml`](../../docker-compose.pilot.yml) применяет
пилотные memory/CPU limits (суммарно 12 vCPU и 18 GiB container memory),
включает пятидневный Prometheus retention,
48-часовой Kafka retention, отдельный spill volume и параметры proxy ниже.

Перед запуском задайте токены и параметры выбранного auth/categorization backend:

```bash
export CONTROL_API_TOKEN='<random-control-token>'
export ACL_API_TOKEN='<random-acl-token>'
export SEARCH_API_TOKEN='<random-search-token>'

# Включайте после настройки backend/users:
export AUTH_ENABLED=false
export CATEGORIZATION_ENABLED=false
export UT1_ENABLED=false
```

Не храните значения токенов в Git или shell history production-хоста.

### Конфигурация proxy

Стартовый профиль:

```env
MITM_ENABLED=true
WORKER_COUNT=2

CACHE_CAPACITY=20000
CACHE_SHARDS=16
CACHE_TTL_SECONDS=3600
CACHE_SPILL_THRESHOLD_BYTES=262144
CACHE_SPILL_DIR=/var/cache/bsdm-spill
CACHE_COMPRESSION=zstd
MAX_CACHE_BODY_SIZE=4194304

KAFKA_SAMPLE_RATE=0
METRICS_SAMPLE_RATE=10
PERF_FAST_CACHE_HIT=false
STREAMING_MISS_ENABLED=true

AUTH_ENABLED=true
ACL_ENABLED=true
CATEGORIZATION_ENABLED=true
```

`CACHE_CAPACITY` — общее число записей на процесс proxy. Оно делится между
`CACHE_SHARDS`, а не умножается на число шардов.

Для cache-indexer задайте `SEARCH_API_DEFAULT_DAYS=5`, чтобы default search
соответствовал доступному окну данных.

## Хранение не более 5 суток

Базовая DDL в репозитории имеет более длинный TTL. На новом ClickHouse volume
pilot override автоматически применяет
[`pilot_retention.sql`](../../scripts/clickhouse/pilot_retention.sql). Для уже
инициализированного volume выполните те же команды явно до начала приёмочного
трафика:

```sql
ALTER TABLE bsdm.http_cache
MODIFY TTL ts + INTERVAL 5 DAY;

ALTER TABLE bsdm.entity_features
MODIFY TTL window_start + INTERVAL 5 DAY;

ALTER TABLE bsdm.ml_scores
MODIFY TTL scored_at + INTERVAL 5 DAY;

ALTER TABLE bsdm.domain_phishing_features
MODIFY TTL window_start + INTERVAL 5 DAY;

ALTER TABLE bsdm.beacon_pair_features
MODIFY TTL window_start + INTERVAL 5 DAY;
```

Дополнительно:

- Kafka retention: 24–48 часов;
- Prometheus: `--storage.tsdb.retention.time=5d`;
- Docker logs: ротация 10 MiB × 3 файла;
- Redis: `maxmemory 2gb` и `maxmemory-policy allkeys-lfu`;
- spill: отдельный каталог с лимитом 25–30 GB.

При уже накопленных данных `MATERIALIZE TTL` может создать заметную нагрузку.
Выполняйте его в окно обслуживания или дождитесь фонового удаления.
ClickHouse TTL удаляет данные фоновыми merges и не гарантирует физическое
удаление ровно на границе пяти суток. Если пять дней — жёсткое compliance
ограничение, контролируйте самые старые строки и добавьте плановый
`DROP PARTITION` для дневных partitions.

## Запуск и приёмка

Базовый analytics stack:

```bash
./scripts/gen-ca.sh
docker compose \
  -f docker-compose.yml \
  -f docker-compose.pilot.yml \
  up -d --build
docker compose -f docker-compose.yml -f docker-compose.pilot.yml ps
```

Alert-worker требует непустой `ALERT_WEBHOOK_URL`. Добавляйте alerting и одну
ML-модель только после запуска базового стека:

```bash
export ALERT_WEBHOOK_URL='https://siem.example.invalid/bsdm'
export ML_MODEL='ueba_zscore_v0'
docker compose \
  -f docker-compose.yml \
  -f docker-compose.pilot.yml \
  --profile alerts --profile ml \
  up -d --build
```

После старта очистите DLP patterns командой из раздела
[«Границы пилота»](#границы-пилота) и проверьте ответ `[]` через
`GET /api/security/dlp`:

```bash
curl http://127.0.0.1:9090/api/security/dlp \
  -H "Authorization: Bearer ${CONTROL_API_TOKEN}"
```

Проверки:

```bash
curl http://127.0.0.1:9090/health
curl http://127.0.0.1:9090/ready
curl --cacert certs/ca.crt -x http://127.0.0.1:1488 https://httpbin.org/get
curl 'http://127.0.0.1:8123/?query=SELECT+count()+FROM+bsdm.http_cache'
curl 'http://127.0.0.1:8080/api/search?limit=5'
```

Для полного ML-набора запускайте отдельный `ml-worker` на каждую модель. В первом
пилоте достаточно одной модели и alert-worker; остальные добавляйте по очереди,
измеряя длительность запросов ClickHouse.

## Критерии пересмотра сайзинга

Увеличивайте ресурсы или разделяйте data/analytics plane, если выполняется хотя бы
одно условие:

- CPU proxy выше 70% более 15 минут;
- host RAM выше 80% или начинается swap;
- Kafka consumer lag растёт непрерывно;
- ClickHouse merges не успевают завершаться;
- p95 добавленной proxy latency выходит за установленный SLO;
- рабочий трафик стабильно выше 300 Mbit/s;
- cache spill заполняет более 70% выделенного диска.

Следующий шаг после успешного пилота — две реплики proxy и отдельный analytics
host. Это решение принимается по измерениям, а не линейным умножением числа
пользователей.
