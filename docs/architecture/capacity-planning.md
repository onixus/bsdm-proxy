# Capacity planning

Сайзинг BSDM-Proxy нельзя надёжно получить только из числа пользователей.
Основные факторы — peak requests/s, HTTPS MITM, bandwidth, размер объектов,
cache hit ratio, число событий, retention и включённые security-модули.

Все значения ниже — инженерная оценка. Они должны быть подтверждены нагрузочным
тестом на трафике пилота.

## Базовый пилот

Текущий референс:

- 100 пользователей, 50–70 одновременно активных;
- 50–100 proxy requests/s в пике;
- до 500 000 событий в сутки;
- до 500 Mbit/s кратковременного трафика;
- 5 суток хранения;
- без HA, DLP, reverse proxy, ICAP и ClamAV.

| Профиль | vCPU | RAM | NVMe |
|---|---:|---:|---:|
| Минимальный | 8 | 16 GiB | 150 GB |
| **Рекомендуемый** | **12** | **24 GiB** | **200 GB** |
| Нагрузочный запас | 12–16 | 32 GiB | 250 GB |

Полный состав и настройки: [Пилот на 100 пользователей](../getting-started/pilot-deployment.md).

## Формула analytics storage

Расчёт числа строк:

```text
rows = events_per_day × retention_days
```

Расчёт рабочей ёмкости:

```text
clickhouse_working_set =
  rows × compressed_bytes_per_row × merge_factor
```

Для первичной оценки:

- `compressed_bytes_per_row`: 300–1000 байт;
- `merge_factor`: 2–3 для parts, merges и эксплуатационного запаса.

Для пилота:

```text
500 000 × 5 = 2 500 000 rows
2 500 000 × 0.3–1.0 KB × 3 = 2.25–7.5 GB
```

Выделение **40 GB под ClickHouse** оставляет запас на feature tables,
неравномерные строки и временные merges.

Kafka sizing считается отдельно:

```text
kafka_disk =
  events_per_day × raw_event_bytes × kafka_retention_days × replication_factor
```

При одном пилотном брокере, 1–2 KB на событие и retention 1–2 дня достаточно
нескольких гигабайт; рекомендуется выделить 20 GB.

## L1 cache

`CACHE_CAPACITY` — **общее количество записей в одном процессе proxy**.
`HttpL1Cache` делит это число между `CACHE_SHARDS`:

```text
per_shard = CACHE_CAPACITY / CACHE_SHARDS
```

Нельзя рассчитывать L1 как `CACHE_CAPACITY × CACHE_SHARDS`.

RAM для inline-объектов:

```text
l1_ram ≈ inline_entries × average_inline_body × overhead
```

Чтобы крупные объекты не занимали heap, используйте mmap spill:

```env
CACHE_CAPACITY=20000
CACHE_SHARDS=16
CACHE_SPILL_THRESHOLD_BYTES=262144
CACHE_SPILL_DIR=/var/cache/bsdm-spill
MAX_CACHE_BODY_SIZE=4194304
```

Порог 128–256 KiB подходит как начальный. Подбирайте его по распределению
размеров объектов и измеренному RSS.

## Redis L2

Для одного proxy Redis не обязателен. Он нужен, если требуется:

- общий L2 между репликами;
- сохранение части cache hit ratio после рестарта proxy;
- проверка distributed cache сценария.

Пилотный лимит:

```text
maxmemory 2gb
maxmemory-policy allkeys-lfu
```

Не оставляйте Redis без `maxmemory`: L2 хранит сериализованные ответы и может
занять весь доступный RAM.

## Semantic index

Default local index:

```text
10 000 vectors × 64 dimensions × 4 bytes = 2.56 MB raw vectors
```

С учётом keys и структур поиска ему не нужны десятки гигабайт RAM. Для пилота:

- local index: входит в RAM proxy;
- Qdrant: 1–2 GiB RAM и 5–10 GB disk;
- отдельный embedding model считается отдельно.

При embeddings 768–1536 dimensions и сотнях тысяч записей пересчитайте raw
vectors и HNSW overhead по фактической коллекции.

## CPU и сеть

Proxy CPU определяют:

- TLS handshakes и доля MITM;
- cache MISS и upstream TLS;
- compression;
- policy/auth checks;
- WASM/ICAP/DLP, если они включены;
- bandwidth и размер response body.

Micro-benchmarks L1 HIT не заменяют full-path test. В частности,
`PERF_FAST_CACHE_HIT=true` может обходить ACL/categorization и не должен
использоваться при обязательной проверке политики.

Для пилота требуется 1 Gbit/s NIC. Если рабочий трафик стабильно превышает
300 Mbit/s, измеряйте softirq, TLS CPU и disk throughput spill.

## Дополнительные модули

| Модуль | Эффект |
|---|---|
| WASM | CPU на каждый hook; зависит от fuel и guest logic |
| ICAP/ClamAV | CPU/RAM scanner и buffering; считать отдельным профилем |
| DLP | Сканирование request body; считать по объёму upload |
| DoH/DoT | TLS handshakes на DNS endpoint |
| Qdrant | Зависит от dimensions и количества векторов, не числа пользователей |
| ML workers | ClickHouse query cost; одна модель на процесс |
| Redis L2 | RAM зависит от body sizes и eviction policy |

Не включайте experimental-модуль в production budget без отдельного теста его
реального пути.

## Переход от пилота к production

Первая ступень масштабирования:

| Узел | Состав | Стартовый размер |
|---|---|---|
| Edge-1 | proxy + optional DNS/AWG | 4 vCPU / 8 GiB / 60 GB |
| Edge-2 | proxy + optional DNS/AWG | 4 vCPU / 8 GiB / 60 GB |
| Analytics | Kafka, ClickHouse, workers, monitoring | 12 vCPU / 32 GiB / 300 GB |

Это не обязательный размер для 100 пользователей. Переход оправдан, когда нужна
data-plane redundancy или измерения показывают конкуренцию proxy и analytics за
CPU, RAM или disk I/O.

## Метрики для решения

Масштабируйте по наблюдениям:

- proxy CPU/RSS и p95/p99 latency;
- active connections и TLS handshake rate;
- cache hit ratio и spill disk usage;
- Kafka producer errors и consumer lag;
- ClickHouse query latency, parts и merge backlog;
- ML cycle duration;
- Prometheus TSDB size;
- host network, disk latency и free space.

Сайзинг пересматривается после изменения retention, event sampling, body limits
или набора включённых модулей.
