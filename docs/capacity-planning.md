# Capacity Planning

Планирование ёмкости для корпоративного развёртывания BSDM-Proxy.

> Wiki: [Capacity Planning](https://github.com/onixus/bsdm-proxy/wiki/Capacity-Planning) (держите в синхроне с этим файлом).

## Статус цифр

Таблицы ниже — **estimate / planning sketch**, не результат нагрузочного прогона на N пользователей.
Ориентиры сверены с арифметикой событий и lab-бенчами data plane; пиковый RPS и железо analytics plane
нужно перемерить на своём трафике (MITM %, hit-rate, `KAFKA_SAMPLE_RATE`, req/page).

Peak RPS в рефе — **прокси-запросы / CacheEvent**, не page loads. При ~70 ресурсах на
страницу (HTTP Archive median) 350 RPS ≈ единицы полноценных page/s.

## Референс-сценарий (corporate medium)

| Параметр | Значение | Как получено |
|----------|----------|--------------|
| Пользователи | 5 000 | сценарий-ориентир |
| Серверы (endpoints) | 300 | сценарий-ориентир (не «нагрузка на proxy») |
| Hot logs (ClickHouse) | 42 дня (TTL) | политика хранения |
| Cold logs | 28 дней | политика хранения |
| Events/day | ~4M | ≈ 800 событий/user/day × 5k |
| Avg RPS | ~46 | 4M / 86 400 |
| Peak RPS | ~330–350 | ≈ ×7–8 к среднему (офисный пик) |

## Профили кеша

| Профиль | Пользователи (ориентир) | `CACHE_CAPACITY` | `MAX_CACHE_BODY_SIZE` | `CACHE_TTL` | `CACHE_COMPRESSION` | `REDIS_L2` | `CACHE_SHARDS` | `CACHE_SPILL_THRESHOLD` |
|---------|-------------------------|------------------|----------------------|-------------|---------------------|------------|----------------|-------------------------|
| Lab / dev (defaults) | — | 10 000 | 10 MB | 3600 | off | off | 16 | 256 KB |
| **Малый prod** | **~0.5–1.5k** | **50 000** | **4 MB** | **3600** | **zstd** | **optional** | **16** | **256 KB** |
| Corporate medium | ~5k | 100 000 | 2 MB | 7200 | zstd | on | 16–32 | 256 KB |
| Экономия RAM | lab / edge | 5 000 | 512 KB | 600 | off | off | 8 | 128 KB |

```bash
# Corporate medium — см. packaging/config/bsdm-proxy.env.example
CACHE_CAPACITY=100000
MAX_CACHE_BODY_SIZE=2097152
CACHE_TTL_SECONDS=7200
CACHE_COMPRESSION=zstd
CACHE_COMPRESS_MIN_BYTES=1048576
CACHE_SHARDS=16
CACHE_SPILL_THRESHOLD_BYTES=262144
REDIS_L2_ENABLED=true
```

```bash
# Малый prod (~1k users) — Lite SWG или полный стек с урезанным analytics
CACHE_CAPACITY=50000
MAX_CACHE_BODY_SIZE=4194304
CACHE_TTL_SECONDS=3600
CACHE_COMPRESSION=zstd
CACHE_SHARDS=16
CACHE_SPILL_THRESHOLD_BYTES=262144
WORKER_COUNT=1
REDIS_L2_ENABLED=false
```

## Ресурсы: corporate medium (~4M events/day)

vCPU / RAM / диск в строках — **на один инстанс**. Итоги считаются явно для CH=1 и CH=3.

| Компонент | Кол-во | vCPU / инст. | RAM / инст. | Диск / инст. |
|-----------|--------|--------------|-------------|--------------|
| bsdm-proxy | 4 | 8 | 16 GB | 50 GB SSD |
| Redis L2 | 2 | 4 | 32 GB | 100 GB |
| Kafka | 3 | 4 | 16 GB | 200 GB |
| ClickHouse | 1 или 3 | 8 | 32 GB | 500 GB NVMe |

| Итого | vCPU | RAM | Диск |
|-------|------|-----|------|
| **CH ×1** (типичный старт) | **60** | **208 GB** | **~1.5 TB** |
| **CH ×3** (HA analytics) | **76** | **272 GB** | **~2.5 TB** |

Monitoring (Prometheus / Grafana / Alertmanager) — обычно на отдельных нодах; в итоги выше не входит
(~2–4 vCPU / 4–8 GB).

Data plane при ~350 peak RPS сам по себе легче, чем 4×8 vCPU: запас заложен под MITM, ACL,
иерархию и рост. Тяжесть рефа — **Kafka + ClickHouse + Redis L2**.

## Ресурсы: малый prod (~1k users)

Ориентир: peak **~60–70 RPS**, **~0.8M** events/day (×0.2 от medium). Не линейный «÷5» всей
таблицы medium — analytics plane масштабируется ступеньками.

| Вариант | Состав | vCPU | RAM | Диск |
|---------|--------|------|-----|------|
| **Lite SWG** (без Kafka/CH) | 2× proxy за LB | ~8 | ~16 GB | ~80 GB SSD |
| **Полный** | 2× proxy + Kafka 1–3 + CH×1 (+ Redis opt.) | ~20–30 | ~50–80 GB | ~0.5 TB |

На инстанс proxy: **4 vCPU / 8 GB / 40 GB SSD** (spill + CA). Redis L2 при ~1k **не обязателен**.

## Squid rock ↔ BSDM spill (HTTP Archive / large objects)

Squid stores small objects in `cache_mem` and larger ones in `cache_dir rock`. BSDM mirrors that split with **inline L1** vs **mmap spill**, plus accept workers.

| Squid | BSDM | Role |
|-------|------|------|
| `cache_mem` | `CACHE_CAPACITY` × shards (inline entries) | Hot small objects in RAM |
| `cache_dir rock <path> <MB>` | `CACHE_SPILL_DIR` + disk under spill threshold | Large bodies on disk (mmap) |
| `maximum_object_size` | `MAX_CACHE_BODY_SIZE` | Hard cap per object |
| `maximum_object_size_in_memory` | `CACHE_SPILL_THRESHOLD_BYTES` | Above threshold → spill file, not inline |
| `workers N` | `WORKER_COUNT` | Accept loops (`SO_REUSEPORT`) |

Reference Squid bench config: [`scripts/squid-benchmark-tuned.conf`](../scripts/squid-benchmark-tuned.conf) — `workers 4`, `cache_dir rock … 1024`, `cache_mem 256 MB`, `maximum_object_size 10 MB`.

### Example: ~2.6 MB objects (HTTP Archive CDN)

Typical HA warm objects are a few MB. Keep spill threshold **well below** median body size so large responses do not bloat process RSS:

```bash
# Squid-tuned parity sketch (see scripts/squid-benchmark-tuned.conf)
WORKER_COUNT=4
CACHE_SHARDS=16
CACHE_CAPACITY=10000          # entries (not bytes); sharded across CACHE_SHARDS
CACHE_SPILL_THRESHOLD_BYTES=262144   # 256 KiB — bodies ≥ this → mmap spill
MAX_CACHE_BODY_SIZE=10485760         # 10 MiB (matches Squid maximum_object_size)
CACHE_SPILL_DIR=/var/cache/bsdm-proxy/spill
```

**Rule of thumb:** set `CACHE_SPILL_THRESHOLD_BYTES` ≈ 64–256 KiB for CDN/static workloads; raise only if most responses are tiny and you want fewer spill files. Scale `CACHE_SHARDS` with CPU (16 default; 32 on busy multi-core). Pair with `WORKER_COUNT=4` when comparing to the tuned Squid workers profile.

Bench scripts: `scripts/run-httparchive-benchmark.sh`, `scripts/compare-squid-bsdm-httparchive.sh` (`BENCH_PROFILE=warm|cold`).

## Kubernetes

См. [k8s-architecture.md](k8s-architecture.md) и Helm chart [`charts/bsdm/`](../charts/bsdm/README.md).

Локальный HA sketch без k8s: `docker compose -f docker-compose.ha.yml up -d`.
