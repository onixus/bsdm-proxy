# Capacity Planning

Планирование ёмкости для корпоративного развёртывания BSDM-Proxy.

> Wiki (актуальная версия): [Capacity Planning](https://github.com/onixus/bsdm-proxy/wiki/Capacity-Planning)

## Референс-сценарий

| Параметр | Значение |
|----------|----------|
| Пользователи | 5 000 |
| Серверы | 300 |
| Hot logs (ClickHouse) | 42 дня (TTL) |
| Cold logs | 28 дней (4 недели) |
| Events/day (medium) | ~4M |
| Peak RPS | ~330–350 |

## Рекомендуемые лимиты кеша

| Профиль | `CACHE_CAPACITY` | `MAX_CACHE_BODY_SIZE` | `CACHE_TTL` | `CACHE_COMPRESSION` | `REDIS_L2` | `CACHE_SHARDS` | `CACHE_SPILL_THRESHOLD` |
|---------|------------------|----------------------|-------------|---------------------|------------|----------------|-------------------------|
| Lab / dev (defaults) | 10 000 | 10 MB | 3600 | off | off | 16 | 256 KB |
| Малый prod | 50 000 | 4 MB | 3600 | zstd | optional | 16 | 256 KB |
| **Corporate medium** | **100 000** | **2 MB** | **7200** | **zstd** | **on** | **16–32** | **256 KB** |
| Экономия RAM | 5 000 | 512 KB | 600 | off | off | 8 | 128 KB |

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

## Ресурсы (medium, ~4M events/day)

| Компонент | Кол-во | vCPU | RAM | Диск |
|-----------|--------|------|-----|------|
| bsdm-proxy | 4 | 8 | 16 GB | 50 GB SSD |
| Redis L2 | 2 | 4 | 32 GB | 100 GB |
| Kafka | 3 | 4 | 16 GB | 200 GB |
| ClickHouse | 1–3 | 8 | 32 GB | 500 GB NVMe |
| **Итого** | — | ~80 | ~350 GB | ~1.3 TB |

Полные формулы, модели нагрузки и риски — на [wiki](https://github.com/onixus/bsdm-proxy/wiki/Capacity-Planning).

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
CACHE_CAPACITY=10000          # entries per shard (not bytes)
CACHE_SPILL_THRESHOLD_BYTES=262144   # 256 KiB — bodies ≥ this → mmap spill
MAX_CACHE_BODY_SIZE=10485760         # 10 MiB (matches Squid maximum_object_size)
CACHE_SPILL_DIR=/var/cache/bsdm-proxy/spill
```

**Rule of thumb:** set `CACHE_SPILL_THRESHOLD_BYTES` ≈ 64–256 KiB for CDN/static workloads; raise only if most responses are tiny and you want fewer spill files. Scale `CACHE_SHARDS` with CPU (16 default; 32 on busy multi-core). Pair with `WORKER_COUNT=4` when comparing to the tuned Squid workers profile.

Bench scripts: `scripts/run-httparchive-benchmark.sh`, `scripts/compare-squid-bsdm-httparchive.sh` (`BENCH_PROFILE=warm|cold`).

## Kubernetes

См. [k8s-architecture.md](k8s-architecture.md) и Helm chart [`charts/bsdm/`](../charts/bsdm/README.md).

Локальный HA sketch без k8s: `docker compose -f docker-compose.ha.yml up -d`.
