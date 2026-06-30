# Capacity Planning

Планирование ёмкости для корпоративного развёртывания BSDM-Proxy.

> Wiki (актуальная версия): [Capacity Planning](https://github.com/onixus/bsdm-proxy/wiki/Capacity-Planning)

## Референс-сценарий

| Параметр | Значение |
|----------|----------|
| Пользователи | 5 000 |
| Серверы | 300 |
| Hot logs (OpenSearch) | 14 дней |
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
| OpenSearch hot | 3 | 8 | 64 GB | 300 GB NVMe |
| OpenSearch cold | 2 | 4 | 32 GB | 500 GB |
| **Итого** | — | ~80 | ~350 GB | ~1.3 TB |

Полные формулы, модели нагрузки и риски — на [wiki](https://github.com/onixus/bsdm-proxy/wiki/Capacity-Planning).
