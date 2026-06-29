# Performance tuning (×2 RPS без DPDK)

Цель — удвоить пропускную способность на том же железе за счёт оптимизации userspace hot path и multi-worker accept, без kernel bypass (DPDK).

## Baseline (0.2.3-test, 4 vCPU)

| Сценарий | ~RPS |
|----------|------|
| wrk L1 HIT | 56k |
| wrk L1 MISS | 6.1k |
| curl HIT | 888 |

Цель после perf-режима: **≥110k wrk L1 HIT**.

## Переменные окружения

| Переменная | Default | Описание |
|------------|---------|----------|
| `PERF_FAST_CACHE_HIT` | `false` | L1 HIT до ACL: без policy/Kafka/heavy metrics |
| `BSM_PERF_MODE` | `false` | Алиас `PERF_FAST_CACHE_HIT=true` |
| `WORKER_COUNT` | `1` | Число accept-loop с SO_REUSEPORT (Linux) |
| `HTTP_PRESERVE_HEADER_CASE` | `true` | `false` убирает preserve/title-case в http1 (bench) |
| `KAFKA_SAMPLE_RATE` | `0` | `N` → 1 из N cache events в Kafka (`0` = все) |
| `METRICS_SAMPLE_RATE` | `0` | `N` → histograms для 1 из N запросов (`0` = все) |

## Рекомендуемый bench-профиль

```bash
cargo build --release -p bsdm-proxy --bin proxy

HTTP_PORT=12788 METRICS_PORT=19190 \
  MITM_ENABLED=false HIERARCHY_ENABLED=false RUST_LOG=warn \
  PERF_FAST_CACHE_HIT=true WORKER_COUNT=1 \
  METRICS_SAMPLE_RATE=100 HTTP_PRESERVE_HEADER_CASE=false \
  ./target/release/proxy
```

## Бенчмарк

```bash
./scripts/compare-squid-bsdm.sh          # Squid vs BSDM, стандартный wrk/curl
./scripts/run-proxy-benchmark.sh HOST:PORT LABEL
```

## Профилирование

```bash
./scripts/perf-profile.sh
sudo perf report -i /tmp/bsdm-perf.data
```

## Архитектура hot path

1. **L1 lookup** (`quick_cache`) — самый частый путь.
2. **`PERF_FAST_CACHE_HIT`**: HIT возвращается до ACL/categorization; Kafka и histograms опциональны.
3. **`WORKER_COUNT`**: N процессов accept на одном порту (SO_REUSEPORT), общий L1 `Arc<Cache>`.
4. **ACL**: `RwLock` + `check_access(&self)` — read-mostly без сериализации на каждый MISS.
5. **Kafka**: sampling через `KAFKA_SAMPLE_RATE`.

## Production vs bench

| | Bench | Production |
|---|-------|------------|
| `PERF_FAST_CACHE_HIT` | `true` | `false` |
| `WORKER_COUNT` | `4` (по CPU) | `4` |
| `KAFKA_SAMPLE_RATE` | — | `10` |
| `HTTP_PRESERVE_HEADER_CASE` | `false` | `true` (MITM) |

См. также [architecture.md](architecture.md), [logging.md](logging.md).
