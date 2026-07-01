# Performance tuning (×2 RPS без DPDK)

Цель — удвоить пропускную способность на том же железе за счёт оптимизации userspace hot path и multi-worker accept, без kernel bypass (DPDK).

## Baseline (0.3.0, 4 vCPU)

| Сценарий | Инструмент | ~RPS | Примечание |
|----------|------------|------|------------|
| L1 HIT | wrk | 52–72k | sustained load, keep-alive |
| L1 MISS | wrk | 6–8k | уникальные URL (lua) |
| L1 HIT | **oha** | 50–72k | browser-like keep-alive |
| L1 MISS | **oha** | 3–6k | `--rand-regex-url`, уникальные path |
| L1 HIT | ~~curl xargs~~ | ~900 | **устарело** — потолок harness, не прокси |

Цель после perf-режима: **≥110k wrk L1 HIT**.

### Зависимости бенчмарка

```bash
# Debian/Ubuntu
sudo apt install wrk curl
cargo install oha   # или бинарь с https://github.com/hatoo/oha
```

Старый curl+xargs harness: `BENCH_LEGACY_CURL=1 ./scripts/run-proxy-benchmark.sh ...`

## Переменные окружения (прокси)

| Переменная | Default | Описание |
|------------|---------|----------|
| `PERF_FAST_CACHE_HIT` | `false` | L1 HIT до ACL: без policy/Kafka/heavy metrics |
| `BSM_PERF_MODE` | `false` | Алиас `PERF_FAST_CACHE_HIT=true` |
| `WORKER_COUNT` | `1` | Число accept-loop с SO_REUSEPORT (Linux); **4** для sites/large-object bench |
| `TCP_SNDBUF_BYTES` | `524288` | SO_SNDBUF на клиентских соединениях (`0` = не менять) |
| `CACHE_SHARDS` | `16` | Число шардов L1 (`quick_cache` на шард); снижает contention при `WORKER_COUNT>1` |
| `CACHE_SPILL_THRESHOLD_BYTES` | `262144` | Тела ≥ порога пишутся в mmap spill (`0` = только inline) |
| `CACHE_SPILL_DIR` | `{tmp}/bsdm-cache-spill` | Каталог временных spill-файлов для крупных тел |
| `HTTP_PRESERVE_HEADER_CASE` | `true` | `false` убирает preserve/title-case в http1 (bench) |
| `KAFKA_SAMPLE_RATE` | `0` | `N` → 1 из N cache events в Kafka (`0` = все) |
| `METRICS_SAMPLE_RATE` | `0` | `N` → histograms для 1 из N запросов (`0` = все) |
| `STREAMING_MISS_ENABLED` | `true` | Tee upstream MISS body to client while buffering for L1 |

## HTTP Archive bench profiles (`BENCH_PROFILE`)

Sites bench (70 sites × 20 warm repeats) is **warm-heavy**. Multi-worker accept (`WORKER_COUNT=4`) increases L1 lock contention on repeated HITs; a single worker often wins on warm goodput.

| `BENCH_PROFILE` | `WORKER_COUNT` | Когда использовать |
|-----------------|----------------|-------------------|
| `warm` (default) | `1` | HTTP Archive sites bench, warm goodput vs Squid |
| `cold` | `4` | Cold/MISS-heavy, multi-accept parallelism |

Пресеты заданы в [`scripts/bench-profile.sh`](../scripts/bench-profile.sh) и применяются в `run-httparchive-benchmark.sh` / `compare-squid-bsdm-httparchive.sh`.

```bash
# Warm profile (default) — рекомендуется для sites bench
./scripts/run-httparchive-benchmark.sh

# Cold profile — больше accept workers
BENCH_PROFILE=cold ./scripts/run-httparchive-benchmark.sh

# Оба профиля подряд
./scripts/run-httparchive-bench-profiles.sh

# Squid vs BSDM (BSDM с выбранным профилем)
BENCH_PROFILE=warm ./scripts/compare-squid-bsdm-httparchive.sh
```

См. результаты и методику: [benchmarks-httparchive.md](benchmarks-httparchive.md).

## Рекомендуемый bench-профиль (wrk/oha micro-bench)

```bash
cargo build --release -p bsdm-proxy --bin proxy

HTTP_PORT=12788 METRICS_PORT=19190 \
  MITM_ENABLED=false HIERARCHY_ENABLED=false RUST_LOG=warn \
  PERF_FAST_CACHE_HIT=true WORKER_COUNT=4 \
  METRICS_SAMPLE_RATE=100 HTTP_PRESERVE_HEADER_CASE=false \
  TCP_SNDBUF_BYTES=524288 \
  ./target/release/proxy
```

## Бенчмарк

```bash
./scripts/compare-squid-bsdm.sh              # Squid vs BSDM (wrk + oha)
./scripts/run-proxy-benchmark.sh HOST:PORT LABEL
./scripts/run-profile-benchmark.sh           # baseline / perf / corporate

# Corporate auth для wrk/oha:
export WRK_PROXY_AUTH_HEADER="Proxy-Authorization: Basic $(printf '%s' 'user:pass' | base64 -w0)"
export CURL_PROXY_USER='user:pass'           # альтернатива
```

### Сценарии `run-proxy-benchmark.sh`

| Шаг | Что измеряет |
|-----|----------------|
| wrk L1 HIT/MISS | максимальный sustained RPS |
| oha L1 HIT | keep-alive, N соединений (ближе к браузеру) |
| oha L1 MISS | уникальные URL, cache cold path |

Переменные: `OHA_CONN_HIT`, `OHA_CONN_MISS`, `OHA_DURATION` (по умолчанию = wrk).

### HTTP Archive Top 1k page load

```bash
./scripts/run-httparchive-benchmark.sh
cargo test -p bsdm-proxy-e2e --test httparchive
```

См. [benchmarks-httparchive.md](benchmarks-httparchive.md).

## Профилирование

```bash
./scripts/perf-profile.sh
sudo perf report -i /tmp/bsdm-perf.data
```

## Архитектура hot path

1. **L1 lookup** (sharded `quick_cache`, `HttpL1Cache`) — самый частый путь.
2. **`PERF_FAST_CACHE_HIT`**: HIT возвращается до ACL/categorization; Kafka и histograms опциональны.
3. **`WORKER_COUNT`**: N процессов accept на одном порту (SO_REUSEPORT), общий L1 `Arc<HttpL1Cache>`.
4. **Tiered bodies**: мелкие ответы inline, крупные (≥ `CACHE_SPILL_THRESHOLD_BYTES`) — mmap spill + zero-copy serve.
4. **ACL**: `RwLock` + `check_access(&self)` — read-mostly без сериализации на каждый MISS.
5. **Kafka**: sampling через `KAFKA_SAMPLE_RATE`.

## Production vs bench

| | Bench (HTTP Archive warm) | Bench (wrk HIT) | Production |
|---|---------------------------|-----------------|------------|
| `BENCH_PROFILE` | `warm` | — | — |
| `PERF_FAST_CACHE_HIT` | `true` | `true` | `false` |
| `WORKER_COUNT` | `1` (warm) / `4` (cold) | `4` | `1` per pod (k8s) |
| `KAFKA_SAMPLE_RATE` | — | — | `10` |
| `HTTP_PRESERVE_HEADER_CASE` | `false` | `false` | `true` (MITM) |

См. также [architecture.md](architecture.md), [logging.md](logging.md).
