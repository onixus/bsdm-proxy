# HTTP Archive Top 1k benchmarks

Тесты и бенчмарки, основанные на медианных метриках [HTTP Archive: Page Weight (Top 1,000)](https://httparchive.org/reports/page-weight?lens=top1k&start=2023_07_01&end=2024_07_01&view=grid) за период Jul 2023 – Jul 2024. Числа сверены с [Web Almanac 2024: Page Weight](https://almanac.httparchive.org/en/2024/page-weight).

## Профиль (медиана)

| Метрика | Desktop | Mobile |
|---------|---------|--------|
| Вес страницы | 2 652 KB | 2 311 KB |
| Запросов | 71 | 66 |
| HTML | 18 KB × 2 | 18 KB × 2 |
| CSS | 78 KB × 8 | 73 KB × 8 |
| JavaScript | 613 KB × 24 | 558 KB × 22 |
| Images | 1 054 KB × 18 | 900 KB × 16 |
| Fonts | 131 KB × 4 | 111 KB × 3 |
| Other | 755 KB × 15 | 651 KB × 15 |

Перцентили полного веса (desktop / mobile): P10 549 / 471 KB, P50 2 157 / 1 938 KB, P75 4 169 / 3 766 KB, P90 8 375 / 7 680 KB.

Канонический профиль: [`scripts/httparchive-top1k-profile.json`](../scripts/httparchive-top1k-profile.json). Поле `other.bytes` — остаток до `total_bytes` (компоненты в Almanac округлены по KB).

## Компоненты

| Файл | Назначение |
|------|------------|
| `scripts/httparchive_profile.py` | Загрузка JSON, разбиение байт по ресурсам, валидация |
| `scripts/mock-upstream-httparchive.py` | Mock upstream с телами нужного размера |
| `scripts/httparchive-sites-bench.py` | **Основная методика**: 70 случайных сайтов Top 1k, 12 conn, 20 warm-повторов |
| `scripts/httparchive-page-load.py` | Legacy: одна медианная страница (71 ресурс) |
| `scripts/run-httparchive-benchmark.sh` | Полный прогон sites bench (BSDM) |
| `scripts/compare-squid-bsdm-httparchive.sh` | Squid vs BSDM (sites bench) |
| `e2e/tests/httparchive.rs` | E2E: 71/66 запросов, MISS → HIT, проверка объёма |

## Методика (sites bench)

1. Из пула **Top 1 000** случайно выбираются **70 сайтов** (`seed=42` для воспроизводимости).
2. Каждый сайт — одна страница медианного веса (desktop 2.59 MiB / mobile 2.26 MiB).
3. **Cold**: 70 запросов с **12 параллельными** соединениями.
4. **Warm**: те же 70 сайтов повторяются **20 раз** (12 conn).

Итого: **1 470 запросов** (70 cold + 70×20 warm) на прогон.

## Быстрый старт

```bash
# Валидация профиля
python3 scripts/httparchive_profile.py

# E2E (без внешних сервисов)
cargo test -p bsdm-proxy-e2e --test httparchive

# Sites bench (mock + proxy)
cargo build --release -p bsdm-proxy --bin proxy
./scripts/run-httparchive-benchmark.sh

# Squid vs BSDM
./scripts/compare-squid-bsdm-httparchive.sh
```

Переменные:

- `BENCH_SITES` — число сайтов (default **70**)
- `PAGE_CONCURRENCY` — параллелизм (default **12**)
- `BENCH_WARM_REPEATS` — warm-повторы (default **20**)
- `WORKER_COUNT` — default **4** в `run-httparchive-benchmark.sh` / compare
- `BENCH_SITE_SEED` — seed выбора сайтов (default **42**)
- `HTTPARCHIVE_DEVICE` — `desktop` или `mobile`
- `PERF_FAST_CACHE_HIT`, `WORKER_COUNT` — как в [performance.md](performance.md)

### Legacy: одна страница (71 ресурс)

```bash
PAGE_CONCURRENCY=6 python3 scripts/httparchive-page-load.py \
  --proxy http://127.0.0.1:12788 --upstream http://127.0.0.1:18080
```

## Отличие от wrk/oha

Сценарии `run-proxy-benchmark.sh` измеряют **один URL** (микро-запрос ~33 B). HTTP Archive-тесты моделируют **полную медианную страницу Top 1k**: десятки запросов и ~2.6 MB на cold load, что ближе к реальному корпоративному трафику и нагрузке на кэш/память.

См. также [performance.md](performance.md), [capacity-planning.md](capacity-planning.md).
