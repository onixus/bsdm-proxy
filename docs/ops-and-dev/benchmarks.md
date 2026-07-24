# HTTP Archive Top 1k benchmarks

Тесты и бенчмарки, основанные на медианных метриках [HTTP Archive: Page Weight (Top 1,000)](https://httparchive.org/reports/page-weight?lens=top1k&start=2023_07_01&end=2024_07_01&view=grid) за период Jul 2023 – Jul 2024. Числа сверены с [Web Almanac 2024: Page Weight](https://almanac.httparchive.org/en/2024/page-weight).

> Результаты ниже сохранены как исторический baseline версий `0.3.x–0.5.0`.
> Они включают bench-only fast path и не являются сайзингом полного продукта.
> Текущий расчёт ресурсов: [capacity planning](../architecture/capacity-planning.md).

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

Канонический профиль: [`scripts/httparchive-top1k-profile.json`](../../scripts/httparchive-top1k-profile.json). Поле `other.bytes` — остаток до `total_bytes` (компоненты в Almanac округлены по KB).

## Компоненты

| Файл | Назначение |
|------|------------|
| `scripts/httparchive_profile.py` | Загрузка JSON, разбиение байт по ресурсам, валидация |
| `scripts/mock-upstream-httparchive.py` | Mock upstream с телами нужного размера |
| `scripts/httparchive-sites-bench.py` | **Основная методика**: 70 случайных сайтов Top 1k, 12 conn, 20 warm-повторов |
| `scripts/httparchive-page-load.py` | Legacy: одна медианная страница (71 ресурс) |
| `scripts/run-httparchive-benchmark.sh` | Полный прогон sites bench (BSDM) |
| `scripts/run-httparchive-bench-profiles.sh` | Прогон warm + cold профилей подряд |
| `scripts/bench-profile.sh` | Пресеты `BENCH_PROFILE` → `WORKER_COUNT` |
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
BENCH_PROFILE=warm ./scripts/compare-squid-bsdm-httparchive.sh
BENCH_PROFILE=cold ./scripts/compare-squid-bsdm-httparchive.sh

# Оба профиля (BSDM only)
./scripts/run-httparchive-bench-profiles.sh
```

### Bench profiles (`BENCH_PROFILE`)

| Профиль | `WORKER_COUNT` | Назначение |
|---------|----------------|------------|
| `warm` (default) | `1` | Warm goodput на sites bench (меньше contention на shared L1) |
| `cold` | `4` | Cold/MISS parallelism, multi accept-loop |

Пресеты: [`scripts/bench-profile.sh`](../../scripts/bench-profile.sh). Переопределение: `BENCH_PROFILE=warm WORKER_COUNT=2 ...` (явный `WORKER_COUNT` сохраняется).

Переменные:

- `BENCH_SITES` — число сайтов (default **70**)
- `PAGE_CONCURRENCY` — параллелизм (default **12**)
- `BENCH_WARM_REPEATS` — warm-повторы (default **20**)
- `BENCH_PROFILE` — `warm` \| `cold` (default **warm**); см. таблицу выше
- `WORKER_COUNT` — задаётся профилем (`1` warm / `4` cold), можно переопределить
- `BENCH_SITE_SEED` — seed выбора сайтов (default **42**)
- `HTTPARCHIVE_DEVICE` — `desktop` или `mobile`
- `PERF_FAST_CACHE_HIT`, `WORKER_COUNT` — как в [performance.md](../architecture/performance.md)

### Legacy: одна страница (71 ресурс)

```bash
PAGE_CONCURRENCY=6 python3 scripts/httparchive-page-load.py \
  --proxy http://127.0.0.1:12788 --upstream http://127.0.0.1:18080
```

## Отличие от wrk/oha

Сценарии `run-proxy-benchmark.sh` измеряют **один URL** (микро-запрос ~33 B). HTTP Archive-тесты моделируют **полную медианную страницу Top 1k**: десятки запросов и ~2.6 MB на cold load, что ближе к реальному корпоративному трафику и нагрузке на кэш/память.

См. также [performance.md](../architecture/performance.md), [capacity-planning.md](../architecture/capacity-planning.md).

## Результаты (lab, 4 vCPU, desktop profile)

Методика: 70 сайтов, 12 conn, 20 warm repeats, `PERF_FAST_CACHE_HIT=true`, tiered L1 (PR #93).
Warm goodput — фаза **warm repeats** из вывода `httparchive-sites-bench.py`.
Перемеряйте на своём железе: `BENCH_PROFILE=warm ./scripts/compare-squid-bsdm-httparchive.sh`.

| Дата | Версия | Профиль | `WORKER_COUNT` | BSDM warm Mbit/s | Squid warm Mbit/s | Примечание |
|------|--------|---------|----------------|------------------|-------------------|------------|
| 2026-03 (ADR 0001) | 0.3.x | cold | 4 | ~500 | ~657 | до tiered L1 tuning |
| 2026-06 (backlog) | 0.3.x | cold | 4 | ~538 | ~593 | post P0 perf + tiered L1 |
| 2026-07-01 | 0.3.x | cold* | 4 | ~478 | ~535 | total 481 vs 537; Squid rock×4 |
| **2026-07-16** | **0.5.0** | **warm** | **1** | **477** | **527** | gate profile; Squid w1+mem (host SMP broken) |
| **2026-07-16** | **0.5.0** | **cold** | **4** | **516** | **469** | BSDM cold path 714; Squid same w1+mem |

\*До введения `BENCH_PROFILE`; эквивалент сегодняшнего `cold` (`WORKER_COUNT=4`).

Gap warm profile vs Squid: цель M2.5 — **≥ Squid −5%** на warm goodput ([roadmap](../roadmap.md)).
Прогон 2026-07-16 warm: BSDM **477** vs Squid **527** → **−9.5%** (цель ≥560 / −5% не достигнута).
На том же хосте `cold` (WC=4) дал BSDM warm **516** (−3.4% к Squid rock×4 ~535 из 2026-07-01).
