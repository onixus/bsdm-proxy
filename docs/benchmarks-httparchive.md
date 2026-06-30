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
| `scripts/httparchive-page-load.py` | Симуляция загрузки страницы через прокси (6 параллельных соединений) |
| `scripts/run-httparchive-benchmark.sh` | Полный прогон cold + warm page load |
| `e2e/tests/httparchive.rs` | E2E: 71/66 запросов, MISS → HIT, проверка объёма |

## Быстрый старт

```bash
# Валидация профиля
python3 scripts/httparchive_profile.py

# E2E (без внешних сервисов)
cargo test -p bsdm-proxy-e2e --test httparchive

# Бенчмарк (mock + proxy + 2 прохода страницы)
cargo build --release -p bsdm-proxy --bin proxy
./scripts/run-httparchive-benchmark.sh

# Mobile-профиль
HTTPARCHIVE_DEVICE=mobile ./scripts/run-httparchive-benchmark.sh ha-mobile
```

Переменные:

- `HTTPARCHIVE_DEVICE` — `desktop` (default) или `mobile`
- `PAGE_CONCURRENCY` — параллелизм загрузки (default 6, как у браузера)
- `PERF_FAST_CACHE_HIT`, `WORKER_COUNT` — как в [performance.md](performance.md)

## Отличие от wrk/oha

Сценарии `run-proxy-benchmark.sh` измеряют **один URL** (микро-запрос ~33 B). HTTP Archive-тесты моделируют **полную медианную страницу Top 1k**: десятки запросов и ~2.6 MB на cold load, что ближе к реальному корпоративному трафику и нагрузке на кэш/память.

См. также [performance.md](performance.md), [capacity-planning.md](capacity-planning.md).
