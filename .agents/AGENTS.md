# BSDM-Proxy — Workspace Rules

## Formatting and Linting

- **ALWAYS** run `cargo fmt --all` before committing any Rust code changes.
  CI строго проверяет форматирование и упадёт при несоблюдении.
- **ALWAYS** run `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  before committing logical changes. Clippy-ворнинги трактуются как ошибки.
- Быстрая проверка обоих: `make lint`.

## Rust Coding Guidelines

### Общие принципы
- Идиоматичный Rust (Edition 2021), строгая типизация.
- Используй `tokio` для всего асинхронного кода.
- Никогда не используй `.unwrap()` или `.expect()` в production-коде.
  Допустимо только в тестах и в `main()` при начальной инициализации.
- Для обработки ошибок: `anyhow::Result` в бинарных крейтах,
  `thiserror` для библиотечных типов ошибок.

### Потокобезопасность
- При работе с кэшем (`sharded_cache.rs`, `hierarchy.rs`, `l2_cache.rs`)
  обращай внимание на `Arc`, `RwLock`, `Mutex`.
- `ProxyService` — singleton, клонируется через `Arc` per-connection.
- `DeviceRegistry` — `Clone`-able через `Arc<RwLock<..>>`.

### Видимость модулей
- Используй `pub(crate)` или `pub(super)` вместо `pub` где возможно.
- Вложенные `impl`-блоки в субмодулях начинаются с `use super::*;`
  (паттерн `control_api/`, `proxy_service/`).

## Metrics

- При добавлении нового функционала **всегда** добавляй соответствующие
  Prometheus-метрики в `proxy/src/metrics.rs`.
- Используй существующие паттерны: `Counter`, `Histogram`, `Gauge`.
- Именование: `bsdm_proxy_<subsystem>_<metric>_<unit>`.

## Testing

- **Всегда** предлагай unit-тесты для нового кода.
- Для нового функционала добавляй E2E-тесты в `/e2e/`.
- `cargo test --workspace` должен проходить без Docker/Kafka/ClickHouse.
- Для бенчмарков используй скрипты из `/scripts/`
  (например, `run-proxy-benchmark.sh`).

## Database (ClickHouse & Redis)

- ClickHouse используется для тяжелой аналитики и ML-фичей.
- При добавлении новых полей в ML-модели — предложи SQL-миграции
  в `/scripts/clickhouse/migrations/`.
- Все SQL-запросы оптимизируй для колоночной СУБД:
  избегай `SELECT *`, используй партиционирование.
- Redis — L2-кэш. Ключи с префиксом (конфигурируется через env vars).

## Infrastructure

- При изменении конфигурационных файлов обновляй `.env.example`
  в `/packaging/config/`.
- При добавлении нового микросервиса обнови:
  - Helm-чарты в `/charts/bsdm/`
  - `docker-compose.yml` и `docker-compose.lite.yml`
  - `Dockerfile` (multi-stage build)
- Документируй новые env vars в `bsdm-proxy.env` и `docs/`.

## Performance

- Это прокси-сервер: **low-latency** — приоритет.
- Избегай лишних аллокаций на hot path
  (`proxy_service/request.rs`, `proxy_service/cache_ops.rs`).
- Используй `bytes::Bytes` для zero-copy передачи тел ответов.
- Предпочитай `quick_cache` для in-memory кэша (lock-free).
