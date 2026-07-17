# bsdm-proxy: Стратегический Roadmap

Вектор развития проекта для повышения рыночной ценности, гибкости и удобства использования. Четыре ключевые фазы (параллельно engineering milestones **M1–M5** в [roadmap.md](roadmap.md)).

| Фаза | Фокус |
|------|--------|
| [1. Lite](#фаза-1-режим-lite-и-оптимизация-ресурсов) | Низкий порог входа, VPS / edge |
| [2. DX](#фаза-2-developer-experience-dx-и-динамическое-управление) | Control plane, hot reload, Cloud-Native |
| [3. Wasm](#фаза-3-расширяемость-через-webassembly-wasm) | Плагины и кастомизация |
| [4. AI-трафик](#фаза-4-интеллектуальные-функции-и-ai-трафик) | Rate limit, semantic cache, coalescing |

---

## Фаза 1: Режим "Lite" и оптимизация ресурсов

*Фокус: снижение порога входа и адаптация под небольшие инфраструктуры (VPS, edge-узлы).*

- **Отвязка от тяжелых зависимостей:** ✅ `INDEX_STORE=sqlite|memory` + optional Kafka; HTTP `POST /api/events` (см. [lite.md](lite.md)).
- **Встроенное хранилище:** ✅ SQLite / in-memory event store на cache-indexer.
- **Standalone-архитектура:** независимый бинарник / lightweight container — proxy уже работает без `KAFKA_BROKERS`; Lite compose + SQLite. ✅ `kafka` Cargo feature (B21) drops `rdkafka` from Lite builds.
- **Zero-Config профили:** ✅ [`docker-compose.lite.yml`](../docker-compose.lite.yml) + [`scripts/gen-ca.sh`](../scripts/gen-ca.sh).

---

## Фаза 2: Developer Experience (DX) и динамическое управление

*Фокус: удобство администрирования и эксплуатация в Cloud-Native среде.*

- **Control Plane API:** ✅ REST на metrics port — ACL CRUD, `/api/stats`, `/api/cache/purge`, `/api/hierarchy/*`, `/api/upstream/tls*` ([control-plane.md](control-plane.md)). gRPC — later.
- **Горячая перезагрузка (Hot Reload):** ✅ ACL (file auto-reload + API mutate/persist). ✅ Hierarchy static peers (`POST /api/hierarchy/reload`). ✅ Upstream TLS client pool (`POST /api/upstream/tls/reload`).
- **Умная инвалидация кэша:** ✅ URL / tag / all purge (`POST /api/cache/purge`). Cache-Tag + Surrogate-Key index on L1.
- **Встроенный мониторинг:** ✅ `GET /api/stats` JSON (Lite, без Grafana).

---

## Фаза 3: Расширяемость через WebAssembly (Wasm)

*Фокус: кастомизация для энтузиастов и enterprise.*

- **Интеграция Wasm-рантайма:** Wasmtime (или аналог) в пайплайн request/response.
- **SDK:** библиотеки (Rust, Go, AssemblyScript) для пользовательских плагинов.
- **Модульность ядра:** PoC переноса жёстко закодированной логики (например auth) в Wasm-модули.

---

## Фаза 4: Интеллектуальные функции и AI-трафик

*Фокус: современные паттерны трафика и LLM.*

- **Умный Rate Limiting:** ✅ token bucket per IP / user / API key (`RATE_LIMIT_API_KEY_*`, header или Bearer; optional required → 401).
- **Семантическое кэширование:** ✅ LLM POST content-hash cache + local similarity index prep ([semantic-cache.md](semantic-cache.md)); next: external embeddings / vector DB.
- **Request Coalescing:** ✅ singleflight для GET/HEAD MISS (`MISS_COALESCE_ENABLED`, metric `bsdm_proxy_cache_coalesced_total`, `X-Cache-Status: COALESCED-HIT`).

---

## Связь с engineering milestones

| Стратегическая фаза | Пересекается с |
|---------------------|----------------|
| Lite | `docker-compose.lite.yml`, SQLite indexer, optional `kafka` Cargo feature (B21) |
| DX | REST control plane ✅ ([control-plane.md](control-plane.md)); next: [gRPC #187](https://github.com/onixus/bsdm-proxy/issues/187) |
| Wasm | [Wasmtime plugin host #188](https://github.com/onixus/bsdm-proxy/issues/188) |
| AI-трафик | coalescing ✅, API-key RL ✅, LLM/semantic cache prep ✅; next: [vector DB #189](https://github.com/onixus/bsdm-proxy/issues/189) |

Текущий product plan (Squid / ретропоиск / ML): [roadmap.md](roadmap.md).  
Статус GitHub issues: [issue-tracker.md](issue-tracker.md).

---

*Добавлено: 2026-07 · tracker hygiene 2026-07-17*
