# Статус проекта и зрелость функций

Этот документ — единая точка правды о текущем состоянии BSDM-Proxy. Он описывает
реализованный код, а не целевые возможности из roadmap.

Текущая версия Cargo workspace: **`0.8.0`**. Версию нужно сверять с
`proxy/Cargo.toml` и остальными workspace-крейтами.

## Уровни зрелости

| Уровень | Что означает |
|---|---|
| **Основной** | Есть реализация, тесты и документированный путь запуска. Это не заменяет нагрузочное и security-тестирование конкретного окружения. |
| **Beta** | Функция работает, но требует отдельной приёмки, настройки или имеет эксплуатационные ограничения. |
| **Experimental** | PoC или ранняя интеграция. Не использовать как security boundary без доработки и отдельного аудита. |
| **Planned** | В коде нет законченного пользовательского сценария. |

## Матрица функций

| Область | Функция | Статус | Комментарий |
|---|---|---|---|
| Архитектура | Hybrid Policy (DNS -> SNI -> Selective MITM) | Основной | `POLICY_MODE` (`selective-mitm` по умолчанию, `sni`, `full-mitm`). Интегрировано с Agent Contract v0.1. |
| Data plane | HTTP forward proxy, CONNECT, Selective/Full MITM | Основной | MITM включается селективно по категориям (`MITM_CATEGORIES`). |
| Кеш | L1, mmap spill, compression, revalidation, miss coalescing | Основной | `CACHE_CAPACITY` — общая ёмкость L1, которая делится между шардами. |
| Кеш | Redis L2, ICP/HTCP hierarchy | Beta | Нужны отдельные Redis/peer deployment и failover-тесты. |
| Политики | ACL, categorization, rate limiting, SNI filtering | Основной | Фильтрация по SNI выполняется до TLS расшифровки. |
| Аутентификация | Basic, OIDC | Основной | OIDC включает строгую валидацию CSRF token, JWT issuer, aud и exp. |
| Аутентификация | LDAP, NTLM, Kerberos | Beta | Требуют соответствующей Cargo feature и интеграционного стенда. |
| Аналитика | Kafka → cache-indexer → ClickHouse, Search API | Основной | Срок хранения задаётся TTL ClickHouse. Поля `dlp_violation` и `casb_alert` поддерживаются в схеме. |
| Detection | alert-worker | Beta | Запросы правил выполняются периодически; нужен контроль ClickHouse latency. |
| ML | UEBA, phishing, beacon, threat-score write-back | Beta | Один процесс `ml-worker` обслуживает одну выбранную модель. |
| DNS | DNS Sinkhole + RPZ (Core component) | Основной | Включает DoH (`/dns-query`) и DoT (TCP/853) шлюзы шифрованного DNS. |
| AI cache | Exact LLM POST cache, local/Qdrant near-hit | Beta | Поддерживает векторный бэкенд Qdrant (`SEMANTIC_VECTOR_BACKEND=qdrant`) и квотирование по API ключам. |
| Extensions | WASM request hook | Experimental (Frozen) | Заморожено. PoC hook с fuel limits. |
| Inspection | ICAP REQMOD/RESPMOD | Experimental (Frozen) | Заморожено. RESPMOD требует buffered MISS (`STREAMING_MISS_ENABLED=false`). |
| DLP/CASB | Сигнатурное сканирование request body | Experimental (Frozen) | Заморожено. Сигнатурный сканер. |
| ZTNA/IAP | Reverse proxy + OIDC | Experimental (Frozen) | Описан в Agent Contract v0.1 (ADR 0005). |
| Network | eBPF/XDP manager | Experimental (Frozen) | Заморожено. `EBPF_XDP_ENABLED` интерфейс. |
| Remote access | AmneziaWG sidecar/config API | Experimental (Frozen) | Заморожено. |
| Cluster | Global sessions, distributed rate limit, threat sync | Experimental (Frozen) | Scaffolding gRPC mesh. |
| Admin UI & Trust UI | Native Static UI Routing | Beta | Native UI routing на `/admin` (Admin Console) и `/trust` (Trust-UI) прямо через proxy binary. |

## Известные ограничения

1. `docker compose up` запускает analytics base, но не все опциональные профили.
   `alert-worker`, `ml-worker`, DNS и ICAP включаются отдельно.
2. Поля `dlp_violation` и `casb_alert` интегрированы в схему ClickHouse и event mapper proxy.
3. Для одновременного запуска нескольких ML-моделей нужны отдельные экземпляры
   `ml-worker` с разными значениями `ML_MODEL`.
4. ICAP RESPMOD не выполняется на streaming MISS. Для полного response scanning
   требуется `STREAMING_MISS_ENABLED=false`.
5. Reverse proxy/OIDC, eBPF control path и AmneziaWG control integration считаются
   experimental независимо от отметок в исторических release notes.
6. Встроенный DLP engine создаётся при старте proxy без отдельного `DLP_ENABLED`.
   Для пилота без DLP нужен постоянный выключатель или пустой набор паттернов,
   установленный через control API.
7. `GlobalSessionStore`, Redis rate-limit path и `ThreatSyncEngine` добавлены как
   scaffolding. Текущий `main.rs` создаёт session/threat stores без Redis, а
   proxy request path не вызывает distributed rate-limit check. Название
   «global/real-time sync» пока не означает рабочий multi-node сценарий.

## Правило обновления

При изменении функции в одном PR обновляются:

1. код и примеры конфигурации;
2. соответствующая страница в `docs/`;
3. эта матрица зрелости;
4. `CHANGELOG.md`, если изменение пользовательское;
5. Wiki через автоматическую синхронизацию из `docs/`.

Roadmap описывает намерения и последовательность работ. Он не должен повышать
уровень зрелости функции без подтверждения в этой матрице.
