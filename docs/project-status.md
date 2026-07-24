# Статус проекта и зрелость функций

Этот документ — единая точка правды о текущем состоянии BSDM-Proxy. Он описывает
реализованный код, а не целевые возможности из roadmap.

Текущая версия Cargo workspace: **`0.6.1-1`**. Версию нужно сверять с
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
| Data plane | HTTP forward proxy, CONNECT, HTTPS MITM | Основной | MITM требует локального CA и явного доверия клиентов. |
| Кеш | L1, mmap spill, compression, revalidation, miss coalescing | Основной | `CACHE_CAPACITY` — общая ёмкость L1, которая делится между шардами. |
| Кеш | Redis L2, ICP/HTCP hierarchy | Beta | Нужны отдельные Redis/peer deployment и failover-тесты. |
| Политики | ACL, categorization, rate limiting | Основной | Fast cache path нельзя включать при обязательной проверке политики. |
| Аутентификация | Basic | Основной | Секреты должны храниться вне Git. |
| Аутентификация | LDAP, NTLM, Kerberos | Beta | Требуют соответствующей Cargo feature и интеграционного стенда. |
| Аналитика | Kafka → cache-indexer → ClickHouse, Search API | Основной | Срок хранения задаётся TTL ClickHouse, а не числом пользователей. |
| Detection | alert-worker | Beta | Запросы правил выполняются периодически; нужен контроль ClickHouse latency. |
| ML | UEBA, phishing, beacon, threat-score write-back | Beta | Один процесс `ml-worker` обслуживает одну выбранную модель. |
| DNS | UDP sinkhole, DoH, DoT | Beta | Не является полноценным recursive resolver или DNSSEC validator. |
| AI cache | Exact LLM POST cache, local/Qdrant near-hit | Beta | Local hash embedding ищет близкие формулировки, но не является semantic model. |
| Extensions | WASM request hook | Experimental | Один PoC hook, ограниченный ABI, без WASI filesystem/network. |
| Inspection | ICAP REQMOD/RESPMOD | Experimental | RESPMOD требует buffered MISS; ICAP-over-TLS не реализован. |
| DLP/CASB | Сигнатурное сканирование request body | Experimental | Набор строковых сигнатур; это не полноценный DLP/PII engine. |
| ZTNA/IAP | Reverse proxy + OIDC | Experimental | Текущая реализация не проверяет подпись JWT и использует mock OIDC state. |
| Network | eBPF/XDP manager | Experimental | Требует Linux privileges, clang/ip/bpftool и отдельной проверки метрик. |
| Remote access | AmneziaWG sidecar/config API | Experimental | Compose sidecar и control-plane state пока не образуют единый lifecycle. |
| Cluster | Global sessions, distributed rate limit, threat sync | Experimental | Есть локальные stores и REST endpoints, но runtime не передаёт им Redis connection и не применяет synchronized IoC к policy. |
| Admin UI | React SPA | Beta | UI нужно собирать и публиковать отдельно; основной Compose его не обслуживает. |

## Известные ограничения

1. `docker compose up` запускает analytics base, но не все опциональные профили.
   `alert-worker`, `ml-worker`, DNS и ICAP включаются отдельно.
2. Поля `dlp_violation` и `casb_alert` присутствуют в event mapper, но их необходимо
   добавить в ClickHouse-схему до включения DLP/CASB analytics.
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
