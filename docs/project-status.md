# Статус проекта и зрелость функций

Этот документ — единая точка правды о текущем состоянии BSDM-Proxy. Он описывает
реализованный код, а не целевые возможности из roadmap.

Текущая версия Cargo workspace: **`1.0.0-rc.1`**. Версию нужно сверять с
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
| Политики | ACL, categorization, rate limiting, фильтрация по CONNECT authority | Основной | Доменная политика HTTPS применяется до TLS-расшифровки по authority из запроса `CONNECT`. ClientHello (SNI) не разбирается: domain fronting и `CONNECT <IP>:443` доменными правилами не ловятся — реальный SNI-контроль запланирован на 1.1 ([roadmap](roadmap.md)). |
| Аутентификация | Basic | Основной | Файл пользователей (Argon2id, `0600`); в production без файла — отказ старта. |
| Аутентификация | OIDC (reverse proxy / IAP) | Experimental (Frozen) | Код проверяет подпись `id_token` по JWKS провайдера, `iss`/`aud`/`azp`/`exp`, `nonce` и PKCE; провайдеры Google, Apple и generic через `OIDC_PROVIDERS` ([authentication.md](features/authentication.md)). Модуль входит в замороженный ZTNA/IAP-контур (строка ниже) и не поддерживается в v1.0. |
| Аутентификация | LDAP, NTLM, Kerberos | Beta | Требуют соответствующей Cargo feature и интеграционного стенда. |
| Аналитика | Kafka → cache-indexer → ClickHouse, Search API | Основной | Search also same-origin via control plane (`SEARCH_UPSTREAM_URL`). TTL ClickHouse; `dlp_violation` / `casb_alert` in schema. |
| Detection | alert-worker | Beta | Запросы правил выполняются периодически. Latency ClickHouse ограничена: клиентский дедлайн (`ALERT_CLICKHOUSE_TIMEOUT_MS`), серверные `max_execution_time` / `max_result_rows` / `readonly=2`, обрыв деградировавшего цикла с экспоненциальным backoff и гистограммы `alert_worker_clickhouse_query_seconds` / `alert_worker_cycle_duration_seconds` ([alerting.md](analytics/alerting.md)). |
| ML | UEBA, phishing, beacon, threat-score write-back | Beta | Один процесс `ml-worker` = одна модель. Пилот: UEBA `ueba_zscore_v0` + write-back ([pilot-ml.md](getting-started/pilot-ml.md)); proxy `THREAT_SCORE_*` opt-in, block off. |
| DNS | DNS Sinkhole + RPZ (Core component) | Основной | DoH/DoT gateways; control-plane **RPZ API** (`/api/dns/rpz/*`) + zone reload. |
| Threat Intelligence | Мониторинг угроз (Shadow) и Data-Plane Enforcement (`threat-intel`, `ti_enforce`) | Beta | Блокировка по фидам выключена по умолчанию (`TI_ENFORCEMENT_MODE=shadow`, [ADR 0008](adr/0008-threat-intel-shadow-mode.md)). Data-plane enforcement реализован в `ti_enforce.rs` с тройным защитным барьером (Triple-Gate) и приоритетом корпоративного Allowlist, активируется при явном `TI_ENFORCEMENT_MODE=enforce`. Реализовано: сбор OpenPhish, PhishStats, Phishing.Database, URLhaus; нормализация URL/доменов/IP; SQLite персистентность с TTL; взвешенный скоринг; компиляция RPZ-зон с поддержкой Live Status/Rollback API (`GET /api/v1/rpz/status`, `POST /api/v1/rpz/rollback`) и Proxy ACL экспорта; интеграция SIEM (CEF/ECS/Syslog), SOAR API (`/api/v1/soar/*`), ML-модель репутации (`/api/v1/ml/reputation`), E2E-харнесс (`threat_intel_e2e.rs`) и интерактивный SOC триаж ложных срабатываний в Admin Console ([threat-intel-collector.md](features/threat-intel-collector.md)). |
| AI cache | Exact LLM POST cache, local/Qdrant near-hit | Beta | Поддерживает векторный бэкенд Qdrant (`SEMANTIC_VECTOR_BACKEND=qdrant`) и квотирование по API ключам. |
| Extensions | WASM request hook | Experimental (Frozen) | Заморожено. PoC hook с fuel limits. |
| Inspection | ICAP REQMOD/RESPMOD | Experimental (Frozen) | Заморожено. RESPMOD требует buffered MISS (`STREAMING_MISS_ENABLED=false`). |
| DLP/CASB | Сигнатурное сканирование request body | Experimental (Frozen) | Заморожено. Сигнатурный сканер. |
| ZTNA/IAP | Reverse proxy + OIDC | Experimental (Frozen) | Описан в Agent Contract v0.1 (ADR 0005). |
| Network | eBPF/XDP manager | Beta (lab) | **Lab-only, не security boundary** (Day-1 пилота: OFF). Выключен по умолчанию и требует явного arming в окружении (`EBPF_XDP_ENABLED` / `EBPF_XDP_ALLOW_RUNTIME_ENABLE`): без него `PUT /api/ebpf/config` с `enabled: true` отвечает 403. Dual-stack IPv4/IPv6 XDP-фильтр, учет дропов ядра через BPF-карту `bsdm_drop_stats`, полный Control API (`/api/ebpf/*`), метрики `bsdm_proxy_ebpf_*` (включая `bsdm_proxy_ebpf_armed`) и lab-смоук `scripts/run-ebpf-lab-smoke.sh`. [ebpf-xdp.md](features/ebpf-xdp.md). |
| Remote access | AmneziaWG sidecar/config API | Beta (lab) | **Lab-only, не для продакшена** (Day-1 пилота: OFF, issue #331). Curve25519 криптография, PSK, авто-провижининг пиров, экспорт .conf, метрики и интеграция с Agent Contract (`tunnel` capability). [bsdm-connect-client.md](getting-started/bsdm-connect-client.md). |
| Cluster | Global sessions, distributed rate limit, threat sync | Experimental (Frozen) | Scaffolding gRPC mesh. |
| Admin UI | Admin Console (Hybrid core) | Основной | Primary nav: Dashboard, Logs, Analytics, Policies, RPZ (Live Status/Rollback), **Devices** (Drift/OS Proxy badges), **AmneziaWG**, Users, Settings (разделы Devices и AmneziaWG помечены в навигации как lab-only, не для продакшена). SPA baked into proxy image (`/admin/`). Live/demo provenance, error/empty states, mutation token gate, Threat Investigation Modal, ML Domain Inspector. Search CORS for localhost split. |
| Admin UI | Admin Console experimental routes | Experimental (Frozen) | Deep-links `/wasm`, `/cluster`, `/ai-cache` only — frozen banner, not in primary nav. |
| UI reference | Standalone Trust-UI | Выведен из эксплуатации | Полностью удалён; операторский интерфейс консолидирован в Admin Console (`/admin/`). |
| Agent (Phase C) | Local policy agent spike | Beta (lab) | Enroll, CSR, events, push (long-poll/SSE/**WS**/gRPC), mTLS, CRL, lab OCSP JSON + **RFC 6960 DER OCSP**, data-plane **OCSP stapling**, **multi-node Redis**, multi-OS installers + system proxy, **fleet silent/MDM scaffolding** (Intune/GPO/Jamf, unsigned), **config drift detection (SHA-256 digest)**, Admin `/devices`. Notarized/signed store packages = customer pipeline. [pilot-agent.md](getting-started/pilot-agent.md) · [pilot-agent-fleet.md](getting-started/pilot-agent-fleet.md). |
| Agent (Client & Routing) | BSDM Connect (`bsdm-connect`), Split Routing, PAC & UI | Beta (lab) | Альтернативный клиент на Rust, локальное разграничение маршрутов по доменам (`Direct`/`Proxy`/`Tunnel`/`Block`), генератор PAC-файлов с защитой от JS-инъекций, встроенный защищенный Web/Mobile UI сервер (CSRF defense, CSP, Slowloris protection) на `:8765`, скаффолды для macOS App и Android VPN Service. [bsdm-connect-client.md](getting-started/bsdm-connect-client.md) · [agent-ui-and-split-routing.md](getting-started/agent-ui-and-split-routing.md). |

## GA-скоуп v1.0

Уровень поддержки в релизе **v1.0** и значение по умолчанию в production-профиле
([`deploy/compose/docker-compose.prod.yml`](../deploy/compose/docker-compose.prod.yml), [`charts/bsdm/values-production.yaml`](../charts/bsdm/values-production.yaml)).
GA означает: есть security boundary, тесты, документированный путь и безопасный
prod-дефолт **в коде**. Beta/lab/frozen не входят в гарантии релиза. Порядок
развёртывания — [Production deployment](getting-started/production-deployment.md).

| Компонент | GA v1.0 | Prod default | Условие / комментарий |
|---|---|---|---|
| HTTP forward proxy + CONNECT | **GA** | ON | `Host` = authority, SSRF по разрешённым адресам, лимит тела запроса; open-proxy guard (`ALLOW_ANONYMOUS_PROXY`); `ALLOWED_CONNECT_PORTS` задаётся явно |
| `POLICY_MODE=selective-mitm` | **GA** | ON | MITM по `MITM_CATEGORIES`; CA fail-closed в production; breaker — от ≥ 3 клиентов, cooldown 900 с ([известные ограничения](getting-started/production-deployment.md#7a-известные-ограничения-безопасности-v10)) |
| `POLICY_MODE=sni` | **GA** | — | фильтрация по CONNECT authority, ClientHello не разбирается |
| `POLICY_MODE=full-mitm` | lab | запрещён | отклоняется в `DEPLOYMENT_PROFILE=production` |
| L1 cache (sharded, spill, compression, revalidation, coalescing) | **GA** | ON | приватные ответы (`Cookie`/`Authorization`/`Set-Cookie`/`Vary`) не хранятся |
| Redis L2 | beta | OFF | нет гайда по AUTH/TLS, failover не проверен |
| Hierarchy ICP/HTCP, peer discovery | beta | OFF | discovery без аутентификации |
| ACL (blocklist, `default_action=allow`) | **GA** | ON | |
| Categorization: UT1, custom DB | **GA** | ON | |
| Categorization: URLhaus / PhishTank / OTX online | beta | OFF | внешний вызов на hot path |
| RKN-registry sync | beta | OFF | в production только явный `RKN_FALLBACK_URL` |
| Rate limiting (локальный) | **GA** | ON | |
| Distributed rate limit / global sessions / threat sync | frozen | OFF | scaffolding |
| Auth Basic | **GA** | ON | без users-файла в production — отказ старта |
| Auth LDAP / NTLM / Kerberos | beta | OFF (feature) | NTLM/Kerberos кэшируют аутентификацию по IP; `kerberos_keytab` — AGPL-3.0 |
| OIDC + reverse proxy (ZTNA/IAP) | frozen | OFF | |
| Control REST `/api/*`, ACL REST | **GA** | ON, токен обязателен | `config/apply` — allowlist ключей; lab-маршруты → `404` в production; один токен без RBAC (RBAC — 1.1) |
| Admin Console `/admin/` | **GA** | ON | lab-разделы (Devices, AmneziaWG, WASM, Cluster, AI-cache) не используются |
| `/metrics`, `/health`, `/ready` | **GA** | ON | `METRICS_REQUIRE_AUTH=true` или bind на mgmt-IP |
| gRPC control plane | beta | OFF | |
| Control mTLS (agent, `:9443`) | lab | OFF | один CA на MITM и agent |
| Agent Contract (enroll/policy/CRL/OCSP/WS) | lab | OFF | |
| AmneziaWG API / BSDM Connect | lab | OFF | |
| eBPF/XDP | lab | OFF | инвариант `bsdm_proxy_ebpf_armed == 0` |
| ICAP | frozen | OFF | |
| Native DLP / CASB | frozen | OFF | |
| WASM hooks | frozen | OFF (feature) | `WASM_FAIL_OPEN=false` |
| Semantic / AI cache, Qdrant | beta | OFF | |
| Kafka → cache-indexer → ClickHouse, Search API | **GA** | опционально | Kafka/ClickHouse без TLS/SASL; URL в событиях — данные расшифрованного трафика |
| Lite HTTP event sink + SQLite indexer | **GA** | опционально | раздельные search/ingest токены |
| alert-worker | beta | OFF | |
| ml-worker + threat-score write-back | beta | OFF | `THREAT_SCORE_BLOCK_THRESHOLD=0` |
| dns-sinkhole UDP + RPZ API + zone reload | **GA** | ON (core) | только во внутренней сети |
| dns-sinkhole DoH / DoT | beta | OFF | |
| threat-intel collector + proxy `ti_shadow` | beta | shadow | observe-only допустим в prod |
| TI enforce (`ti_enforce`, SOAR, публикация RPZ) | beta | `TI_ENFORCEMENT_MODE=shadow` | только по [ADR 0008](adr/0008-threat-intel-shadow-mode.md) |
| PAC/WPAD | **GA** | OFF до `PAC_PROXY` | |

Поддерживаемая топология v1.0 — один узел или несколько **независимых** узлов
proxy за L4-балансировщиком (без общего кэша и состояния breaker). HA одного
сайта — [roadmap 1.2](roadmap.md).

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
   eBPF/XDP дополнительно закрыт двойным барьером: подсистема не взводится без
   явного `EBPF_XDP_ENABLED=true` или `EBPF_XDP_ALLOW_RUNTIME_ENABLE=true` в
   окружении процесса, а control plane может только переключать уже взведённую
   подсистему ([ebpf-xdp.md](features/ebpf-xdp.md)). Пилотный инвариант —
   `bsdm_proxy_ebpf_armed == 0`.
6. Native DLP выключен по умолчанию (`DLP_ENABLED=false` / unset). Для lab-оценки
   сигнатур: `DLP_ENABLED=true`. Runtime: `POST /api/security/dlp` с `[]` очищает
   паттерны (требует Bearer); состояние не персистится между рестартами.
7. `threat-intel` сохраняет нормализованные индикаторы в SQLite (`TI_SQLITE_PATH`),
   вычисляет взвешенный скоринг доверия и компилирует артефакты enforcement —
   зону `threats.rpz` и список `threat_domains.json` (`TI_RPZ_ENABLED`, по умолчанию
   `true`, `threat-intel/src/config.rs`). Предоставляет REST API для SOAR
   (`/api/v1/soar/*`) и ML скоринга репутации (`/api/v1/ml/reputation`);
   мутации SOAR требуют `TI_API_TOKEN` и пишутся в аудит `TI_SOAR_AUDIT_PATH`,
   листенер по умолчанию на `127.0.0.1` (`TI_ADMIN_BIND`).
   **Режим по умолчанию — Shadow: мониторинг без блокировки** (`TI_ENFORCEMENT_MODE=shadow`,
   [ADR 0008](adr/0008-threat-intel-shadow-mode.md)). В режиме shadow артефакты пишутся
   с суффиксом `.shadow` и используются proxy (`ti_shadow.rs`) исключительно для
   наблюдения без блокировки. При явном `TI_ENFORCEMENT_MODE=enforce` proxy (`ti_enforce.rs`)
   загружает `threat_domains.json` с тройным защитным барьером (Triple-Gate) и
   приоритетом корпоративного Allowlist. Переход к enforcement — только по критериям
   ADR 0008 и с явной подписью в [go/no-go](ops-and-dev/pilot-go-no-go-template.md).
8. `GlobalSessionStore`, Redis rate-limit path и `ThreatSyncEngine` добавлены как
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
