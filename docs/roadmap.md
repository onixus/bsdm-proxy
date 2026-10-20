# Roadmap BSDM-Proxy: v1.0 GA → 1.1 → 1.2 → 2.0

Текущая версия кода: **`1.0.0-rc.1`**, релиз-кандидат v1.0.
GA-скоуп описывает целевой поддерживаемый набор, а завершение GA-приёмки
фиксируется отдельно в критериях выхода ниже. Версию сверяйте с `proxy/Cargo.toml`.

## План допуска к релизу от 2026-10-20

Актуальный порядок реализации и приёмки — [план исполнения с GitHub-эпиками
и sub-issues](release-execution-plan.md). Он имеет приоритет над прежним
распределением работ по 1.1/1.2 ниже. Номер версии RC не означает опубликованную
и принятую production-поставку.

До v1.0 обязательны: защита обязательной MITM-инспекции от клиентского bypass,
ClientHello/SNI policy, безопасные CONNECT defaults, минимальный персональный
RBAC, защищённый аудит и TLS управления. Эти работы перенесены из будущего
hardening в release blockers. Поддерживаемая первая топология и путь аналитики
фиксируются отдельно; Compose production — предложенный эталон, Helm/native
не наследуют его приёмку.

Исторические нагрузочные отчёты, включая `load-test-results/latest.md`, не
являются доказательством допуска RC: требуется новая методика и новый прогон
на фиксированном артефакте. Статус реализации не меняется от создания задач.

Roadmap описывает намерения и последовательность работ. Фактическая зрелость
функций фиксируется в [матрице статуса](project-status.md) и её разделе
[GA-скоуп v1.0](project-status.md#ga-скоуп-v10); пункт roadmap не повышает
уровень зрелости без подтверждения там.

Источники плана на 1.x/2.0 — архитектурное и security-ревью релиз-кандидата
v1.0 (находки с идентификаторами `P1-xx`/`P2-xx` — архитектура, `AS-xx` —
AppSec). Номера используются для трассировки в issue и CHANGELOG.

---

## Архитектурная философия

1. **DNS/RPZ — первичный рубеж**: блокировка вредоносных и запрещённых доменов на уровне DNS до установления соединения.
2. **Контроль до расшифровки**: текущий Allow/Deny использует authority из `CONNECT`; проверка SNI из ClientHello теперь обязательна до допуска v1.0.
3. **Selective MITM**: расшифровка HTTPS только для категорий высокого риска (`MITM_CATEGORIES`).
4. **Local Agent**: исполнение политики на устройствах (On-Device SWG) вместо централизованного туннелирования — lab до 1.2.
5. **Threat Intelligence в Shadow Mode**: сбор и скоринг IOC без блокировки; enforcement — только по [ADR 0008](adr/0008-threat-intel-shadow-mode.md).
6. **Control plane не слабее data plane**: минимальные роли, аудит и TLS управления обязательны до допуска v1.0; изоляция CA по процессам остаётся дальнейшей архитектурной работой. В текущем RC control API использует один Bearer-токен без RBAC и работает в процессе proxy с доступом к CA ([known issues](getting-started/production-deployment.md#7a-известные-ограничения-безопасности-v10)).

---

## Обзор этапов

| Этап | Тема | Цель | Статус |
|---|---|---|---|
| Фазы A–D | Hybrid Policy, agent lab, Threat Intelligence | Историческая функциональная база | Реализация не означает принятого RC или пилота |
| **v1.0 GA** | Ограниченный production-релиз | Поддерживаемый прокси, обязательные гарантии защиты, проверенная поставка и эксплуатация | Не принят; эпики E1–E6 |
| **После v1.0** | Enterprise readiness | AD, HA, контентная защита, TI и проверка TCO | Эпик E7; точная версия после discovery |
| **Дополнительный hardening** | Остаток прежнего плана 1.1/1.2 | CA-иерархия, расширения и дальнейшая архитектура | Backlog, не обещание релизной даты |
| **2.0** | Multi-site, multi-tenant, раздельные planes | Единый источник политики для нескольких сайтов, изоляция арендаторов, control plane без доступа к `ca.key` | Видение |

Мажорная версия допускает несовместимые изменения конфигурации и API; миноры —
только аддитивные (новые переменные с безопасным дефолтом, новые колонки
ClickHouse через `ADD COLUMN IF NOT EXISTS`).

---

## v1.0 GA — Production baseline (текущий RC)

**Цель.** Одноузловой (или несколько независимых узлов за L4) Secure Web
Gateway, который безопасен «из коробки»: fail-closed control plane, shared
cache по RFC 9111, отсутствие lab-модулей в prod-профиле, подписанная поставка.

**Реализованная база RC (не закрывает эпики допуска E1–E6):**

- **GA-скоуп и prod-профили** — матрица GA/beta/lab/frozen; [`docker-compose.prod.yml`](../deploy/compose/docker-compose.prod.yml), [`values-production.yaml`](../charts/bsdm/values-production.yaml), захарденные systemd-юниты.
- **Security-фиксы ревью (data plane)** — shared cache не хранит приватные ответы (`Cookie`/`Authorization`/`Set-Cookie`/`Vary`); `Host` ≠ authority → `400`; SSRF по разрешённым адресам, `BLOCK_LOOPBACK_FORWARDING=true` в production; лимит тела запроса (`413`); таймауты upstream; Basic без users-файла и `PERF_FAST_CACHE_HIT` в production запрещены; hardening dns-sinkhole и cache-indexer (AS-01…AS-10, AS-12…AS-17, AS-19, AS-20, AS-22, AS-23).
- **Security-фиксы ревью (control plane и доверие)** — allowlist ключей `config/apply` без self-respawn и shell-команд (P0-5); CA fail-closed в production и метрика срока CA (P1-03); breaker срабатывает от ≥ 3 различных клиентов, cooldown 900 с, метрика trip'ов (P1-02, частично); open-proxy guard `ALLOW_ANONYMOUS_PROXY` (P1-04); отдельный `SEARCH_UPSTREAM_TOKEN` (P1-06); lab-маршруты `404` в production и device-токен, привязанный к устройству (P1-07, AS-05); RKN без стороннего fallback (P1-09). Итоговый список — `CHANGELOG.md` `[1.0.0-rc.1]`.
- **Supply chain** — блокирующий CI-гейт (fmt, clippy `-D warnings`, test, cargo-deny, admin-console), публикация шести образов с SBOM, trivy-гейтом и подписью cosign.
- **Эксплуатационная документация** — [production deployment](getting-started/production-deployment.md), [readiness checklist](ops-and-dev/production-readiness-checklist.md), [runbook](ops-and-dev/runbook.md), [upgrade guide](ops-and-dev/upgrade-guide.md).

**Критерии выхода (GA):**

- [ ] Обязательные гарантии E2 реализованы и независимо проверены; перенос в known issues сам по себе не закрывает release blocker.
- [ ] `ci-gate` зелёный на релизном теге; образы подписаны, SBOM опубликован, trivy без fixable CRITICAL/HIGH.
- [ ] Production-профиль не стартует без токена и users-файла; с ними — стартует, `bsdm_proxy_ebpf_armed == 0`, `CONNECT 127.0.0.1:9090` → `403`.
- [ ] Readiness checklist пройден на референсном стенде (нагрузочный тест, учения CA и restore).
- [ ] Эпики E1–E6 закрыты с доказательствами; проведён эксплуатационный пилот и подписан go/no-go для принятой сборки.
- [x] Known issues v1.0 опубликованы ([§7a prod-гайда](getting-started/production-deployment.md#7a-известные-ограничения-безопасности-v10)).

**Метрики:** прежние ориентиры p95 ≤ 10 мс на HIT / p99 ≤ 50 мс на selective-MITM,
error rate < 0.5%, RTO proxy ≤ 1 ч / analytics ≤ 4 ч не являются измеренными
гарантиями RC. Пороги, нагрузочный профиль, baseline, RTO/RPO и методы расчёта
утверждаются до испытаний в R03; доказательства собираются в E4.

---

## 1.1 — Control plane & trust hardening

Историческая группировка backlog. Обязательные части breaker/SNI, RBAC,
аудита, TLS управления, destination policy и доставки/приватности событий
перенесены в E2 до v1.0. Остальные пункты не повышают maturity автоматически.
В плане допуска разрешён штатный TLS reverse proxy; встроенный TLS не является
единственным допустимым способом выполнить gate v1.0.

**Цель.** Убрать класс «один токен = root на узле с ключом CA» и сделать
инспекцию неотключаемой со стороны клиента. После 1.1 control plane можно
выставлять операторам за пределы хоста без компенсирующих мер.

**Эпики:**

1. **MITM circuit breaker v2** (остаток P1-02, ADR 0007 rev. 2) — учитывать только TLS-alert'ы недоверия к сертификату (`unknown_ca`, `bad_certificate`, `certificate_unknown`), а не любой RST/EOF; для `malware`/`phishing` в production — fail-closed (block) вместо bypass; trip → событие в pipeline + алерт-правило в поставке. Закрывает known issue «3 сговорившихся клиента → 15 мин bypass».
2. **Профиль MITM-листов и CA** (P2-02) — `not_after ≤ 397 д`, EKU `serverAuth`, случайный serial; поставляемый алерт на `bsdm_proxy_mitm_ca_not_after_timestamp_seconds`.
3. **Гигиена data plane и секретов** — дефолт `ALLOWED_CONNECT_PORTS=443` в production и разделение CONNECT/HTTP-портов (остаток AS-15); `HTTP_BIND`; поддержка `*_FILE` для секретов; per-IP backoff неудачных входов Basic (остаток AS-07); append-only ingest и обязательный отдельный `INGEST_API_TOKEN` в production (AS-18); таймаут на тело ответа upstream (остаток AS-22); лимит DoT/DoH-соединений на IP (остаток AS-13); RPZ-фиды только по `https` (остаток AS-14).
4. **Остатки control plane** — публичные `GET /api/stats`, `/api/hierarchy/peers`, `/api/upstream/tls` за токеном (P2-09); проверка `Host` в reverse-proxy режиме при разморозке.
5. **RBAC control plane** — роли `viewer` / `policy-admin` / `security-admin` / `agent`; per-principal токены с id, хешированные at rest, ротация без рестарта; отдельный scope security-posture (MITM, CA, pinning, auth backend).
6. **Неизменяемый audit log** изменений политики и конфигурации (actor, diff, время, IP источника) → event pipeline + append-only файл; просмотр в Admin Console.
7. **TLS для control plane** `:9090` из коробки + опциональный OIDC-вход в Admin Console вместо статического Bearer.
8. **CA-иерархия** (P2-03, P2-04) — offline root → короткоживущий MITM-intermediate (ротация без смены root на клиентах) / Agent-intermediate / делегированный OCSP-responder с кэшем ответов; hot-reload CA; интерфейс PKCS#11/HSM.
9. **Реальный SNI-контроль** (P2-01) — peek ClientHello, SNI ≠ `CONNECT` authority → deny/алерт; политика для `CONNECT` по голому IP; явное решение по ECH с метрикой.
10. **Vary-aware cache** — ключ с нормализованными значениями `Vary` вместо «не хранить».
11. **Приватность событий** (P1-08) — `EVENT_URL_MODE` (strip/hash query) по умолчанию в production, privacy-профили per category (none / domain-only / path / full), псевдонимизация username; Kafka TLS/SASL и ClickHouse TLS.
12. **Аутентифицированная иерархия кэшей** — peer discovery с HMAC/mTLS, обязательный mTLS для sibling fetch.
13. **dns-sinkhole** — TCP fallback, EDNS0, кэш с валидацией, DNSSEC-passthrough, `DNS_SINKHOLE_ALLOWED_CLIENTS`.
14. **Единая схема конфигурации** — типизированная, валидируемая, версионируемая; `config/apply` работает с allowlist ключей схемы, а не с сырым env.
15. **Эксплуатационный долг** — очистка `CACHE_SPILL_DIR` при старте; поставляемые Prometheus-правила для proxy (down, latency, breaker, event drop, SSRF blocks); миграция `rustls-pemfile` → `rustls-pki-types`.

**Критерии выхода:**

- [ ] Ни одна операция control plane не выполняется без роли; все мутации видны в audit log.
- [ ] Admin Console и `/api/*` доступны по TLS без внешнего reverse proxy.
- [ ] Клиенты, обрывающие собственные handshake (в том числе несколько сговорившихся), не могут перевести домен из категорий `malware`/`phishing` в bypass (e2e-тест); trip порождает событие и алерт.
- [ ] Алерты на срок CA и trip'ы breaker входят в поставку.
- [ ] Ни одного публичного endpoint control plane, кроме `/health`, `/ready`; `ALLOWED_CONNECT_PORTS` имеет безопасный дефолт.
- [ ] Domain fronting (SNI ≠ authority) детектируется e2e-тестом.
- [ ] События в production по умолчанию без query-строк; Kafka работает по SASL_SSL в референсном стенде.

**Метрики:** 0 эндпоинтов control plane без авторизации; доля bypass-трафика по breaker < 1% с аудитом каждого trip; время ротации токена без простоя = 0; покрытие audit log 100% мутаций; hit ratio на авторизованном контенте не ниже v1.0 после Vary-aware cache.

---

## 1.2 — HA одного сайта и enterprise identity

**Цель.** Отказ любого одного узла сайта не заметен пользователям; корпоративная
аутентификация и блокировка по threat intelligence — в GA.

**Эпики:**

1. **Active-active HA на сайте** — несколько proxy за L4 LB, общий Redis L2 (`rediss://` + AUTH) с failover-тестами, общий policy/ACL store, согласованное состояние breaker и cert cache (или детерминированные листы); Redis L2 → GA.
2. **Distributed rate limit, global sessions, threat sync** — довести scaffolding до рабочего multi-node с тестами **или удалить** из кодовой базы.
3. **LDAP / Kerberos / NTLM → GA** — интеграционный стенд в CI; fail-closed при недоступности DC с метрикой; аутентификация, привязанная к соединению, а не к IP клиента (AS-11); решение по лицензии `kerberos_keytab` (AGPL-3.0) и `rsa` (Marvin) через `sspi` — замена или юридическое заключение. `AUTH_CONN_CACHE_TTL_SECONDS` для топологий с пулящим LB (P2-07).
4. **Threat-intel enforce → GA** по критериям ADR 0008; подпись/целостность фидов и max-delta guard для всех блок-фидов (RKN, TI, UT1); RKN без стороннего fallback (P1-09).
5. **Agent Contract → beta-prod** — device-токен привязан к mTLS fingerprint, короткоживущие токены, подписанные policy bundles; signed/notarized дистрибуция — customer pipeline.
6. **alert-worker и ml-worker → GA** (скоринг и алерты; блокировка по ML остаётся opt-in).
7. **SLO и алерт-пакет** — breaker trips, CA expiry, event drop rate, auth backend errors, SSRF blocks; документированные fail-modes Redis/Kafka/LDAP (P2-05).

**Критерии выхода:**

- [ ] Остановка любого узла proxy под нагрузкой: error rate < 0.5%, без ручных действий (chaos-тест в CI или на стенде).
- [ ] Distributed rate limit либо работает на ≥ 2 узлах с тестами, либо удалён.
- [ ] LDAP и Kerberos проходят интеграционный стенд в CI; NTLM/Kerberos не наследуют аутентификацию между пользователями за NAT.
- [ ] TI enforce включён хотя бы на одной площадке по записи go/no-go ADR 0008 с FP < 1% за 14 дней shadow.

**Метрики:** доступность сайта ≥ 99.9% (месяц); RTO отказа узла ≤ 30 с (выход из LB по readiness); FP-rate TI enforce < 1%; доля аутентифицированного трафика при Kerberos ≥ 99%.

---

## 2.0 — Multi-site, multi-tenant, раздельные planes

**Цель.** Платформа для нескольких площадок и арендаторов, в которой
компрометация административного контура не означает компрометацию CA.

**Эпики:**

1. **Multi-node / multi-site control plane** — единый источник политики (GitOps-friendly), согласованный аудит, шардирование аналитики по сайтам.
2. **Multi-tenancy** — изоляция политик, кэша (tenant-aware cache key), аналитики и CA per tenant.
3. **Разделение data plane и control plane** по процессам/контейнерам: control plane без доступа к `ca.key`, подпись листов через локальный signer-сервис (HSM-ready).
4. **Расширения** (WASM / ICAP / DLP) — sandbox с ресурсными квотами, capability-модель и подписанные модули — **или** окончательный отказ и удаление из кода.

**Критерии выхода:**

- [ ] Политика применяется на ≥ 2 сайтах из одного источника с аудитом изменений.
- [ ] Данные одного арендатора недоступны другому (кэш, аналитика, политика) — подтверждено тестами изоляции и внешним пентестом.
- [ ] RCE в процессе control plane не даёт доступа к ключу CA (подтверждено threat model и пентестом).
- [ ] По каждому замороженному модулю принято решение: продукт с sandbox или удаление.

**Метрики:** время распространения политики на все сайты ≤ 60 с; 0 межарендаторных утечек в пентесте; доля кода в процессе с доступом к ключу CA (signer) — минимальная и аудируемая.

---

## Выполнено: фазы A–D

История работ до v1.0. Отмеченные пункты реализованы; уровень зрелости — по
[матрице статуса](project-status.md).

### Фаза A — Hybrid Policy Foundation

- [x] Внедрение параметра `POLICY_MODE` (`selective-mitm` | `sni` | `full-mitm`) — по умолчанию `selective-mitm`.
- [x] Перевод `dns-sinkhole` в Core-компонент поставки (включение в базовый `docker-compose.yml`).
- [x] Движок правил до TLS-терминирования. *Уточнение (ревью v1.0): решение принимается по authority из `CONNECT`, ClientHello не разбирается — реальный SNI peek перенесён в 1.1.*
- [x] Селективный MITM по списку категорий (`MITM_CATEGORIES=malware,phishing,illegal-content`).
- [x] Изменение порта прокси по умолчанию с `1488` на `3128`.
- [x] Расширенная наблюдаемость исключений (`decision_source` = `dns | sni | mitm | pinning-bypass`).
- [x] Верификация инварианта `POLICY_MODE=sni` never terminates TLS (unit + e2e + docs, #272).

---

### Фаза B — Selective MITM Hardening & Pilot

- [x] Документирование и регламентация полного жизненного цикла CA (`docs/ops-and-dev/ca-lifecycle.md`).
- [x] Управление реестром исключений Certificate Pinning (`pinning_exceptions.json`).
- [x] Включение MITM строго через политики (запрет глобальных флагов принудительного MITM в продакшене).
- [x] Профиль нагрузочного тестирования пилота: Selective MITM + DNS + Auth (100 пользователей) — `scripts/run-hybrid-load-test.sh`, [docs](ops-and-dev/load-test-selective-mitm.md), CI hybrid job (#269).
- [x] Pilot compose + acceptance criteria (Hybrid defaults, no experimental day-1) — `deploy/compose/docker-compose.pilot.yml`, [pilot-deployment.md](getting-started/pilot-deployment.md) (#270).
- [x] Проверка резервного копирования и восстановления ClickHouse / ротации CA — [backup-restore.md](ops-and-dev/backup-restore.md), `scripts/drill-backup-restore.sh`, `scripts/backup-clickhouse.sh` / `restore-clickhouse.sh`, CA archive rollback.
- [x] **Request hot-path performance & lock optimization** — zero-allocation domain/category matching, sharded `PolicyDecisionCache` (`RwLock`), index-based regex resolution, atomic sampling and static Prometheus metrics labels.

---

### Фаза C — Agent Direction (On-Device SWG)

- [x] Разработка спецификации Agent Contract v0.1 (`docs/architecture/agent-contract.md`).
- [x] Написание ADR 0005: Local Policy Agent vs Tunnel-First (`docs/adr/0005-local-policy-agent-vs-tunnel-first.md`).
- [x] Минимальный lab-прототип агента (`examples/agent-spike`, Linux/macOS smoke) + control-plane API (#273, v0.9.2–0.9.6).
- [x] Доставка политик и регистрация устройств (policy pull/push, enroll, heartbeat, devices, CRL/OCSP lab; Admin `/devices`).
- [x] RFC 6960 DER OCSP responder + gRPC agent policy product path (`WatchAgentPolicy`).
- [x] WebSocket policy push (`/api/v1/agent/policy/ws`).
- [x] Data-plane TLS OCSP stapling (MITM + control mTLS server leaves).
- [x] Multi-node shared device registry + CRL (Redis write-through).
- [x] Multi-OS pilot installers + system-proxy hooks (`packaging/agent`, agent-spike CLI).
- [x] MDM/GPO **silent fleet packaging scaffolding** — silent installers, Intune Win32 scripts, GPO ADMX, macOS pkgbuild + mobileconfig example, fleet drop script (`packaging/agent/fleet/`, [pilot-agent-fleet.md](getting-started/pilot-agent-fleet.md)).
- [x] **AmneziaWG / BSDM Connect endpoint integration** — Curve25519 cryptography, pre-shared keys (PSK), automated peer provisioning, Agent Contract `tunnel` capability, atomic config generation, device revocation sync, and Prometheus telemetry.
- [x] **Alternative Rust Client (`bsdm-connect`)** — standalone CLI and daemon binary, AWG configuration lifecycle, command execution timeouts, atomic 0600 file save ([bsdm-connect-client.md](getting-started/bsdm-connect-client.md)).
- [x] **Domain-based split routing & PAC generator** — Local route evaluation (`Direct`, `Proxy`, `Tunnel`, `Block`), standards-compliant JavaScript `FindProxyForURL(url, host)` generation with strict JS escaping and CIDR/pattern validation ([agent-ui-and-split-routing.md](getting-started/agent-ui-and-split-routing.md)).
- [x] **Hardened Agent Web/Mobile UI server** — Embedded localhost UI server with real-time metrics, Slowloris protection, strict CSP/Frame headers, and CSRF / DNS-rebinding defense (`X-BSDM-Request: 1`).
- [x] **Cross-platform UI & Packaging Scaffolds** — macOS App bundle creator script (`packaging/agent/macos/create-macos-app.sh`) and Android VPN Service template (`packaging/agent/android/`).
- [x] **Comprehensive E2E integration test suite** — `e2e/tests/amneziawg_and_agent_e2e.rs` covering AWG server config, keypair generation, agent enrollment, tunnel lifecycle, PAC generation, and UI CSRF rejection.
- [ ] **Notarized / Authenticode-signed store distribution** — customer signing pipeline only (out of lab; no Apple/Microsoft certs in CI).

---

### Фаза D — Threat Intelligence & Feed Collector

> Все артефакты ниже реализованы как **генерация и наблюдение**. Применение их для
> блокировки трафика выключено по умолчанию и допускается только по критериям
> перехода из [ADR 0008](adr/0008-threat-intel-shadow-mode.md).

- [x] **Threat intelligence feed collector** (`threat-intel`, TASK-TI-001) — сбор OpenPhish, PhishStats, Phishing.Database и URLhaus по расписанию, retry/backoff, дедупликация, метрики на `:8093/metrics`, JSONL-снапшоты + `report.json`, Compose profile и Helm toggle ([threat-intel-collector.md](features/threat-intel-collector.md)).
- [x] **IOC storage & SQLite persistence** (TASK-TI-002) — структурированное хранение индикаторов (`SqliteStorage`, `indicators`, `sources`, `collection_history`), дедупликация, TTL-экспирация и индексы.
- [x] **IOC normalization and category tagging** (TASK-TI-003) — канонизация URL/доменов/IP, валидация Punycode/IDN, фильтрация bogon/private IP.
- [x] **Confidence Scoring & Multi-source correlation** (TASK-TI-010) — алгоритм взвешенного скоринга с бонусом корреляции фидов и временным затуханием (freshness decay).
- [x] **Automated RPZ zone generation & atomic rollback** (TASK-TI-021) — автоматическая компиляция фидов в RPZ-зоны (`threats.rpz`) с монотонным BIND-серийником `YYYYMMDDNN`, ротацией резервных копий (`.bak`) и поддержкой атомарного отката (`rollback_rpz_zone`). Публикация зоны в `dns-sinkhole` — отдельный явный шаг оператора (ADR 0008), по умолчанию не выполняется.
- [x] **Proxy ACL threat feed export** (TASK-TI-020) — экспорт нормализованных доменов и URL угроз в JSON-формате (`threat_domains.json`). В режиме `TI_ENFORCEMENT_MODE=shadow` (по умолчанию) proxy читает только `.shadow`-копию для наблюдения (`ti_shadow.rs`); сам `threat_domains.json` загружается data-plane (`ti_enforce.rs`) лишь при явном `TI_ENFORCEMENT_MODE=enforce` под Triple-Gate и с приоритетом Allowlist (ADR 0008).
- [x] **Enterprise SIEM Integration & Delivery Transports** (TASK-TI-030) — форматирование событий в CEF (ArcSight/QRadar/Splunk), ECS JSON (Elastic), Syslog RFC 5424 и сетевая/файловая доставка (`SyslogTransport` UDP/TCP, `FileSiemTransport`, `SiemDispatcher`).
- [x] **SOAR Automated Response API** (TASK-TI-031) — автоматизированные действия сдерживания и расследования (`/api/v1/soar/block`, `/api/v1/soar/unblock`, `/api/v1/soar/investigate`).
- [x] **ML Domain Reputation, Phishing Clustering & Anomaly Engine** (TASK-TI-040) — детекция омоглифов (Unicode confusables), Damerau-Levenshtein расстояние до брендов, кластеризация фишинговых кампаний (`cluster_phishing_campaigns`) и энтропийный анализ аномалий (`detect_domain_anomalies`, `/api/v1/ml/*`).
- [x] **DNS RPZ Live Status & Rollback API** — оперативный мониторинг SOA-серийника и правил (`/api/v1/rpz/status`), аварийный откат зоны (`/api/v1/rpz/rollback`) и интеграция с панелью RPZ в Admin Console.
- [x] **SOC Operations & False Positive Triage UI** — интерактивное расследование индикаторов с 1-click unblock/whitelist (`ThreatInvestigationModal.tsx`), инспектор брендового фишинга и Unicode-омоглифов (`MlDomainInspector.tsx`).
- [x] **Core Proxy Lock Sharding & Metrics Guard** — 32-секторное шардирование `MitmCircuitBreaker`, защита от взрыва кардинальности Prometheus-метрик (eTLD+1) и 50ms таймауты L2 Redis с неблокирующим `UNLINK`.
- [x] **Agent Fleet Drift & OS Proxy Enforcement** — вычисление SHA-256 дайджеста локальных правил, мониторинг системного перехвата прокси и индикация дрифта в Admin Console.

---

## Замороженные модули (Scope Freeze)

Состояние на v1.0; судьба модулей решается в эпике 2.0 «Расширения».

Следующие экспериментальные модули заморожены в текущем виде для исключения фичер-крипа:
- **Native String DLP**: Заморожен до появления полноценного спека.
- **Mock OIDC Reverse Proxy**: Заморожен.
- **Global Session / Threat Sync Scaffolding**: Заморожен до подтверждения однокластерной модели.

Отдельно от заморозки: **eBPF/XDP** модернизирован в lab-режиме (dual-stack IPv4/IPv6, Control API `/api/ebpf/*`, учет дропов ядра через BPF-карту `bsdm_drop_stats`) и в Scope Freeze больше не входит. Компонент остаётся lab-only и не входит в Day-1 скоуп одноузлового пилота — см. [project-status.md](project-status.md). Выключен по умолчанию и требует явного arming в окружении процесса (`EBPF_XDP_ENABLED` / `EBPF_XDP_ALLOW_RUNTIME_ENABLE`): control plane не может включить фильтр сам и отвечает 403. Lab-путь запуска — [features/ebpf-xdp.md](features/ebpf-xdp.md), смоук `scripts/run-ebpf-lab-smoke.sh`.

---

## Правила roadmap

1. Выполненная задача не повышает зрелость функции автоматически (требуются тесты, документация, наблюдаемость).
2. Безопасность и предсказуемость важнее расширения функционала; control plane не может быть слабее data plane.
3. Каждый этап закрывается по критериям выхода, а не по дате. Открытый обязательный эпик означает no-go; исключение требует пересмотра support contract и проверенного ограничения, а не только записи в known issues.
4. Исторические release notes не переписываются под новую архитектуру.
