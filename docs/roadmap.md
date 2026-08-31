# Roadmap BSDM-Proxy (Hybrid + Agent Architecture)

Текущая версия workspace: **`0.9.13`**.

Roadmap определяет порядок работ в рамках стратегии **Hybrid Policy (DNS -> SNI -> Selective MITM)**, переход к **On-Device Local Policy Agent** и интеграцию **Threat Intelligence**. Фактическая зрелость функционала фиксируется в [матрице статуса](project-status.md).

---

## Архитектурная философия

1. **DNS/RPZ — первичный рубеж**: фильтрация вредоносных и заблокированных доменов на уровне DNS до установления соединений.
2. **SNI (ClientHello) — контроль до расшифровки**: применение правил (Allow/Deny/Redirect) без терминирования TLS.
3. **Selective MITM — селективная расшифровка**: расшифровка HTTPS применяется исключительно для целевых категорий высокого риска (`MITM_CATEGORIES`).
4. **Local Agent — фильтрация на устройствах**: исполнение правил на эндпоинтах пользователя (On-Device SWG) вместо централизованного туннелирования.
5. **Threat Intelligence — мониторинг угроз в режиме Shadow**: автоматический сбор и актуализация IOC-индикаторов (фишинг, вредоносное ПО). Enforcement для DNS RPZ и прокси-политик — в разработке и выключен по умолчанию (`TI_ENFORCEMENT_MODE=shadow`, [ADR 0008](adr/0008-threat-intel-shadow-mode.md)).

---

## Фаза A — Hybrid Policy Foundation

- [x] Внедрение параметра `POLICY_MODE` (`selective-mitm` | `sni` | `full-mitm`) — по умолчанию `selective-mitm`.
- [x] Перевод `dns-sinkhole` в Core-компонент поставки (включение в базовый `docker-compose.yml`).
- [x] Движок правил на уровне SNI (ClientHello) до TLS-терминирования.
- [x] Селективный MITM по списку категорий (`MITM_CATEGORIES=malware,phishing,illegal-content`).
- [x] Изменение порта прокси по умолчанию с `1488` на `3128`.
- [x] Расширенная наблюдаемость исключений (`decision_source` = `dns | sni | mitm | pinning-bypass`).
- [x] Верификация инварианта `POLICY_MODE=sni` never terminates TLS (unit + e2e + docs, #272).

---

## Фаза B — Selective MITM Hardening & Pilot

- [x] Документирование и регламентация полного жизненного цикла CA (`docs/ops-and-dev/ca-lifecycle.md`).
- [x] Управление реестром исключений Certificate Pinning (`pinning_exceptions.json`).
- [x] Включение MITM строго через политики (запрет глобальных флагов принудительного MITM в продакшене).
- [x] Профиль нагрузочного тестирования пилота: Selective MITM + DNS + Auth (100 пользователей) — `scripts/run-hybrid-load-test.sh`, [docs](ops-and-dev/load-test-selective-mitm.md), CI hybrid job (#269).
- [x] Pilot compose + acceptance criteria (Hybrid defaults, no experimental day-1) — `deploy/compose/docker-compose.pilot.yml`, [pilot-deployment.md](getting-started/pilot-deployment.md) (#270).
- [x] Проверка резервного копирования и восстановления ClickHouse / ротации CA — [backup-restore.md](ops-and-dev/backup-restore.md), `scripts/drill-backup-restore.sh`, `scripts/backup-clickhouse.sh` / `restore-clickhouse.sh`, CA archive rollback.
- [x] **Request hot-path performance & lock optimization** — zero-allocation domain/category matching, sharded `PolicyDecisionCache` (`RwLock`), index-based regex resolution, atomic sampling and static Prometheus metrics labels.

---

## Фаза C — Agent Direction (On-Device SWG)

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

## Фаза D — Threat Intelligence & Feed Collector

> Все артефакты ниже реализованы как **генерация и наблюдение**. Применение их для
> блокировки трафика выключено по умолчанию и допускается только по критериям
> перехода из [ADR 0008](adr/0008-threat-intel-shadow-mode.md).

- [x] **Threat intelligence feed collector** (`threat-intel`, TASK-TI-001) — сбор OpenPhish, PhishStats, Phishing.Database и URLhaus по расписанию, retry/backoff, дедупликация, метрики на `:8093/metrics`, JSONL-снапшоты + `report.json`, Compose profile и Helm toggle ([threat-intel-collector.md](features/threat-intel-collector.md)).
- [x] **IOC storage & SQLite persistence** (TASK-TI-002) — структурированное хранение индикаторов (`SqliteStorage`, `indicators`, `sources`, `collection_history`), дедупликация, TTL-экспирация и индексы.
- [x] **IOC normalization and category tagging** (TASK-TI-003) — канонизация URL/доменов/IP, валидация Punycode/IDN, фильтрация bogon/private IP.
- [x] **Confidence Scoring & Multi-source correlation** (TASK-TI-010) — алгоритм взвешенного скоринга с бонусом корреляции фидов и временным затуханием (freshness decay).
- [x] **Automated RPZ zone generation & atomic rollback** (TASK-TI-021) — автоматическая компиляция фидов в RPZ-зоны (`threats.rpz`) с монотонным BIND-серийником `YYYYMMDDNN`, ротацией резервных копий (`.bak`) и поддержкой атомарного отката (`rollback_rpz_zone`). Публикация зоны в `dns-sinkhole` — отдельный явный шаг оператора (ADR 0008), по умолчанию не выполняется.
- [x] **Proxy ACL threat feed export** (TASK-TI-020) — экспорт нормализованных доменов и URL угроз в JSON-формате (`threat_domains.json`). Файл предназначен для будущего применения в политиках proxy data-plane; сейчас proxy его не читает.
- [x] **Enterprise SIEM Integration & Delivery Transports** (TASK-TI-030) — форматирование событий в CEF (ArcSight/QRadar/Splunk), ECS JSON (Elastic), Syslog RFC 5424 и сетевая/файловая доставка (`SyslogTransport` UDP/TCP, `FileSiemTransport`, `SiemDispatcher`).
- [x] **SOAR Automated Response API** (TASK-TI-031) — автоматизированные действия сдерживания и расследования (`/api/v1/soar/block`, `/api/v1/soar/unblock`, `/api/v1/soar/investigate`).
- [x] **ML Domain Reputation, Phishing Clustering & Anomaly Engine** (TASK-TI-040) — детекция омоглифов (Unicode confusables), Damerau-Levenshtein расстояние до брендов, кластеризация фишинговых кампаний (`cluster_phishing_campaigns`) и энтропийный анализ аномалий (`detect_domain_anomalies`, `/api/v1/ml/*`).


---

## Замороженные модули (Scope Freeze)

Следующие экспериментальные модули заморожены в текущем виде для исключения фичер-крипа:
- **eBPF/XDP**: Заморожен, не является основным вектором фильтрации.
- **Native String DLP**: Заморожен до появления полноценного спека.
- **Mock OIDC Reverse Proxy**: Заморожен.
- **Global Session / Threat Sync Scaffolding**: Заморожен до подтверждения однокластерной модели.

---

## Правила roadmap

1. Выполненная задача не повышает зрелость функции автоматически (требуются тесты, документация, наблюдаемость).
2. Безопасность и предсказуемость селективного режима имеют приоритет перед расширением функционала.
3. Исторические release notes не переписываются под новую архитектуру.
