# Roadmap BSDM-Proxy (Hybrid + Agent Architecture)

Текущая версия workspace: **`0.9.7`**.

Roadmap определяет порядок работ в рамках стратегии **Hybrid Policy (DNS -> SNI -> Selective MITM)** и переход к **On-Device Local Policy Agent**. Фактическая зрелость функционала фиксируется в [матрице статуса](project-status.md).

---

## Архитектурная философия

1. **DNS/RPZ — первичный рубеж**: фильтрация вредоносных и заблокированных доменов на уровне DNS до установления соединений.
2. **SNI (ClientHello) — контроль до расшифровки**: применение правил (Allow/Deny/Redirect) без терминирования TLS.
3. **Selective MITM — селективная расшифровка**: расшифровка HTTPS применяется исключительно для целевых категорий высокого риска (`MITM_CATEGORIES`).
4. **Local Agent — фильтрация на устройствах**: исполнение правил на эндпоинтах пользователя (On-Device SWG) вместо централизованного туннелирования.

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
- [x] Pilot compose + acceptance criteria (Hybrid defaults, no experimental day-1) — `docker-compose.pilot.yml`, [pilot-deployment.md](getting-started/pilot-deployment.md) (#270).
- [x] Проверка резервного копирования и восстановления ClickHouse / ротации CA — [backup-restore.md](ops-and-dev/backup-restore.md), `scripts/drill-backup-restore.sh`, `scripts/backup-clickhouse.sh` / `restore-clickhouse.sh`, CA archive rollback.

---

## Фаза C — Agent Direction (On-Device SWG)

- [x] Разработка спецификации Agent Contract v0.1 (`docs/architecture/agent-contract.md`).
- [x] Написание ADR 0005: Local Policy Agent vs Tunnel-First (`docs/adr/0005-local-policy-agent-vs-tunnel-first.md`).
- [x] Минимальный lab-прототип агента (`examples/agent-spike`, Linux/macOS smoke) + control-plane API (#273, v0.9.2–0.9.6).
- [x] Доставка политик и регистрация устройств (policy pull/push, enroll, heartbeat, devices, CRL/OCSP lab; Admin `/devices`).
- [x] RFC 6960 DER OCSP responder + gRPC agent policy product path (`WatchAgentPolicy`).
- [x] WebSocket policy push (`/api/v1/agent/policy/ws`).
- [ ] Production multi-OS agent (installers, system proxy) и multi-node shared registry.

---

## Замороженные модули (Scope Freeze)

Следующие экспериментальные модули заморожены в текущем виде для исключения фичер-крипа:
- **AmneziaWG / BSDM Connect**: Заморожен до полной реализации Agent Contract v0.1.
- **eBPF/XDP**: Заморожен, не является основным вектором фильтрации.
- **Native String DLP**: Заморожен до появления полноценного спека.
- **Mock OIDC Reverse Proxy**: Заморожен.
- **Global Session / Threat Sync Scaffolding**: Заморожен до подтверждения однокластерной модели.

---

## Правила roadmap

1. Выполненная задача не повышает зрелость функции автоматически (требуются тесты, документация, наблюдаемость).
2. Безопасность и предсказуемость селективного режима имеют приоритет перед расширением функционала.
3. Исторические release notes не переписываются под новую архитектуру.
