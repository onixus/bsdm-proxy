# План доведения BSDM-Proxy до релиза и эксплуатации

Дата: **2026-10-20**. Статус: **запланировано, не выполнено**. Версия кода остаётся `1.0.0-rc.1`.

## Цель и границы

Первый результат — ограниченный production v1.0 управляемого прокси для одной площадки. Второй — отдельно принятые enterprise-возможности. Наличие реализации, документации или зелёного CI не означает опубликованную и принятую поставку.

Предлагаемый эталон: одна Linux-платформа, Compose production и HTTP event sink + SQLite. Окончательный support contract фиксирует R01. Helm, native, Kafka/ClickHouse и beta/lab-функции не наследуют эту приёмку. AWG, AI-cache, WASM, multi-site и дополнительные UI-фичи замораживаются на время v1.0.

Минимальный RBAC, персональный аудит, TLS управления, MITM без клиентского bypass, SNI и безопасные CONNECT defaults перенесены в обязательные gates v1.0. Исторические отчёты `load-test-results/latest.md` не используются как доказательство принятого RC. Их исправление и новая методика — R02/R16.

## Milestones и порядок

- [v1.0 — Production acceptance](https://github.com/onixus/bsdm-proxy/milestone/1)
- [Post-v1.0 — Enterprise readiness](https://github.com/onixus/bsdm-proxy/milestone/2)

Порядок приёмки: **E1 → E2 + E3 → E4 → E5 → E6 → E7**. Подготовка harness, мониторинга и runbooks может идти параллельно. Зависимости отдельных задач ниже задают условия их приёмки; верхнеуровневая стрелка означает выходной gate, а не запрет ранней подготовки.

Ориентир для двух разработчиков, DevSecOps/QA и независимого security reviewer — **8–12 недель до решения по ограниченному v1.0**. После R01–R03 оценка пересчитывается. Календарные сроки не заменяют gates. Персональные исполнители не назначены автоматически; указаны ответственные роли.

| Эпик | Ответственность | Зависимости закрытия | Оценка |
|---|---|---|---|
| [E1 / #404](https://github.com/onixus/bsdm-proxy/issues/404) — Контракт v1.0 и достоверность доказательств | Product owner + архитектор | Нет | 2–3 рабочих дня |
| [E2 / #408](https://github.com/onixus/bsdm-proxy/issues/408) — Обязательные гарантии безопасности и совместимости v1.0 | Разработка + независимый AppSec | [E1 / #404](https://github.com/onixus/bsdm-proxy/issues/404) | 2–4 недели |
| [E3 / #417](https://github.com/onixus/bsdm-proxy/issues/417) — Воспроизводимая RC-поставка и жизненный цикл установки | DevSecOps | [E1 / #404](https://github.com/onixus/bsdm-proxy/issues/404) | 1–2 недели; параллельно E2 |
| [E4 / #422](https://github.com/onixus/bsdm-proxy/issues/422) — Независимая техническая приёмка фиксированного RC | QA + независимый AppSec | [E1 / #404](https://github.com/onixus/bsdm-proxy/issues/404), [E2 / #408](https://github.com/onixus/bsdm-proxy/issues/408), [E3 / #417](https://github.com/onixus/bsdm-proxy/issues/417) | 1–2 недели после стабилизации RC |
| [E5 / #428](https://github.com/onixus/bsdm-proxy/issues/428) — Ограниченный пилот и эксплуатационный допуск | Владелец сервиса + эксплуатация | [E4 / #422](https://github.com/onixus/bsdm-proxy/issues/422) | 2–4 недели |
| [E6 / #432](https://github.com/onixus/bsdm-proxy/issues/432) — Релиз v1.0 и поддерживаемая коммерческая поставка | Release manager + Product owner | [E5 / #428](https://github.com/onixus/bsdm-proxy/issues/428) | После go/no-go; без фиксированной даты |
| [E7 / #436](https://github.com/onixus/bsdm-proxy/issues/436) — Корпоративный SWG после v1.0: identity, HA и эффективность защиты | Product owner + архитектор | [E6 / #432](https://github.com/onixus/bsdm-proxy/issues/432) | После v1.0; оценить после discovery |

## Общее правило закрытия

- E1–E6 обязательны для v1.0. E7 — отдельная последующая приёмка, не блокер ограниченного релиза.
- Закрытие требует результата, проверяемого evidence и reviewer; role owner назначает конкретного исполнителя при старте.
- Для runtime-проверки фиксируются SHA, artifact digest, окружение, настройки без секретов, команды, raw logs и время. Для организационного решения — версия документа и согласующие.
- NOT RUN, пустое поле или PR без требуемого испытания не являются PASS.
- После изменения RC требуется impact review и повторение затронутых gates. Даже GA version bump/rebuild получает собственный CI и smoke.
- Открытый B-пункт readiness означает no-go. У допустимых C-пунктов обязательны владелец, срок и контроль.
- Critical/high risk в поддерживаемом scope требует устранения либо утверждённого и проверенного ограничения support contract; запись в known issues сама по себе недостаточна.
- Пилот и release go/no-go подтверждают продукт, разработка, ИБ и эксплуатация. Новые задачи не объявляют старые обещания выполненными.

## Эпики и sub-issues

### [E1 / #404](https://github.com/onixus/bsdm-proxy/issues/404) — Контракт v1.0 и достоверность доказательств

**Выходной gate:** Scope, платформа, SLO и правила доказательств согласованы; исторический PASS не используется для допуска RC.

| Задача | Роль | Зависимости приёмки |
|---|---|---|
| [R01 / #405](https://github.com/onixus/bsdm-proxy/issues/405) — Зафиксировать поддерживаемый scope, платформу и сетевой контур | Архитектор + Product owner | Нет |
| [R02 / #406](https://github.com/onixus/bsdm-proxy/issues/406) — Отозвать нагрузочный PASS как основание допуска RC и сверить документацию | QA + технический писатель | Нет |
| [R03 / #407](https://github.com/onixus/bsdm-proxy/issues/407) — Утвердить SLO, RTO/RPO и формат release evidence | QA + эксплуатация + ИБ | [R01 / #405](https://github.com/onixus/bsdm-proxy/issues/405) |

#### [R01 / #405](https://github.com/onixus/bsdm-proxy/issues/405) — Зафиксировать поддерживаемый scope, платформу и сетевой контур

Выбрать одну эталонную Linux-платформу и Compose production; зафиксировать HTTP/CONNECT, selective MITM, ACL/categorization, L1, Basic, Admin, UDP DNS/RPZ и один путь аналитики. Предлагаемый первый путь — HTTP sink + SQLite; Kafka/ClickHouse, Helm и native требуют отдельной приёмки.

Критерии приёмки:

- [ ] Матрица функция → гарантия → ограничения → тест включает все поддерживаемые компоненты.
- [ ] Зафиксированы клиентские ОС/браузеры, pinning, Basic в защищённой сети, egress, UDP/443, внешние DNS/DoH/ECH.
- [ ] Beta/lab не входят в гарантии; AWG, AI-cache, WASM, multi-site и новые UI-фичи заморожены на время v1.0.

**Доказательство:** Утверждённый support matrix и ADR эталонной топологии; роли согласующих.

#### [R02 / #406](https://github.com/onixus/bsdm-proxy/issues/406) — Отозвать нагрузочный PASS как основание допуска RC и сверить документацию

Сохранить исторические отчёты, но добавить notice об ограничениях. Убрать ссылки на latest.md как доказательство принятого RC; различать реализацию, CI, опубликованный артефакт и эксплуатационную приёмку.

Критерии приёмки:

- [ ] 60 секунд не подтверждают >15 минут; общая latency не называется added latency или отдельным MITM p99.
- [ ] Roadmap, readiness, pilot go/no-go и release positioning не объявляют неподтверждённую приёмку выполненной.
- [ ] Исторические результаты сохранены с происхождением, без выдумывания новых измерений.

**Доказательство:** Diff документации и перечень проверенных утверждений; link/wiki validation.

#### [R03 / #407](https://github.com/onixus/bsdm-proxy/issues/407) — Утвердить SLO, RTO/RPO и формат release evidence

До испытаний определить throughput, concurrency, traffic mix, p95/p99 отдельно по путям и baseline, error budget, resource headroom, 24–72h soak, сроки хранения доказательств и правила переиспытаний.

Критерии приёмки:

- [ ] Пороги и способ расчёта утверждены до запуска, включая критерии насыщения и отказов.
- [ ] Evidence включает commit, artifact digest, ОС/железо, конфиг без секретов, raw logs и timestamps.
- [ ] RTO/RPO отдельно для proxy, конфигурации, CA и аналитики; пустое доказательство означает FAIL/NOT RUN.
- [ ] Изменение SHA после приёмки требует impact review и повторения затронутых тестов.

**Доказательство:** Версионированный acceptance protocol и шаблон evidence manifest.

### [E2 / #408](https://github.com/onixus/bsdm-proxy/issues/408) — Обязательные гарантии безопасности и совместимости v1.0

**Выходной gate:** Клиент не отключает обязательную инспекцию; управление защищено и персонально аудируется; все поддерживаемые пути прошли негативные проверки.

| Задача | Роль | Зависимости приёмки |
|---|---|---|
| [R04 / #409](https://github.com/onixus/bsdm-proxy/issues/409) — MITM: обязательная инспекция без клиентского bypass через breaker | Rust-разработчик + AppSec | [R01 / #405](https://github.com/onixus/bsdm-proxy/issues/405) |
| [R05 / #410](https://github.com/onixus/bsdm-proxy/issues/410) — CONNECT: ClientHello/SNI и политика IP/ECH | Rust-разработчик + AppSec | [R01 / #405](https://github.com/onixus/bsdm-proxy/issues/405) |
| [R06 / #411](https://github.com/onixus/bsdm-proxy/issues/411) — Production-политика портов и разрешённых адресов назначения | Rust-разработчик + AppSec | [R01 / #405](https://github.com/onixus/bsdm-proxy/issues/405) |
| [R07 / #412](https://github.com/onixus/bsdm-proxy/issues/412) — Персональные административные токены и минимальный RBAC | Backend + Admin Console + AppSec | [R01 / #405](https://github.com/onixus/bsdm-proxy/issues/405) |
| [R08 / #413](https://github.com/onixus/bsdm-proxy/issues/413) — Защищённый аудит административных изменений | Backend + эксплуатация | [R07 / #412](https://github.com/onixus/bsdm-proxy/issues/412), [R03 / #407](https://github.com/onixus/bsdm-proxy/issues/407) |
| [R09 / #414](https://github.com/onixus/bsdm-proxy/issues/414) — TLS управления и изоляция административного контура | DevSecOps + AppSec | [R01 / #405](https://github.com/onixus/bsdm-proxy/issues/405), [R07 / #412](https://github.com/onixus/bsdm-proxy/issues/412) |
| [R10 / #415](https://github.com/onixus/bsdm-proxy/issues/415) — HTTP-совместимость: Set-Cookie, streaming, cancellation и deadlines | Rust-разработчик + QA | [R01 / #405](https://github.com/onixus/bsdm-proxy/issues/405) |
| [R11 / #416](https://github.com/onixus/bsdm-proxy/issues/416) — Контракт доставки событий и приватность аналитики | Backend + DevSecOps + ИБ | [R01 / #405](https://github.com/onixus/bsdm-proxy/issues/405), [R03 / #407](https://github.com/onixus/bsdm-proxy/issues/407), [R08 / #413](https://github.com/onixus/bsdm-proxy/issues/413) |

#### [R04 / #409](https://github.com/onixus/bsdm-proxy/issues/409) — MITM: обязательная инспекция без клиентского bypass через breaker

Ввести inspect-required и явно разрешённый bypass; пересмотреть учёт TLS-alert/RST/EOF и административных pinning exceptions. Обязательная инспекция блокирует запрос при невозможности проверки.

Критерии приёмки:

- [ ] Три и более клиента, EOF/RST, unknown_ca и timeout не переводят inspect-required в blind CONNECT.
- [ ] Разрешённый bypass имеет владельца, срок, причину, метрику и аудит; истёкшее исключение не применяется.
- [ ] Есть unit и сетевые E2E, включая recovery/cooldown и конкурентные запросы.

**Доказательство:** Regression logs и независимое ревью модели отказов на точном SHA.

#### [R05 / #410](https://github.com/onixus/bsdm-proxy/issues/410) — CONNECT: ClientHello/SNI и политика IP/ECH

Добавить ограниченный по памяти/времени ClientHello peek; проверить соответствие authority/SNI; явно обработать IP literals, отсутствие SNI, fragmented ClientHello и недоступность имени из-за ECH.

Критерии приёмки:

- [ ] Матрица allow/deny для mismatch, IP, no-SNI/ECH утверждена и проверена.
- [ ] Неполный/повреждённый/медленный ClientHello не создаёт обхода и не зависает без лимита.
- [ ] Метрики и документация различают authority policy и фактический SNI-контроль.

**Доказательство:** Негативные E2E, corpus/parser tests и AppSec review.

#### [R06 / #411](https://github.com/onixus/bsdm-proxy/issues/411) — Production-политика портов и разрешённых адресов назначения

Установить безопасный CONNECT allowlist по умолчанию, разделить HTTP/CONNECT правила; документировать намеренно разрешённые внутренние назначения и проверить все пути соединения.

Критерии приёмки:

- [ ] IPv4/IPv6, mapped addresses, loopback, metadata, DNS resolution/rebinding проверены на фактическом connect path.
- [ ] CONNECT к неразрешённому порту блокируется без ручной настройки; разрешённые бизнес-исключения работают.
- [ ] Direct, upstream и поддерживаемые cache/miss пути не обходят destination policy.

**Доказательство:** Матрица адресов/портов и сетевые regression logs.

#### [R07 / #412](https://github.com/onixus/bsdm-proxy/issues/412) — Персональные административные токены и минимальный RBAC

Реализовать viewer/policy-admin/security-admin, индивидуальные principals, hash-at-rest, revoke/rotation и безопасную миграцию общего токена. UI не является единственным барьером.

Критерии приёмки:

- [ ] Все read/mutation API инвентаризированы; default deny проверен для каждой роли.
- [ ] Viewer не меняет конфигурацию; policy-admin не получает CA/секреты и не снижает security posture.
- [ ] Отзыв/ротация проверены, секреты не возвращаются API и не попадают в логи.
- [ ] Legacy/bootstrap путь не сохраняет скрытый обход RBAC.

**Доказательство:** Endpoint/role matrix, API negative tests, миграционный сценарий и AppSec sign-off.

#### [R08 / #413](https://github.com/onixus/bsdm-proxy/issues/413) — Защищённый аудит административных изменений

Писать actor/action/result/time/source и redacted diff для всех мутаций; добавить durable локальную запись и защищённую внешнюю копию с проверяемой политикой retention/целостности.

Критерии приёмки:

- [ ] Успешные и отклонённые изменения через все поддерживаемые API трассируются.
- [ ] Пароли, токены, ключ CA и чувствительные значения отсутствуют в audit diff.
- [ ] Рестарт, full disk и недоступность приёмника имеют явное протестированное поведение.
- [ ] Отсутствие/подмена/разрыв доставки обнаруживаются; append-only файл сам по себе не называется неизменяемым.

**Доказательство:** Audit samples, tamper/failure tests и политика доступа к внешней копии.

#### [R09 / #414](https://github.com/onixus/bsdm-proxy/issues/414) — TLS управления и изоляция административного контура

Включить один штатный способ TLS-входа: reverse proxy либо встроенный TLS. Ограничить прямой HTTP-порт и публичные служебные endpoints согласно support matrix.

Критерии приёмки:

- [ ] Из клиентской сети нельзя обойти TLS/RBAC обращением к backend порту.
- [ ] Сертификат, срок, renewal/rotation и отказ доверия проверены.
- [ ] Console/API работают через поддерживаемый TLS URL; health/metrics exposure явно ограничен.

**Доказательство:** Сетевые проверки из management/client сегментов и инструкция ротации.

#### [R10 / #415](https://github.com/onixus/bsdm-proxy/issues/415) — HTTP-совместимость: Set-Cookie, streaming, cancellation и deadlines

Исправить объединение нескольких Set-Cookie; проверить buffered/streaming/cache/revalidation и ограничение ожидания тела upstream.

Критерии приёмки:

- [ ] Несколько Set-Cookie доходят раздельно; login/session сценарии сохраняются.
- [ ] Большие и медленные ответы, отмена клиента, WebSocket/upgrade в заявленном scope не теряют корректность.
- [ ] Таймауты и лимиты не оставляют неограниченные задачи/буферы; cache privacy regressions зелёные.

**Доказательство:** Протокольные regression tests и трассы совместимости.

#### [R11 / #416](https://github.com/onixus/bsdm-proxy/issues/416) — Контракт доставки событий и приватность аналитики

Разделить best-effort analytics и security audit; определить допустимые потери, retry/spool для обязательного аудита, алерты queue/drop и минимизацию URL/identity данных. Защитить выбранный транспорт и разделить ingest/search credentials.

Критерии приёмки:

- [ ] Backpressure, outage и рестарт проверены; потери измеряются и не выдаются за полный журнал.
- [ ] Обязательный аудит выполняет принятый RPO при отказах; overflow policy явно проверена.
- [ ] URL query/секреты и идентификаторы обрабатываются согласно privacy-профилю.
- [ ] Для каждого заявленного транспорта есть проверка auth/TLS или утверждённой изолированной границы; Kafka/CH вне принятого scope не получают GA автоматически.

**Доказательство:** Failure-injection report, privacy samples, dashboard/alert tests.

### [E3 / #417](https://github.com/onixus/bsdm-proxy/issues/417) — Воспроизводимая RC-поставка и жизненный цикл установки

**Выходной gate:** Опубликованный RC установлен, обновлён, откатан и восстановлен на чистой эталонной системе с проверкой происхождения.

| Задача | Роль | Зависимости приёмки |
|---|---|---|
| [R12 / #418](https://github.com/onixus/bsdm-proxy/issues/418) — Публикация RC: exact SHA, digest, SBOM и подписи | DevSecOps | [R01 / #405](https://github.com/onixus/bsdm-proxy/issues/405) |
| [R13 / #419](https://github.com/onixus/bsdm-proxy/issues/419) — Установка RC на чистую эталонную систему | DevSecOps + QA | [R01 / #405](https://github.com/onixus/bsdm-proxy/issues/405), [R12 / #418](https://github.com/onixus/bsdm-proxy/issues/418) |
| [R14 / #420](https://github.com/onixus/bsdm-proxy/issues/420) — Upgrade, rollback, backup/restore и CA rotation | DevSecOps + QA | [R03 / #407](https://github.com/onixus/bsdm-proxy/issues/407), [R13 / #419](https://github.com/onixus/bsdm-proxy/issues/419) |
| [R15 / #421](https://github.com/onixus/bsdm-proxy/issues/421) — Build identity, diagnostics и политика поддержки | Backend + DevSecOps + Product owner | [R01 / #405](https://github.com/onixus/bsdm-proxy/issues/405), [R12 / #418](https://github.com/onixus/bsdm-proxy/issues/418) |

#### [R12 / #418](https://github.com/onixus/bsdm-proxy/issues/418) — Публикация RC: exact SHA, digest, SBOM и подписи

Использовать существующие pipeline для реального prerelease/tag и только поддерживаемых артефактов; не менять и не перетегировать опубликованный RC при исправлениях.

Критерии приёмки:

- [ ] Required CI и dependency/image gates относятся к тому же SHA; default/optional графы различаются.
- [ ] Опубликованы digest, SBOM, provenance и подписи; проверены чистым потребителем.
- [ ] Изменения выпускаются новым RC; задокументирован policy для advisory исключений.

**Доказательство:** Release URL, CI URLs, checksums и verify/verify-attestation logs.

#### [R13 / #419](https://github.com/onixus/bsdm-proxy/issues/419) — Установка RC на чистую эталонную систему

Установить скачанные артефакты без сборки checkout; проверить secrets, CA permissions, persistent data, non-root/read-only и health.

Критерии приёмки:

- [ ] Другой инженер выполняет инструкцию на чистой системе.
- [ ] Без обязательных секретов/CA fail-closed; с валидной конфигурацией проходят реальные запросы.
- [ ] Рестарт сохраняет конфигурацию/данные; lab-интерфейсы закрыты.

**Доказательство:** Install transcript, redacted config, artifact digest и smoke report.

#### [R14 / #420](https://github.com/onixus/bsdm-proxy/issues/420) — Upgrade, rollback, backup/restore и CA rotation

Определить поддерживаемую предыдущую версию и миграцию; проверить совместимость данных, encrypted backup, восстановление на чистой системе и ротацию/откат CA.

Критерии приёмки:

- [ ] Upgrade и rollback выполняются по runbook без потери данных сверх RPO.
- [ ] Restore проверяет не только counts, но и доступ/политику/работоспособность proxy.
- [ ] Измерены RTO/RPO; CA rotation и emergency recovery проверены на клиентах.

**Доказательство:** Таймлайны учений, manifests/checksums backup и протокол проверки клиентов.

#### [R15 / #421](https://github.com/onixus/bsdm-proxy/issues/421) — Build identity, diagnostics и политика поддержки

Вывести version/build SHA в API/console/diagnostics; сформировать безопасный support bundle; определить поддерживаемые версии и процесс исправления уязвимостей.

Критерии приёмки:

- [ ] Runtime identity сопоставляется с release manifest.
- [ ] Bundle не содержит токенов, приватных ключей и ненужных персональных данных.
- [ ] Опубликованы срок поддержки, каналы эскалации и обязательства с назначенными владельцами, без неподтверждённых SLA.

**Доказательство:** Пример sanitised bundle, identity test и support policy.

### [E4 / #422](https://github.com/onixus/bsdm-proxy/issues/422) — Независимая техническая приёмка фиксированного RC

**Выходной gate:** Все обязательные функциональные, нагрузочные, отказные и security проверки пройдены на одной принятой сборке.

| Задача | Роль | Зависимости приёмки |
|---|---|---|
| [R16 / #423](https://github.com/onixus/bsdm-proxy/issues/423) — Исправить нагрузочный harness и машинные acceptance gates | QA/performance engineer | [R02 / #406](https://github.com/onixus/bsdm-proxy/issues/406), [R03 / #407](https://github.com/onixus/bsdm-proxy/issues/407) |
| [R17 / #424](https://github.com/onixus/bsdm-proxy/issues/424) — Матрица функциональной и клиентской совместимости | QA | [R04 / #409](https://github.com/onixus/bsdm-proxy/issues/409), [R05 / #410](https://github.com/onixus/bsdm-proxy/issues/410), [R06 / #411](https://github.com/onixus/bsdm-proxy/issues/411), [R07 / #412](https://github.com/onixus/bsdm-proxy/issues/412), [R09 / #414](https://github.com/onixus/bsdm-proxy/issues/414), [R10 / #415](https://github.com/onixus/bsdm-proxy/issues/415), [R13 / #419](https://github.com/onixus/bsdm-proxy/issues/419) |
| [R18 / #425](https://github.com/onixus/bsdm-proxy/issues/425) — Нагрузка до насыщения и soak 24–72 часа | QA/performance engineer | [R16 / #423](https://github.com/onixus/bsdm-proxy/issues/423), [R17 / #424](https://github.com/onixus/bsdm-proxy/issues/424), [R11 / #416](https://github.com/onixus/bsdm-proxy/issues/416), [R14 / #420](https://github.com/onixus/bsdm-proxy/issues/420) |
| [R19 / #426](https://github.com/onixus/bsdm-proxy/issues/426) — Failure injection и восстановление в пределах RTO/RPO | QA + DevSecOps | [R11 / #416](https://github.com/onixus/bsdm-proxy/issues/416), [R14 / #420](https://github.com/onixus/bsdm-proxy/issues/420), [R17 / #424](https://github.com/onixus/bsdm-proxy/issues/424) |
| [R20 / #427](https://github.com/onixus/bsdm-proxy/issues/427) — Независимая security-приёмка поддерживаемого scope | Независимый AppSec reviewer | [R04 / #409](https://github.com/onixus/bsdm-proxy/issues/409), [R05 / #410](https://github.com/onixus/bsdm-proxy/issues/410), [R06 / #411](https://github.com/onixus/bsdm-proxy/issues/411), [R07 / #412](https://github.com/onixus/bsdm-proxy/issues/412), [R08 / #413](https://github.com/onixus/bsdm-proxy/issues/413), [R09 / #414](https://github.com/onixus/bsdm-proxy/issues/414), [R10 / #415](https://github.com/onixus/bsdm-proxy/issues/415), [R11 / #416](https://github.com/onixus/bsdm-proxy/issues/416), [R13 / #419](https://github.com/onixus/bsdm-proxy/issues/419) |

#### [R16 / #423](https://github.com/onixus/bsdm-proxy/issues/423) — Исправить нагрузочный harness и машинные acceptance gates

Убрать protocol fallback, подставную DNS latency и ложный успех dig; проверять фактическую политику, раздельные distributions, baseline и итоговый verdict.

Критерии приёмки:

- [ ] Ошибка SNI/MITM/DNS не заменяется другим протоколом и отражается в exit code.
- [ ] Проверяется DNS response semantics и ожидаемое allow/block, а не только успех процесса.
- [ ] Raw samples и manifest сохраняются; HIT/MISS/CONNECT/MITM/DNS распределения раздельны.
- [ ] Гейт проверяет все утверждённые пороги; тесты harness ловят искусственно внесённый FAIL.

**Доказательство:** Harness regression tests и демонстрационные PASS/FAIL отчёты, не production acceptance.

#### [R17 / #424](https://github.com/onixus/bsdm-proxy/issues/424) — Матрица функциональной и клиентской совместимости

На опубликованном RC проверить auth/ACL/cache/MITM/DNS/Admin/analytics и согласованные ОС, браузеры, обновления, Git/package managers, WebSocket и pinning apps.

Критерии приёмки:

- [ ] Каждый сценарий привязан к ожидаемому результату и артефакту.
- [ ] Проверены allow/deny, авторизованный/неавторизованный клиент и приватность кэша.
- [ ] Business exceptions имеют владельца/срок; NOT RUN не считается PASS.

**Доказательство:** Compatibility matrix с логами и перечнем ограничений.

#### [R18 / #425](https://github.com/onixus/bsdm-proxy/issues/425) — Нагрузка до насыщения и soak 24–72 часа

Выполнить production auth/ACL/inspection traffic mix, рост нагрузки до предела и согласованный soak; сохранять CPU/RAM/disk/latency/errors/event drops.

Критерии приёмки:

- [ ] Пороги R03 соблюдены для поддерживаемой ёмкости; saturation boundary опубликована.
- [ ] Нет неограниченного роста памяти/диска/очередей за soak.
- [ ] Полная и добавленная latency считаются отдельно; результаты связаны с digest RC.

**Доказательство:** Raw samples, графики, конфигурация стенда и воспроизводимый capacity report.

#### [R19 / #426](https://github.com/onixus/bsdm-proxy/issues/426) — Failure injection и восстановление в пределах RTO/RPO

Испытать upstream/DNS/analytics outage, disk full, resource pressure, SIGKILL/restart и потерю узла. Для single-node честно измерить outage, не объявлять HA.

Критерии приёмки:

- [ ] Security posture не ослабляется незаметно при отказах.
- [ ] Потери/восстановление данных и доступности соответствуют R03.
- [ ] Срабатывают алерты, runbook позволяет восстановить сервис другому инженеру.

**Доказательство:** Fault matrix с таймлайнами, алертами и reconciliation данных.

#### [R20 / #427](https://github.com/onixus/bsdm-proxy/issues/427) — Независимая security-приёмка поддерживаемого scope

Проверить trust boundaries, parser/proxy bypass, cache isolation, CA handling, RBAC, audit, deployment и supply chain. Проверять точный RC; исправления ретестировать независимо.

Критерии приёмки:

- [ ] Есть threat model и scope, отличающий GA от beta/lab.
- [ ] Нет открытых critical/high в поддерживаемом scope без утверждённого проверенного ограничения.
- [ ] Каждая finding имеет воспроизведение, fix/retest или обоснованный disposition.
- [ ] Отчёт различает static review, CI и runtime penetration tests.

**Доказательство:** Независимый отчёт, immutable evidence и re-test результатов.

### [E5 / #428](https://github.com/onixus/bsdm-proxy/issues/428) — Ограниченный пилот и эксплуатационный допуск

**Выходной gate:** Пилот выдержал рабочие показатели; команда самостоятельно эксплуатирует и восстанавливает сервис; блокеров нет.

| Задача | Роль | Зависимости приёмки |
|---|---|---|
| [R21 / #429](https://github.com/onixus/bsdm-proxy/issues/429) — Подготовить эксплуатацию до подключения пользователей | Эксплуатация + SOC | [R03 / #407](https://github.com/onixus/bsdm-proxy/issues/407), [R14 / #420](https://github.com/onixus/bsdm-proxy/issues/420), [R15 / #421](https://github.com/onixus/bsdm-proxy/issues/421) |
| [R22 / #430](https://github.com/onixus/bsdm-proxy/issues/430) — Провести поэтапный пилот ИТ/ИБ → подразделение → целевой профиль | Владелец сервиса + QA | [R18 / #425](https://github.com/onixus/bsdm-proxy/issues/425), [R19 / #426](https://github.com/onixus/bsdm-proxy/issues/426), [R20 / #427](https://github.com/onixus/bsdm-proxy/issues/427), [R21 / #429](https://github.com/onixus/bsdm-proxy/issues/429) |
| [R23 / #431](https://github.com/onixus/bsdm-proxy/issues/431) — Подписать эксплуатационный go/no-go | Владелец сервиса + ИБ + DevOps | [R22 / #430](https://github.com/onixus/bsdm-proxy/issues/430) |

#### [R21 / #429](https://github.com/onixus/bsdm-proxy/issues/429) — Подготовить эксплуатацию до подключения пользователей

Назначить service owner/on-call/escalation, настроить мониторинг доступности/latency/CA/disk/event loss, backups, log access/retention и пользовательские уведомления.

Критерии приёмки:

- [ ] Алерты проверены тестовым событием и доставлены назначенному дежурному.
- [ ] Доступы, исключения MITM и хранение данных согласованы с ответственными.
- [ ] Rollback, CA compromise и restore tabletop пройдены; backup восстановлен.

**Доказательство:** Runbook exercise, escalation roster и заполненный pre-pilot checklist.

#### [R22 / #430](https://github.com/onixus/bsdm-proxy/issues/430) — Провести поэтапный пилот ИТ/ИБ → подразделение → целевой профиль

Расширять аудиторию после промежуточного go/no-go; фиксировать поломки приложений, FP, ручные вмешательства, инциденты и время восстановления.

Критерии приёмки:

- [ ] Для каждой волны есть scope, сроки наблюдения, критерии остановки и откат.
- [ ] Рабочие SLO соблюдены; нет нерешённых release blockers.
- [ ] Исключения не скрывают неработающие обязательные защиты; каждое имеет срок/владельца.

**Доказательство:** Обезличенный pilot report, incident log и решения по волнам.

#### [R23 / #431](https://github.com/onixus/bsdm-proxy/issues/431) — Подписать эксплуатационный go/no-go

Заполнить readiness checklist с доказательствами для принятой сборки и площадки; принять остаточные риски в пределах support contract.

Критерии приёмки:

- [ ] Все B-пункты имеют evidence; открытый B означает no-go.
- [ ] У C-пунктов есть владелец, срок и контроль; нет blank-as-pass.
- [ ] Решение подписано продуктом, ИБ, разработкой и эксплуатацией; версия/digest указаны.

**Доказательство:** Подписанное решение и evidence index без секретов.

### [E6 / #432](https://github.com/onixus/bsdm-proxy/issues/432) — Релиз v1.0 и поддерживаемая коммерческая поставка

**Выходной gate:** GA опубликован из принятого исходного состояния и продаётся только в границах проверенного support contract.

| Задача | Роль | Зависимости приёмки |
|---|---|---|
| [R24 / #433](https://github.com/onixus/bsdm-proxy/issues/433) — Собрать финальный release dossier и подтвердить SHA/artifact boundary | Release manager + QA | [R23 / #431](https://github.com/onixus/bsdm-proxy/issues/431) |
| [R25 / #434](https://github.com/onixus/bsdm-proxy/issues/434) — Опубликовать и проверить GA-поставку | DevSecOps + Release manager | [R24 / #433](https://github.com/onixus/bsdm-proxy/issues/433) |
| [R26 / #435](https://github.com/onixus/bsdm-proxy/issues/435) — Запустить поддержку и ограниченное коммерческое предложение | Product owner + support lead | [R15 / #421](https://github.com/onixus/bsdm-proxy/issues/421), [R23 / #431](https://github.com/onixus/bsdm-proxy/issues/431), [R25 / #434](https://github.com/onixus/bsdm-proxy/issues/434) |

#### [R24 / #433](https://github.com/onixus/bsdm-proxy/issues/433) — Собрать финальный release dossier и подтвердить SHA/artifact boundary

Свести все evidence, ограничения, support matrix и sign-offs; проверить изменения после принятого RC.

Критерии приёмки:

- [ ] Каждое доказательство связано с SHA/digest; устаревшие прогоны помечены.
- [ ] Version bump/rebuild GA не считается идентичным RC: есть impact review, повторный CI и smoke опубликованного GA.
- [ ] Любое функциональное изменение возвращает затронутые gates на re-test.

**Доказательство:** Release manifest, evidence index и решение о допустимости promotion.

#### [R25 / #434](https://github.com/onixus/bsdm-proxy/issues/434) — Опубликовать и проверить GA-поставку

Выпустить неизменяемый GA tag/release, подписи/SBOM/provenance, инструкции установки и миграции; проверить consumer download/install.

Критерии приёмки:

- [ ] Тег, CI, образы и runtime version согласованы; подписи проверены извне pipeline.
- [ ] Потребитель устанавливает поддерживаемую конфигурацию и выполняет smoke.
- [ ] Release notes явно перечисляют принятые гарантии и ограничения, без GA для beta/lab.

**Доказательство:** GA URLs, verify logs и clean-install smoke.

#### [R26 / #435](https://github.com/onixus/bsdm-proxy/issues/435) — Запустить поддержку и ограниченное коммерческое предложение

Предлагать внедрение с сопровождением в принятом scope; определить обязанности заказчика, поддержку, обновления и эскалации.

Критерии приёмки:

- [ ] Предложение не обещает AD/HA/DLP или универсальную замену enterprise SWG до отдельной приёмки.
- [ ] Стоимость сопровождения и фактический объём ручных операций учтены.
- [ ] Назначены владельцы security response, release updates и customer incidents.

**Доказательство:** Service description, support process и согласованные обязательства.

### [E7 / #436](https://github.com/onixus/bsdm-proxy/issues/436) — Корпоративный SWG после v1.0: identity, HA и эффективность защиты

**Выходной gate:** Каждая enterprise-возможность имеет отдельную приёмку; конкурентоспособность подтверждается реальными пилотами и TCO, а не перечнем функций.

| Задача | Роль | Зависимости приёмки |
|---|---|---|
| [R27 / #437](https://github.com/onixus/bsdm-proxy/issues/437) — Принять LDAP/Kerberos/AD на реальном доменном стенде | Identity-разработчик + QA + AppSec | [R25 / #434](https://github.com/onixus/bsdm-proxy/issues/434) |
| [R28 / #438](https://github.com/onixus/bsdm-proxy/issues/438) — Принять HA одной площадки и согласованность политики | Архитектор + DevSecOps + QA | [R25 / #434](https://github.com/onixus/bsdm-proxy/issues/434) |
| [R29 / #439](https://github.com/onixus/bsdm-proxy/issues/439) — Принять один ICAP/антивирусный контур проверки контента | Rust-разработчик + AppSec + QA | [R25 / #434](https://github.com/onixus/bsdm-proxy/issues/434) |
| [R30 / #440](https://github.com/onixus/bsdm-proxy/issues/440) — Принять TI enforcement: качество, freshness и rollback | Threat-intel разработчик + SOC | [R25 / #434](https://github.com/onixus/bsdm-proxy/issues/434) |
| [R31 / #441](https://github.com/onixus/bsdm-proxy/issues/441) — DLP: решение по спросу и ограниченный проверяемый scope | Product owner + DPO/ИБ + разработка | [R25 / #434](https://github.com/onixus/bsdm-proxy/issues/434) |
| [R32 / #442](https://github.com/onixus/bsdm-proxy/issues/442) — Проверить конкурентоспособность: клиентские пилоты и TCO | Product owner + эксплуатация | [R26 / #435](https://github.com/onixus/bsdm-proxy/issues/435), [R27 / #437](https://github.com/onixus/bsdm-proxy/issues/437), [R28 / #438](https://github.com/onixus/bsdm-proxy/issues/438), [R29 / #439](https://github.com/onixus/bsdm-proxy/issues/439), [R30 / #440](https://github.com/onixus/bsdm-proxy/issues/440) |

#### [R27 / #437](https://github.com/onixus/bsdm-proxy/issues/437) — Принять LDAP/Kerberos/AD на реальном доменном стенде

Проверить SSO, группы, revoke, credential expiry, NAT/shared workstations и недоступность AD; закрыть optional dependency/license blockers применимой сборки.

Критерии приёмки:

- [ ] Аутентификация не переносится между пользователями по общему IP.
- [ ] Реальные Windows/AD сценарии, смена групп и отзыв доступа покрыты.
- [ ] Feature-specific supply-chain gate и security acceptance зелёные.

**Доказательство:** Доменный integration report, точная feature-сборка и dependency disposition.

#### [R28 / #438](https://github.com/onixus/bsdm-proxy/issues/438) — Принять HA одной площадки и согласованность политики

Реализовать/зафиксировать policy distribution, readiness, поведение сессий/cache/breaker и rolling upgrade при отказе узла.

Критерии приёмки:

- [ ] RTO/RPO и допустимые разрывы сессий утверждены до проверки.
- [ ] Node loss, network partition, stale policy и rolling update испытаны под нагрузкой.
- [ ] Балансировщик не выдаётся за доказательство общей HA-семантики.

**Доказательство:** HA architecture ADR и fault/load reports.

#### [R29 / #439](https://github.com/onixus/bsdm-proxy/issues/439) — Принять один ICAP/антивирусный контур проверки контента

Определить поддерживаемый scanner и проверить REQMOD/RESPMOD, buffered/streaming, архивы, размеры, timeouts и fail policy.

Критерии приёмки:

- [ ] Контент не доставляется в обход обязательного сканирования через streaming/cache/error path.
- [ ] Есть контролируемый threat/benign corpus, метрики FP/FN и performance.
- [ ] Отказ/перегрузка сканера и ограничение архивов проверены.

**Доказательство:** Content-inspection acceptance и интеграционный контракт scanner.

#### [R30 / #440](https://github.com/onixus/bsdm-proxy/issues/440) — Принять TI enforcement: качество, freshness и rollback

Проверить corpus качества, feed freshness, недоступность источников, allowlist, expiry и rollback на реальном request path.

Критерии приёмки:

- [ ] До теста зафиксированы FP/FN thresholds и источник truth set.
- [ ] Stale/invalid feed, collector stop и rollback имеют проверенное поведение.
- [ ] Allowlist и смена режима не создают скрытой потери защиты.

**Доказательство:** TI quality report и enforcement failure drills.

#### [R31 / #441](https://github.com/onixus/bsdm-proxy/issues/441) — DLP: решение по спросу и ограниченный проверяемый scope

Выбрать конкретные типы данных/каналы по клиентскому спросу; сначала go/no-go продукта, затем отдельный implementation backlog. Не повышать зрелость существующего signature scanner.

Критерии приёмки:

- [ ] Есть подтверждённые use cases, privacy constraints, corpus и целевые FP/FN.
- [ ] Принято явное решение implement/defer/remove с владельцем.
- [ ] При implement созданы отдельные delivery/acceptance задачи; discovery не считается DLP GA.

**Доказательство:** Product decision и измеримый DLP contract.

#### [R32 / #442](https://github.com/onixus/bsdm-proxy/issues/442) — Проверить конкурентоспособность: клиентские пилоты и TCO

Сравнить минимум два независимых клиентских сценария с выбранными альтернативами при одинаковых гарантиях; учесть лицензии, инфраструктуру, внедрение, поддержку и простои.

Критерии приёмки:

- [ ] Сравнение привязано к конфигурациям, security scope и нагрузке, а не benchmark-only fast path.
- [ ] Есть подтверждённые боли/ценность, трудозатраты и ограничения.
- [ ] Решение о позиционировании enterprise SWG опирается на принятые функции; DLP не заявляется без отдельной приёмки.

**Доказательство:** Обезличенные customer reports, TCO model и решение о коммерческом позиционировании.

## Связанные документы

- [Roadmap](roadmap.md)
- [Фактическая зрелость функций](project-status.md)
- [Production readiness checklist](ops-and-dev/production-readiness-checklist.md)
- [Pilot go/no-go](ops-and-dev/pilot-go-no-go-template.md)

GitHub issues хранят актуальное состояние выполнения; этот документ фиксирует согласованный scope, зависимости и критерии. При изменении scope обновляются оба представления.
