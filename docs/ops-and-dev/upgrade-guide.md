# Upgrade guide: 0.9.x → 1.0

Порядок обновления пилотных и pre-GA установок (`0.9.0`–`0.9.15`) до **v1.0.0**.
Полный список изменений — в [CHANGELOG.md](../../CHANGELOG.md) (разделы `[1.0.0-rc.1]` и
все `0.9.x` новее вашей версии); этот документ собирает только то, что требует
действий оператора.

**Связанные документы:** [Production deployment](../getting-started/production-deployment.md) ·
[Production readiness checklist](production-readiness-checklist.md) ·
[Runbook § 7: откат релиза](runbook.md#7-откат-релиза) ·
[Backup & restore](backup-restore.md)

---

## 1. Что меняется концептуально

| Было (0.9.x, пилот) | Стало (1.0 GA) |
|---|---|
| `docker-compose.yml` + `deploy/compose/docker-compose.pilot.yml` | Самостоятельный prod-профиль [`deploy/compose/docker-compose.prod.yml`](../../deploy/compose/docker-compose.prod.yml) + `prod.env` + Compose `secrets:` |
| `charts/bsdm/values-prod.yaml` как «prod» | [`values-production.yaml`](../../charts/bsdm/values-production.yaml) — hardened GA-оверлей (подключается последним); `values-prod.yaml` остаётся sizing-профилем |
| Сборка `up --build` из checkout | Только опубликованные подписанные образы `ghcr.io/onixus/bsdm-*:1.0.0` (cosign + SBOM) |
| Токены в env / shell | Токены в secret store / файлах секретов |
| Зрелость «основной / beta» | GA-скоуп v1.0 ([project-status](../project-status.md#ga-скоуп-v10)); beta и lab вне гарантий релиза |

GA-скоуп совпадает с Day-1 пилота: если пилот шёл по
[pilot-deployment.md](../getting-started/pilot-deployment.md) без experimental
модулей, миграция сводится к смене способа поставки и проверке пунктов ниже.

---

## 2. Изменения, требующие действий

Отметьте строки, относящиеся к версии, с которой вы обновляетесь.

| С версии | Изменение | Действие |
|---|---|---|
| < 0.9.15 | Hop-by-hop заголовки (`Proxy-Authorization`, `Proxy-Connection`, `TE`, `Transfer-Encoding`, …) больше **не пересылаются** upstream и cache peers (RFC 9110 §7.6.1) | Если какой-то upstream полагался на получение `Proxy-Authorization` — перенастроить его на `Authorization`. Для остальных это исправление утечки учётных данных |
| < 0.9.15 | `EBPF_XDP_ENABLED=false` в поставляемом `bsdm-proxy.env`; eBPF требует явного arming (`EBPF_XDP_ALLOW_RUNTIME_ENABLE`), иначе `PUT /api/ebpf/config` → `403` | В prod ничего не делать (eBPF вне GA). Проверить `bsdm_proxy_ebpf_armed == 0` |
| < 0.9.15 | Reverse-proxy OIDC: проверка подписи `id_token`, endpoints из discovery, `OIDC_PROVIDERS` | Модуль frozen и вне GA; при lab-использовании — см. [authentication.md](../features/authentication.md) |
| < 0.9.14 | Basic auth: хеши Argon2id с миграцией при входе; файл пользователей проверяется на `0600` | Выставить `chmod 600` и владельца-сервис на `BASIC_AUTH_USERS_FILE`. Legacy SHA-256 хеши перезаписываются в Argon2id при успешном входе (`BASIC_AUTH_REHASH_ON_LOGIN`, по умолчанию on) — для этого файл должен быть записываемым; read-only файл вход не ломает, но миграция не сохранится. Лучше заранее перевыпустить хеши `scripts/gen-basic-auth-user.sh`. Прогресс — `bsdm_proxy_auth_password_rehashes_total` |
| < 0.9.14 | Proxy проверяет права `ca.key` при старте (в 1.0 production — отказ старта) | `chmod 0400 ca.key` (или `0440` с выделенной группой), владелец — сервисная учётка |
| < 0.9.14 | Ключи MITM circuit breaker — точные имена хостов; трекер ограничен `MITM_CIRCUIT_BREAKER_MAX_DOMAINS`; кэш сертификатов — `MITM_CERT_CACHE_MAX_ENTRIES` | Ничего, если дефолты устраивают. Wildcard-трипы прежних версий исчезают после рестарта |
| < 0.9.14 | SSRF-проверка назначения применяется и к MITM `CONNECT` | Внутренние назначения, ранее доступные через MITM, будут отклоняться — проверить `bsdm_proxy_security_ssrf_blocked_total` после обновления |
| < 0.9.13 | Порт 1488 полностью удалён, везде `3128` | Проверить PAC/GPO/firewall на остатки `1488`–`1490` |
| ранние 0.9.x | CA ищется в `MITM_CA_DIR` (по умолчанию `/etc/bsdm-proxy/certs`); `/certs` и `./certs` — legacy fallback с warning. **В 1.0 в production fallback удалён** (см. §2.1) | Явно задать `MITM_CA_DIR` или перенести CA до обновления |
| 0.9.x Compose | Базовый `docker-compose.yml` fail-closed: `AUTH_ENABLED=true`, обязательны `CONTROL_API_TOKEN`, `SEARCH_API_TOKEN`, `GRAFANA_ADMIN_PASSWORD`, `BASIC_AUTH_USERS_HOST` | Для prod перейти на prod-профиль (§3.1) |
| 0.9.x native | Пакет — статические musl-бинарники + Admin Console (`ADMIN_CONSOLE_DIR`) | Переустановить через `install-release.sh` (§3.3); старый glibc-пакет не переносить |
| любая | ClickHouse: новые колонки (`decision_source`, `bypass_reason`, `acl_rule_id`, `acl_reason`, `threat_shadow_match`) | Применяются автоматически cache-indexer'ом (`ADD COLUMN IF NOT EXISTS`) при старте; ручных миграций нет. TTL не трогается — проверить retention |
| — | Прочие изменения 1.0.0 (CI-гейты, prod-профили, security-фиксы) | Прочитать раздел `[1.0.0-rc.1]` в [CHANGELOG.md](../../CHANGELOG.md), особенно `Security` и `Changed` |

### 2.1 Поведенческие изменения v1.0.0

Security-фиксы релиз-кандидата меняют наблюдаемое поведение proxy. Проверьте
каждый пункт на staging до обновления prod.

| Изменение | Что увидят пользователи / оператор | Действие |
|---|---|---|
| Ответы на запросы с `Cookie` или `Authorization`, а также ответы с `Set-Cookie` и `Vary` (кроме `Accept-Encoding`) **больше не кэшируются**; на HIT `Set-Cookie` вырезается | Падение cache hit ratio на авторизованном контенте (intranet, SaaS) — ожидаемо: раньше такие ответы могли отдаваться другим пользователям | Пересмотреть ожидания по hit ratio и сайзинг upstream-канала; сравнить `bsdm_proxy_cache_bypasses_total` до/после |
| `Host` ≠ authority URI → **`400`** | Клиенты/скрипты с несогласованным `Host` (domain fronting, кривые SDK) получают 400 | Найти в логах источники 400 после обновления; исправлять клиента, а не proxy |
| Тело запроса больше `MAX_REQUEST_BODY_BYTES` (по умолчанию 64 MiB) → **`413`** | Крупные аплоады через proxy отклоняются | Если бизнесу нужны большие аплоады — поднять `MAX_REQUEST_BODY_BYTES` осознанно (тело буферизуется в RAM) или вывести такие назначения в прямой доступ |
| `BLOCK_LOOPBACK_FORWARDING=true` по умолчанию в `DEPLOYMENT_PROFILE=production` | Запросы через proxy к `127.0.0.1`/loopback узла → `403` | Ничего, если loopback-назначения не использовались намеренно |
| `PERF_FAST_CACHE_HIT` / `BSM_PERF_MODE` **игнорируются** в production | Бенчмарки с fast-hit на prod-профиле покажут меньший RPS — это честная цифра с проверкой политики | Убрать переменные из prod-конфигурации |
| `AUTH_ENABLED=true` с Basic без `BASIC_AUTH_USERS_FILE` в production → **отказ старта** | Proxy не поднимается, в логе — недостающая переменная | Смонтировать собственный файл пользователей (`scripts/gen-basic-auth-user.sh`), `0600` |
| **Open-proxy guard:** `AUTH_ENABLED=false` в production без ACL default-deny + allow-правила `IpRange` по клиентским подсетям → **отказ старта** | Анонимный пилот без IP-правил не поднимется | Включить auth, или задать `ACL_DEFAULT_ACTION=deny` + allow `IpRange` с клиентскими подсетями, или осознанно задать `ALLOW_ANONYMOUS_PROXY=true` |
| **CA fail-closed в production:** нет `ca.crt`, ключ не соответствует сертификату, CA истёк или права `ca.key` шире `0440` → **отказ старта**; CA читается только из `MITM_CA_DIR`, без `/certs` и `./certs` | Proxy не поднимается, лог называет причину | `./scripts/rotate-ca.sh verify`; `chmod 0400 ca.key` (или `0440` с выделенной группой); задать `MITM_CA_DIR`. Новая метрика `bsdm_proxy_mitm_ca_not_after_timestamp_seconds` |
| **MITM circuit breaker:** trip только при сбоях от ≥ 3 различных IP клиентов (`MITM_CIRCUIT_BREAKER_MIN_CLIENTS=3`), авто-восстановление через 900 с (`MITM_CIRCUIT_BREAKER_COOLDOWN_SECS`; раньше `0` = до ручного сброса); новая метрика `bsdm_proxy_mitm_circuit_breaker_trips_total` | Домены возвращаются в MITM сами через 15 мин; одиночный клиент больше не выводит домен из инспекции | Добавить алерт на `trips_total`; если нужен прежний режим «до ручного сброса» — явно `MITM_CIRCUIT_BREAKER_COOLDOWN_SECS=0` |
| **Lab-маршруты → `404`** в production (agent, AmneziaWG, cluster, WASM и др.), пока не заданы `AGENT_API_ENABLED` / `AWG_API_ENABLED` / `LAB_API_ENABLED` | Admin Console: разделы Devices/AmneziaWG пустые или с ошибкой | Ничего для GA-скоупа; lab-стенды — явный флаг и не production |
| **`config/apply`** не меняет `CONTROL_API_TOKEN`, `ACL_API_TOKEN`, `SEARCH_API_TOKEN`, `ACL_RULES_PATH`, `UPSTREAM_CA_CERT`, `WASM_*`, `CONFIG_*` (→ `400`); restart в production = graceful shutdown, перезапуск делает супервизор | Settings → Apply с такими ключами отклоняется; без супервизора процесс после Apply не вернётся | Менять эти ключи через конфигурацию развёртывания; убедиться, что есть `Restart=` / `restart:` / Deployment |
| `config/apply` отклоняет значения с `\`, `"`, `'` или пробелами по краям (защита от инъекции строк в systemd `EnvironmentFile`) | Пароль/секрет с такими символами не сохраняется через Admin Console | Задавать такие значения правкой `/etc/bsdm-proxy/bsdm-proxy.env` на хосте (или в secret store) |
| **Search через control plane** использует `SEARCH_UPSTREAM_TOKEN` (fallback `SEARCH_API_TOKEN`) и больше не пересылает токен вызывающего | Если `SEARCH_API_TOKEN` indexer ≠ токену proxy, Search в Admin Console вернёт 401 | Задать `SEARCH_UPSTREAM_TOKEN` = `SEARCH_API_TOKEN` cache-indexer; держать `CONTROL_API_TOKEN` отличным от search-токена |
| **RKN sync** в production не использует встроенный сторонний fallback — только явный `RKN_FALLBACK_URL` | При недоступности основного URL снапшот не обновится | Задать собственное зеркало в `RKN_FALLBACK_URL` или оставить RKN выключенным (beta) |
| Новые лимиты и таймауты: `UPSTREAM_CONNECT_TIMEOUT_MS=10000`, `UPSTREAM_RESPONSE_TIMEOUT_MS=60000`, `BASIC_AUTH_MAX_CONCURRENT_VERIFICATIONS` (по CPU), dns-sinkhole `DNS_SINKHOLE_MAX_INFLIGHT=1024`, `DNS_SINKHOLE_MAX_TCP_CONNECTIONS=512`, `DNS_SINKHOLE_TLS_HANDSHAKE_TIMEOUT_MS=5000`, `DNS_SINKHOLE_TCP_IDLE_TIMEOUT_MS=10000`; cache-indexer `METRICS_BIND`, `INGEST_API_TOKEN` (warn при совпадении с search-токеном) | Медленные upstream (> 60 с до заголовков) → ошибка; при флуде паролей — «overloaded» | Скорректировать под площадку; см. [configuration.md](configuration.md) |
| SSRF-проверка выполняется по **разрешённым** адресам (IPv4-mapped IPv6, имена с A-записью на IMDS/loopback) | Назначения, резолвящиеся в metadata/loopback, отклоняются и для `GET`, и для `CONNECT` | Проверить `bsdm_proxy_security_ssrf_blocked_total` |
| Agent API: device token действует только для своего устройства; revoke, список устройств, policy push — только с `CONTROL_API_TOKEN` | Lab-агенты (вне GA), использовавшие device token для операторских вызовов, получат `403` | Перевести автоматизацию на control-токен |
| Тела `/api/acl/*` и control API читаются после проверки токена и с лимитом | Слишком большие тела мутаций → `413` | Ничего для штатных операций |

Окончательный список и имена переменных — раздел `[1.0.0-rc.1]` в
[CHANGELOG.md](../../CHANGELOG.md).

---

## 3. Процедура

### 3.0 Подготовка (для всех вариантов)

1. Зафиксировать текущую версию (`proxy/Cargo.toml` сборки / тег образа /
   имя тарболла) и конфигурацию: env, values, ACL, pinning exceptions, RPZ state.
2. Бэкап: CA + `certs/archive/`, секреты, `ACL_RULES_PATH`,
   `PINNING_EXCEPTIONS_PATH` и аудит, `DNS_RPZ_STATE_DIR`,
   `./scripts/backup-clickhouse.sh` (если ClickHouse используется).
3. Проверить подпись образов / `sha256` тарболла v1.0.0
   ([§3.4 prod-гайда](../getting-started/production-deployment.md#34-проверка-артефактов-релиза)).
4. Прогнать обновление на staging с prod-флагами; smoke из §4.
5. Согласовать окно: при одном узле proxy рестарт прерывает соединения на время
   `SHUTDOWN_TIMEOUT_SECONDS` + старт.

### 3.1 Compose: пилот → prod-профиль

```bash
# 1. Перенести токены из окружения в файлы секретов
install -d -m 700 deploy/compose/secrets
printf '%s' "$CONTROL_API_TOKEN" > deploy/compose/secrets/control_api_token
printf '%s' "$SEARCH_API_TOKEN"  > deploy/compose/secrets/search_api_token
openssl rand -hex 32 > deploy/compose/secrets/metrics_auth_token
openssl rand -hex 32 > deploy/compose/secrets/ingest_api_token
cp "$BASIC_AUTH_USERS_HOST" deploy/compose/secrets/basic_auth_users   # пилотный файл пользователей
sudo chown 1000:1000 deploy/compose/secrets/* certs/ca.key certs/ca.crt
sudo chmod 0400 deploy/compose/secrets/* certs/ca.key

# 2. Перенести пилотные настройки в prod.env (только непривилегированные)
cp deploy/compose/prod.env.example deploy/compose/prod.env
#   обязательно BSDM_IMAGE_TAG=1.0.0 и PROXY_BIND; DNS_BIND (default 127.0.0.1), MITM_CATEGORIES…
#   аналитика: EVENT_SINK_URL=http://cache-indexer:8080/api/events, SEARCH_UPSTREAM_URL=http://cache-indexer:8080

# 3. Остановить пилотный стек (тома сохраняются)
docker compose -f docker-compose.yml -f deploy/compose/docker-compose.pilot.yml down

# 4. Поднять prod-профиль
C="docker compose -f deploy/compose/docker-compose.prod.yml --env-file deploy/compose/prod.env"
$C config --quiet && $C --profile analytics pull && $C --profile analytics up -d
```

Все пять файлов секретов обязательны, даже без `--profile analytics`. DNS в
prod-профиле слушает `53/udp` на `DNS_BIND` (в пилоте был `:5353`) — обновите
DHCP/резолверы клиентов. ACL-файл монтируется read-only: правки из Admin Console
(Policies) не сохраняются, меняйте файл и перезапускайте proxy.

Prod-профиль Compose не содержит Kafka/ClickHouse: аналитика идёт в SQLite
cache-indexer. Если пилот хранил историю в ClickHouse и она нужна — оставьте
ClickHouse как внешний сервис (профиль M) или выгрузите дамп
`backup-clickhouse.sh` для архива. Имена томов prod-профиля могут отличаться от
пилотных: ACL, pinning registry и RPZ state перенесите явно.

### 3.2 Helm

```bash
helm diff upgrade bsdm charts/bsdm -n bsdm-proxy \
  -f charts/bsdm/values-prod.yaml -f charts/bsdm/values-production.yaml \
  --set image.tag=1.0.0           # при наличии плагина helm-diff
helm upgrade bsdm charts/bsdm -n bsdm-proxy \
  -f charts/bsdm/values-prod.yaml -f charts/bsdm/values-production.yaml \
  --set image.tag=1.0.0 --atomic --timeout 10m
```

`values-production.yaml` требует заранее созданных Secret-ов — без
`bsdm-control` (`control-api-token`) и `bsdm-basic-auth` (`basic-auth-users.json`)
рендер падает; также нужны `bsdm-metrics` (`metrics-auth-token`, для
ServiceMonitor) и `bsdm-mitm-ca`. Команды — в шапке файла и в
[prod-гайде](../getting-started/production-deployment.md#32-kubernetes--helm-профили-m-и-l).
В базовом `values.yaml` `proxy.allowAnonymousProxy` = `true` ради обратной
совместимости (чарт по умолчанию без auth); production-оверлей выставляет `false`.

С chart-версий до 0.6.2 сначала выполните миграцию
[security contract](../../charts/bsdm/README.md#security-contract-breaking-since-062):
пароли и токены — только через `existingSecret`, NetworkPolicy включена по
умолчанию, клиентские сети нужно перечислить явно.

### 3.3 systemd

```bash
sudo ./scripts/install-release.sh --version 1.0.0-rc.1   # или curl … | sudo bash -s -- --version 1.0.0-rc.1
sudo systemctl daemon-reload
sudo systemctl restart bsdm-proxy bsdm-dns-sinkhole
```

Установщик не перезаписывает существующий `/etc/bsdm-proxy/bsdm-proxy.env`:
сравните его с новым примером из пакета и перенесите новые переменные вручную.

Права в нативной установке изменились: бинарники, `/etc/bsdm-proxy` и CA
принадлежат `root` (сервис читает их через группу `bsdm-proxy`), а
`bsdm-proxy.service` больше не может писать в `/etc/bsdm-proxy`. Последствия:

- runtime-изменения из Admin Console сохраняются в
  `/var/lib/bsdm-proxy/bsdm-proxy.env` (`CONFIG_ENV_PATH` дописывается установщиком);
- сохранение ACL через control API работает, только если `ACL_RULES_PATH`
  указывает в `/var/lib/bsdm-proxy/`; иначе правьте файл и делайте reload;
- если включён Basic auth и users-файла нет, установщик создаёт пользователя
  `admin`, пароль — в `/etc/bsdm-proxy/initial-basic-auth-password` (только root).

---

## 4. Проверка после обновления

```bash
curl -fsS http://127.0.0.1:9090/health
curl -fsS http://127.0.0.1:9090/ready
curl --cacert certs/ca.crt -x http://127.0.0.1:3128 https://httpbin.org/get
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:9090/api/cache/purge   # 401
curl -fsS 'http://127.0.0.1:8080/api/search?limit=5' -H "Authorization: Bearer $SEARCH_API_TOKEN"
./scripts/run-dns-pilot-smoke.sh
```

30 минут наблюдения: доля ошибок upstream, p95 latency,
`bsdm_proxy_policy_decision_source_total{source="pinning-bypass"}`,
`bsdm_proxy_security_ssrf_blocked_total`, `bsdm_proxy_kafka_queue_dropped_total`.
Затем пройдите [production readiness checklist](production-readiness-checklist.md).

## 5. Откат на 0.9.x

1. Вернуть предыдущий тег/пакет (`helm rollback`, прежний compose-стек,
   `install-release.sh --version 0.9.15`).
2. Восстановить конфигурацию из бэкапа шага 3.0.
3. Колонки ClickHouse, добавленные новой версией, не удалять — старая версия их
   игнорирует.
4. Хеши Argon2id, уже перезаписанные 1.0, понимает и 0.9.14+; при откате ниже
   0.9.14 восстановите файл пользователей из бэкапа.

Подробно — [runbook § 7](runbook.md#7-откат-релиза).
