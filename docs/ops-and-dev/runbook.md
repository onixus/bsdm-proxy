# Runbook: инциденты production

Процедуры дежурного для BSDM-Proxy v1.0 в GA-скоупе
([production deployment](../getting-started/production-deployment.md)). Каждый
сценарий: **признаки → диагностика → немедленные действия → восстановление →
закрытие**. Принцип из [ADR 0007](../adr/0007-mitm-circuit-breaker.md):
**доступность пользователей важнее инспекции**, но не ценой открытия control
plane или обхода ACL.

**Связанные документы:** [Production readiness checklist](production-readiness-checklist.md) ·
[CA lifecycle](ca-lifecycle.md) · [Backup & restore](backup-restore.md) ·
[Certificate pinning & breaker](../features/certificate-pinning.md) ·
[Control plane security](control-plane-security.md) · [Troubleshooting](../getting-started/troubleshooting.md) ·
[Upgrade guide](upgrade-guide.md)

Обозначения в командах: `C` — команда Compose
(`docker compose -f deploy/compose/docker-compose.prod.yml --env-file deploy/compose/prod.env`),
`$T` — `CONTROL_API_TOKEN`. Для Kubernetes используйте `kubectl -n bsdm-proxy`, для
systemd — `systemctl` / `journalctl -u bsdm-proxy`.

## Приоритеты

| Приоритет | Определение | Реакция |
|---|---|---|
| **P1** | Пользователи не выходят в интернет / компрометация CA или control plane | немедленно, эскалация владельцу сервиса и ИБ |
| **P2** | Деградация (latency, частичные ошибки, потеря аналитики, один узел из N) | ≤ 30 мин |
| **P3** | Нет пользовательского влияния (алерт аналитики, предупреждения) | рабочее время |

Перед любыми действиями: зафиксировать время начала, сохранить логи
(`C logs --since 1h proxy > incident-proxy.log`), не перезапускать контейнеры
«на всякий случай» до сохранения доказательств, если это не P1 без обходного пути.

---

## 1. Proxy недоступен или перегружен

**Признаки:** `up == 0` для proxy; рост `bsdm_proxy_upstream_errors_total`;
p95 `bsdm_proxy_request_duration_seconds` выше SLO; жалобы пользователей; `/ready`
не отвечает `200`.

**Диагностика:**

```bash
curl -fsS -m 3 http://127.0.0.1:9090/health; curl -fsS -m 3 http://127.0.0.1:9090/ready
C ps; C logs --tail=300 proxy          # / journalctl -u bsdm-proxy -n 300 / kubectl logs
docker stats --no-stream                # CPU, mem против лимита
curl -s -H "Authorization: Bearer $METRICS_AUTH_TOKEN" http://127.0.0.1:9090/metrics \
  | grep -E 'bsdm_proxy_requests_in_flight|bsdm_proxy_upstream_connections_active'
curl -x http://127.0.0.1:3128 -sS -o /dev/null -w '%{http_code} %{time_total}\n' http://example.com/
```

| Наблюдение | Вероятная причина | Действие |
|---|---|---|
| Процесс не стартует, в логе про `CONTROL_API_TOKEN` | секрет не смонтирован / пуст | восстановить секрет; **не** ставить `CONTROL_API_ALLOW_INSECURE=true` |
| Не стартует, ошибка CA (нет `ca.crt`, пара не совпадает, CA истёк, права `ca.key` шире `0440`) | CA fail-closed в production; права изменены, ротация не завершена | `./scripts/rotate-ca.sh verify`, `chmod 0400 ca.key`, проверить `MITM_CA_DIR`; при истечении — плановая ротация, при неудаче — откат CA ([backup-restore](backup-restore.md)) |
| Не стартует: `ALLOW_ANONYMOUS_PROXY` / `BASIC_AUTH_USERS_FILE` в логе | open-proxy guard или Basic без файла пользователей | восстановить файл пользователей / `IpRange`-правило; **не** ставить `ALLOW_ANONYMOUS_PROXY=true` как обходной путь без решения ИБ |
| OOMKilled / memory на лимите | spill page cache, UT1, сокетные буферы | см. [module-resource-profile](../architecture/module-resource-profile.md); поднять лимит, уменьшить `TCP_SNDBUF_BYTES`; проверить `RssAnon` vs `VmRSS` |
| CPU 100%, много новых SNI | выпуск MITM-листов (RSA-4096) | временно сузить `MITM_CATEGORIES` или `POLICY_MODE=sni`; план — ECDSA CA |
| Диск spill заполнен | мусор после `SIGKILL` | остановить proxy, очистить `CACHE_SPILL_DIR`, запустить |
| `upstream_errors` растут при нормальном proxy | внешний upstream / DNS / egress | проверить `curl` напрямую с хоста, DNS-резолвер, NAT/egress firewall |
| `rate_limit_rejected_total` растёт | легитимный пик или сканирование | проверить источник по логам; корректировать лимиты осознанно |

**Немедленные действия (P1, обходной путь):**

1. Если есть второй узел/реплика — вывести проблемный из балансировщика
   (K8s: pod выйдет из endpoints по `readiness`).
2. Рестарт: `C restart proxy` / `systemctl restart bsdm-proxy` /
   `kubectl rollout restart deploy/<release>-bsdm`. Перед рестартом
   одноузловой установки — очистить spill.
3. Если сервис не поднимается за 15 минут и причина в новом релизе — [§ 7](#7-откат-релиза).
4. Крайняя мера при недоступности более RTO: переключить клиентов на прямой выход
   (PAC/GPO/DHCP — процедура отката клиентов из readiness checklist, п. 5.5) по
   решению владельца сервиса и ИБ. Зафиксировать как отключение контроля.

**Закрытие:** причина установлена, сайзинг пересмотрен
([триггеры](../getting-started/production-deployment.md#2-топология-и-сайзинг)),
запись инцидента с таймлайном.

---

## 2. MITM circuit breaker сработал

**Признаки:** алерт на `increase(bsdm_proxy_mitm_circuit_breaker_trips_total[5m]) > 0`; рост `bsdm_proxy_policy_decision_source_total{source="pinning-bypass"}`;
в логе `bypass_reason="circuit_breaker_tripped"`; аудит
`"action":"circuit_breaker_tripped"` в `PINNING_AUDIT_LOG_PATH`. Пользователи,
как правило, **не страдают** — домен ушёл в blind `CONNECT`, но инспекция для
него не выполняется. С v1.0 trip требует сбоев от ≥ 3 различных IP клиентов
(`MITM_CIRCUIT_BREAKER_MIN_CLIENTS`), а домен возвращается в MITM сам через
`MITM_CIRCUIT_BREAKER_COOLDOWN_SECS` (900 с). **Каждый trip разбирается:** три
сговорившихся клиента (например, заражённые хосты) могут намеренно вывести
C2-домен из инспекции на 15 минут.

**Диагностика:**

```bash
curl -fsS http://127.0.0.1:9090/api/mitm/circuit-breaker -H "Authorization: Bearer $T" \
  | jq '{tripped_count, tracked_domains, evicted_tripped_domains_total, dropped_attempts_total, tripped: [.tripped_domains[] | {domain, reason, failure_rate}]}'
tail -n 50 "$PINNING_AUDIT_LOG_PATH"
```

| Картина | Решение |
|---|---|
| Один домен, приложение пинит сертификат | **не сбрасывать**; оформить pinning exception ([процедура](../features/certificate-pinning.md#safe-change-procedure)) |
| Временный сбой upstream-сертификата, уже исправлен | сброс по домену |
| Много доменов сразу, `reason` = `cert_gen_error` | проблема локальная: CA (срок, права), часы, диск — **сначала чинить причину**, потом общий сброс |
| Trip по домену из категорий `malware`/`phishing`, клиенты — несколько внутренних хостов | возможный умышленный обход инспекции: **не сбрасывать вслепую**, передать SOC список IP из аудита/логов, рассмотреть ACL deny домена до выяснения |
| Растёт `evicted_domains_total` / `evicted_tripped_domains_total` | карта упирается в `MITM_CIRCUIT_BREAKER_MAX_DOMAINS`: возможное сканирование `CONNECT` — искать источник |

**Сброс** (Bearer, все три поля обязательны, пишется в аудит):

```bash
curl -fsS -X POST http://127.0.0.1:9090/api/mitm/circuit-breaker/reset \
  -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"domain":"api.vendor.example","actor":"oncall@example.com","reason":"INC-1234 upstream cert fixed"}'
```

**Проверка:** `tripped_count` уменьшился; в аудите есть `circuit_breaker_reset`;
повторный trip в том же окне — прекратить сбросы, открыть exception или тикет
владельцу upstream. Повторяющиеся сбросы не заменяют exception.

---

## 3. Компрометация MITM CA

**P1. Признаки:** ключ найден вне хранилища (репозиторий, тикет, образ, общий
диск), несанкционированное чтение Secret/Vault, сертификаты с нашим issuer вне
proxy, утрата контроля над хостом proxy.

Цель первых минут — **остановить выпуск сертификатов и отозвать доверие
клиентов**, сохранив доказательства. Полный чек-лист —
[ca-lifecycle.md § Emergency revocation](ca-lifecycle.md#emergency-revocation-checklist).

1. Объявить инцидент, назначить incident owner (ИБ), зафиксировать SHA-256
   fingerprint скомпрометированного CA:
   `openssl x509 -in ca.crt -noout -fingerprint -sha256`.
2. **Отключить TLS-терминирование на всех узлах**: `POLICY_MODE=sni` (SNI/ACL
   продолжают работать, TLS не расшифровывается) и rollout/рестарт всего парка.
   Проверка: `decision_source` больше не содержит `mitm`.
3. Удалить скомпрометированный root из профилей MDM/GPO, форсировать обновление
   политик, проверить на выборке клиентов.
4. Отозвать версию Secret/Vault, запретить чтение, сохранить журналы доступа.
5. Удалить ключ со всех узлов (`shred`/уничтожение тома) после снятия образа для
   расследования.
6. Выпустить новый CA в чистом окружении (никогда не переиспользовать ключ),
   распространить `ca.crt`, активировать по плановой процедуре
   ([ca-lifecycle.md](ca-lifecycle.md#planned-two-phase-rotation)), вернуть
   `POLICY_MODE=selective-mitm` только после подтверждения покрытия клиентов.
7. Ротировать все учётные данные, имевшие доступ к хранилищу CA (включая
   `CONTROL_API_TOKEN`, если хост был скомпрометирован).
8. Поиск злоупотреблений: сертификаты, выпущенные вне proxy; трафик к
   нетипичным назначениям в Search API за период экспозиции.

**Закрытие:** подпись incident owner, отчёт о покрытии клиентов, обновлённая
дата в календаре ротации.

---

## 4. dns-sinkhole: недоступен или неверно блокирует

**Признаки:** `up == 0` для dns-sinkhole; рост `dns_sinkhole_errors_total`;
массовые «сайт не открывается» при работающем proxy; всплеск
`dns_sinkhole_blocked_total`.

**Диагностика:**

```bash
curl -fsS http://127.0.0.1:8092/health
dig @<sinkhole-ip> -p 5353 example.com A +short      # должен резолвиться
dig @<sinkhole-ip> -p 5353 blocked.test A +short     # sinkhole-адрес
C logs --tail=200 dns-sinkhole
./scripts/run-dns-pilot-smoke.sh
curl -fsS http://127.0.0.1:9090/api/dns/rpz/stats -H "Authorization: Bearer $T"
tail -n 50 "$DNS_RPZ_STATE_DIR/rpz-audit.jsonl"
```

| Картина | Причина | Действие |
|---|---|---|
| Не стартует после изменения зоны | синтаксис, путь, или подсунут `.shadow`-артефакт TI (отказ by design) | вернуть предыдущую зону (бэкап / `.bak`), проверить `DNS_SINKHOLE_ZONE_PATH` |
| Резолв `example.com` падает, blocked работает | недоступен `DNS_SINKHOLE_UPSTREAM` | проверить upstream с хоста; переключить на резервный резолвер |
| Внезапно блокируется много легитимных доменов | новый список RPZ / широкий суффикс | найти мутацию в `rpz-audit.jsonl`, удалить список через `/api/dns/rpz/lists/<id>` (Bearer), перекомпилировать |
| Блокировки по TI-фиду | **не должно быть** в GA: TI в shadow | проверить, что `threats.rpz` не подключён; алерт `BsdmTiEnforcementActive` |

**Обходной путь (P1):** DNS — первый рубеж, но не единственный: вернуть клиентам
корпоративный резолвер (DHCP option 6 / GPO) — ACL и SNI-фильтрация на proxy
продолжают работать. Возврат на sinkhole — после зелёного smoke.

---

## 5. Деградация аналитики (Kafka / ClickHouse / cache-indexer)

Аналитика вынесена из пути запроса: её отказ **не должен** влиять на
пользователей. Приоритет P2, если не затронуты требования ИБ к журналированию.

**Признаки:** `bsdm_proxy_kafka_send_errors_total` / `bsdm_proxy_kafka_queue_dropped_total`
растут; `cache_indexer_insert_errors_total`; Search API пустой или `5xx`;
алерты `BsdmAlertWorkerClickHouseDegraded`, `BsdmAlertWorkerStale`.

**Диагностика:**

```bash
curl -fsS http://127.0.0.1:8080/health
curl -fsS 'http://127.0.0.1:8080/api/search?limit=1' -H "Authorization: Bearer $SEARCH_API_TOKEN"
# ClickHouse
curl -fsS 'http://<clickhouse>:8123/?query=SELECT+1'
curl -fsS 'http://<clickhouse>:8123/?query=SELECT+count()+FROM+system.merges'
df -h   # тома ClickHouse / Kafka / SQLite
# Kafka consumer lag
kafka-consumer-groups.sh --bootstrap-server <kafka>:9092 --describe --group cache-indexer-group
```

| Картина | Действие |
|---|---|
| Диск ClickHouse/Kafka > 85% | проверить TTL (`SHOW CREATE TABLE bsdm.http_cache`), Kafka retention; расширить том; не удалять parts вручную |
| ClickHouse недоступен | восстановить сервис; cache-indexer догонит из Kafka в пределах retention топика; если retention истёк — данные за окно потеряны, зафиксировать |
| Kafka недоступен | proxy продолжает работать, события отбрасываются при переполнении очереди (`kafka_queue_dropped_total`) — зафиксировать окно потери |
| SQLite (Compose prod): ошибки записи | `cache_indexer_sqlite_writer_errors_total`, место на томе; рестарт indexer |
| Повреждение данных | остановить indexer, восстановить из дампа: `RESTORE_TRUNCATE=1 ./scripts/restore-clickhouse.sh …` ([backup-restore](backup-restore.md#restore)), сверить `COUNTS.txt` |

alert-worker при деградации ClickHouse сам переходит на backoff
([alerting.md](../analytics/alerting.md#clickhouse-latency-control)) — не
перезапускайте его циклически.

---

## 6. Утечка токена control plane

**P1**, если `CONTROL_API_TOKEN` или `ACL_API_TOKEN` попал вне secret store
(лог, тикет, чат, репозиторий).

1. Сгенерировать новый токен, обновить секрет, rollout/рестарт proxy.
2. Обновить токен в Admin Console (Settings → Console API), Prometheus и
   автоматизации.
3. Проверить аудит мутаций за период экспозиции: `PINNING_AUDIT_LOG_PATH`,
   `rpz-audit.jsonl`, изменения ACL (`/api/acl/rules`), `/api/config`; сравнить с
   бэкапом конфигурации.
4. Убедиться, что `:9090` не был доступен извне (firewall-логи).

---

## 7. Откат релиза

Когда: регрессия после обновления, которую нельзя исправить конфигурацией за
время, укладывающееся в SLO. Решение принимает дежурный + владелец сервиса.

1. **Зафиксировать** текущие версию, конфигурацию и логи.
2. **Откатить артефакт:**

   ```bash
   # Compose: вернуть предыдущий тег в prod.env
   sed -i 's/^BSDM_IMAGE_TAG=.*/BSDM_IMAGE_TAG=<previous>/' deploy/compose/prod.env
   C pull && C up -d
   # Helm
   helm history bsdm -n bsdm-proxy && helm rollback bsdm <revision> -n bsdm-proxy --wait
   # systemd
   sudo ./scripts/install-release.sh --version <previous> && sudo systemctl restart bsdm-proxy
   ```

3. **Восстановить конфигурацию** из бэкапа перед обновлением (env, ACL, pinning,
   RPZ state), если новая версия её меняла. Установщик и Helm не откатывают
   файлы на хосте.
4. **Схема ClickHouse не откатывается:** колонки, добавленные новой версией,
   остаются и игнорируются старой.
5. **Проверить:** `/health`, `/ready`, HTTPS через MITM, `401` на мутацию без
   токена, Search API, DNS smoke ([upgrade guide § 4](upgrade-guide.md#4-проверка-после-обновления)).
6. **Сообщить** о регрессии (issue с версией, симптомами, логами) и заблокировать
   повторное обновление до исправления.

---

## После любого инцидента

- Таймлайн, влияние, корневая причина, действия, ссылки на логи/метрики.
- Задачи на устранение причины с владельцем и сроком.
- Обновить этот runbook, если процедура не сработала как описано.
