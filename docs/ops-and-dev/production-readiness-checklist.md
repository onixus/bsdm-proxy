# Production readiness checklist (go-live v1.0)

Чек-лист допуска BSDM-Proxy v1.0 к промышленному трафику. Каждый пункт
сформулирован как **требование → как проверить → доказательство**. Пункт без
приложенного доказательства считается **не выполненным** — так же, как в
[pilot go / no-go](pilot-go-no-go-template.md).

Скопируйте файл в артефакты площадки, заполните колонки «Статус» и «Ссылка на
доказательство» (лог команды, скриншот, отчёт, тикет) и приложите к записи о
решении.

**Связанные документы:** [Production deployment](../getting-started/production-deployment.md) ·
[Upgrade guide](upgrade-guide.md) · [Runbook](runbook.md) ·
[Control plane security](control-plane-security.md) · [CA lifecycle](ca-lifecycle.md) ·
[Backup & restore](backup-restore.md) · [Project status](../project-status.md)

| Поле | Значение |
|---|---|
| Площадка / окружение | |
| Версия | `1.0.0` (+ digest образов / sha256 тарболла) |
| Вариант поставки | ☐ Compose prod ☐ Helm values-production ☐ systemd |
| Профиль сайзинга | ☐ S ☐ M ☐ L |
| Дата проверки | |

Легенда: **B** — блокирует go-live; **C** — допустим go-with-conditions с
владельцем и сроком.

---

## 1. Артефакты релиза и supply chain

| # | Требование | Как проверить | Доказательство | Вес | Статус |
|---|---|---|---|---|---|
| 1.1 | Используется тегированный релиз `v1.0.0`, не сборка из checkout | `docker compose … config \| grep image:` / `helm get values` / версия в имени установленного тарболла и `/opt/bsdm-proxy` (бинарник не печатает версию) | вывод команды | B | |
| 1.2 | CI-гейт релизного коммита зелёный (`ci-gate`: fmt, clippy, test, cargo-deny, admin-console) | GitHub Actions run для тега | ссылка на run | B | |
| 1.3 | Подпись образов проверена | `cosign verify ghcr.io/onixus/bsdm-proxy:1.0.0 …` ([команда](../getting-started/production-deployment.md#34-проверка-артефактов-релиза)) | вывод `cosign verify` | B | |
| 1.4 | SBOM получен и подписан, trivy-гейт без CRITICAL/HIGH (fixable) | `cosign verify-attestation --type spdxjson …`; лог trivy в `docker-publish.yml` | вывод + ссылка на run | B | |
| 1.5 | Native: контрольная сумма и подпись тарболла | `sha256sum -c *.tar.gz.sha256`; `cosign verify-blob … --bundle *.sigstore.json` | вывод | B (systemd) | |
| 1.6 | В манифестах указан digest `@sha256:`, а не плавающий тег | ревью Compose/values/GitOps | diff / PR | C | |

## 2. Скоуп и конфигурация

| # | Требование | Как проверить | Доказательство | Вес | Статус |
|---|---|---|---|---|---|
| 2.1 | `DEPLOYMENT_PROFILE=production`, `POLICY_MODE=selective-mitm` (или `sni`) | env процесса (`docker inspect`, `/etc/bsdm-proxy/bsdm-proxy.env`, ConfigMap) | выдержка конфигурации | B | |
| 2.2 | `full-mitm` недоступен | запуск с `POLICY_MODE=full-mitm` на staging отклоняется | лог отказа | B | |
| 2.3 | eBPF/XDP не взведён | `curl … /metrics \| grep bsdm_proxy_ebpf_armed` → `0`; `GET /api/ebpf/config` → `"runtimeEnableAllowed": false` | вывод | B | |
| 2.4 | TI enforcement выключен | `TI_ENFORCEMENT_MODE` не задан или `shadow`; `bsdm_proxy_ti_effective_mode`; алерт `BsdmTiEnforcementActive` не активен | вывод метрики | B | |
| 2.5 | Lab/frozen модули выключены: WASM, ICAP, DLP, AWG, agent fleet, gRPC, cluster | `WASM_ENABLED`, `ICAP_ENABLED`, `DLP_ENABLED`, `CONTROL_GRPC_ENABLED` ≠ `true`; профили `awg`/`icap` не запущены | выдержка env + `docker compose ps` / `kubectl get pods` | B | |
| 2.6 | Beta-модули, если включены, прошли отдельную приёмку | для каждого — запись приёмки | ссылки | C | |
| 2.7 | ACL включён и правила загружены из writable `ACL_RULES_PATH` | `ACL_ENABLED=true`; `GET /api/acl/rules` с Bearer | вывод | B | |
| 2.8 | Pinning exceptions registry смонтирован, аудит пишется | `PINNING_EXCEPTIONS_PATH`, `PINNING_AUDIT_LOG_PATH` существуют, `0600` | `ls -l` | B | |
| 2.9 | Retention задан явно (ClickHouse TTL / SQLite, Kafka, Prometheus) и согласован с ИБ/юристами | `SHOW CREATE TABLE bsdm.http_cache`, конфиг брокера, флаги Prometheus | выдержки + согласование | B | |
| 2.10 | Hardening data plane: `BLOCK_LOOPBACK_FORWARDING=true`, `ALLOWED_CONNECT_PORTS=443` (+ согласованные) задан явно, `PERF_FAST_CACHE_HIT`/`BSM_PERF_MODE` не заданы | env процесса; `curl -x …:3128 http://127.0.0.1:9090/health` и `CONNECT 127.0.0.1:6379` → `403` | вывод | B | |
| 2.11 | Без proxy-auth: есть `IpRange`-правило клиентских подсетей, `ALLOW_ANONYMOUS_PROXY` не задан (или задан по решению ИБ) | ревью `ACL_RULES_PATH` и env при `AUTH_ENABLED=false` | выдержка правил + решение | B | |
| 2.12 | Lab-маршруты закрыты: `AGENT_API_ENABLED`, `AWG_API_ENABLED`, `LAB_API_ENABLED` не заданы | `curl -H "Authorization: Bearer $T" :9090/api/amneziawg/status` → `404` | HTTP-код | B | |
| 2.13 | `INGEST_API_TOKEN` отличается от `SEARCH_API_TOKEN`; `SEARCH_UPSTREAM_TOKEN` задан | secret store; в логе cache-indexer нет warn об общем токене | выдержка лога | B (если analytics) | |

## 3. MITM CA

| # | Требование | Как проверить | Доказательство | Вес | Статус |
|---|---|---|---|---|---|
| 3.1 | Prod-CA выпущен заново (не lab/pilot), профиль `CA:TRUE pathlen:0`, `keyCertSign,cRLSign` | `openssl x509 -in ca.crt -noout -text` | вывод + SHA-256 fingerprint в change record | B | |
| 3.2 | `ca.key` — `0400` (или `0440` с выделенной группой / K8s `fsGroup`), read-only mount, не в образе и не в git; proxy стартует (CA fail-closed в production) | `stat`, `kubectl get pod -o yaml`, `git log --all -- '*ca.key'` пусто | вывод | B | |
| 3.3 | Доступ к ключу ограничен и аудируется | ACL Vault/Secret, политика RBAC | выгрузка политики | B | |
| 3.4 | Зашифрованный бэкап ключа в vault, dual control | запись об экспорте | тикет | B | |
| 3.5 | `ca.crt` распространён на все управляемые классы клиентов | выборочная проверка `curl --cacert` / браузер на каждом классе ОС | отчёт выборки | B | |
| 3.6 | Дата истечения в календаре ротации, есть алерт < 45 дней | `bsdm_proxy_mitm_ca_not_after_timestamp_seconds` в `/metrics`; правило алерта | ссылка на календарь/правило | B | |
| 3.7 | Учение ротации и отката CA пройдено на этой версии | `make rotate-ca-drill`, `SKIP_CLICKHOUSE=1 ./scripts/drill-backup-restore.sh` | лог учения ([пример](pilot-drills-runbook.md)) | B | |
| 3.8 | Решение по алгоритму CA (RSA-4096 vs ECDSA P-256) принято с учётом CPU | расчёт по [module-resource-profile](../architecture/module-resource-profile.md#mitm) | запись решения | C | |

## 4. Секреты и control plane

| # | Требование | Как проверить | Доказательство | Вес | Статус |
|---|---|---|---|---|---|
| 4.1 | Заданы `CONTROL_API_TOKEN`, `ACL_API_TOKEN`, `SEARCH_API_TOKEN` (≥ 32 байт, уникальны) | наличие в secret store; proxy стартует (без токена — отказ старта) | скриншот secret store без значений | B | |
| 4.2 | `*_ALLOW_INSECURE` не `true` | `env \| grep ALLOW_INSECURE` | вывод | B | |
| 4.3 | Мутации без токена → `401` | `curl -X POST :9090/api/cache/purge` без Bearer ([quick verification](control-plane-security.md#quick-verification)) | HTTP-код | B | |
| 4.4 | `/api/mitm/circuit-breaker` без токена → `401` | `curl :9090/api/mitm/circuit-breaker` | HTTP-код | B | |
| 4.5 | Search API без токена → `401` | `curl :8080/api/search?limit=1` | HTTP-код | B | |
| 4.6 | `/metrics` требует отдельный scrape-токен (`METRICS_AUTH_TOKEN`) | `curl :9090/metrics` без токена → `401`, с токеном → `200` | вывод `curl` | B | |
| 4.7 | Admin Console вне хоста — только через TLS reverse proxy + SSO/mTLS | конфиг ingress/nginx, `curl -v https://…/admin/` | конфиг + вывод | B | |
| 4.8 | Секреты отсутствуют в git, values, ConfigMap, образах | `gitleaks`/ревью; `kubectl get cm -o yaml` | отчёт сканера | B | |
| 4.9 | Политика ротации токенов (≤ 90 дней) назначена владельцу | регламент | ссылка | C | |
| 4.10 | Файл Basic-пользователей — свой, не example, `0600` | `stat`, сверка хешей с example | вывод | B (если auth) | |

## 5. Сеть

| # | Требование | Как проверить | Доказательство | Вес | Статус |
|---|---|---|---|---|---|
| 5.1 | `:3128` доступен только из клиентских подсетей | скан из внешней и чужой подсети (`nmap`) | вывод скана | B | |
| 5.2 | `9090`, `8080`, `8092`, `8093`, ClickHouse, Kafka, Redis не доступны из клиентской сети и интернета | `nmap` из клиентской сети; NetworkPolicy / SG | вывод скана + политика | B | |
| 5.3 | K8s: NetworkPolicy включена, клиентские CIDR/namespace заданы | `kubectl get networkpolicy`; `values-production.yaml` | вывод | B (K8s) | |
| 5.4 | DNS-клиенты переводятся на sinkhole только после smoke | `./scripts/run-dns-pilot-smoke.sh` | лог | B | |
| 5.5 | Путь отката клиентов (PAC/DHCP/GPO) подготовлен и проверен | процедура + тест на одном сегменте | запись теста | B | |

## 6. Наблюдаемость

| # | Требование | Как проверить | Доказательство | Вес | Статус |
|---|---|---|---|---|---|
| 6.1 | Prometheus скрейпит proxy, dns-sinkhole, cache-indexer | `up` = 1 для всех targets | скриншот targets | B | |
| 6.2 | Алерты из [минимального набора](../getting-started/production-deployment.md#8-мониторинг-и-алерты) загружены и маршрутизированы дежурным | `promtool check rules`; тестовый алерт доходит до канала | ссылка на тестовый алерт | B | |
| 6.3 | Дашборды Grafana развёрнуты | `bsdm-proxy`, `bsdm-http-traffic-ch` | скриншот | C | |
| 6.4 | Логи централизованы и хранятся по политике; аудит-файлы (pinning, RPZ, SOAR) отгружаются | SIEM-запрос по последним событиям | скриншот запроса | B | |
| 6.5 | События доходят до Search API | `GET /api/search?limit=5` с Bearer после тестового трафика | вывод | B | |
| 6.6 | Алерты `BsdmMitmBreakerTripped` и `BsdmMitmCaExpiringSoon` ([`prometheus/alerts/mitm.yml`](../../prometheus/alerts/mitm.yml)) загружены и доходят до дежурного | тестовый trip на staging (3 клиента) / подмена порога | ссылка на алерт | B | |

## 7. Резервное копирование и восстановление

| # | Требование | Как проверить | Доказательство | Вес | Статус |
|---|---|---|---|---|---|
| 7.1 | Расписание бэкапов настроено по [таблице](../getting-started/production-deployment.md#9-бэкапы-и-восстановление) | cron/CronJob, последние успешные прогоны | список бэкапов | B | |
| 7.2 | Восстановление аналитики проверено, counts совпадают | `RESTORE_TRUNCATE=1 ./scripts/restore-clickhouse.sh …` на staging | `COUNTS.txt` до/после | B | |
| 7.3 | Восстановление proxy с нуля уложилось в RTO (≤ 1 ч) | учение: чистый хост → install → CA/env → трафик | таймлайн учения | B | |
| 7.4 | Бэкапы зашифрованы, хранятся отдельно от хоста | политика хранилища | ссылка | B | |

## 8. Производительность и ёмкость

| # | Требование | Как проверить | Доказательство | Вес | Статус |
|---|---|---|---|---|---|
| 8.1 | Нагрузочный тест с prod-флагами на профиле трафика площадки | `./scripts/run-hybrid-load-test.sh` | отчёт в [`load-test-results/`](load-test-results/README.md) | B | |
| 8.2 | p95/p99 добавленной latency в рамках SLO, error rate < 0.5% | отчёт 8.1 | цифры | B | |
| 8.3 | Запас: CPU proxy < 70%, RAM < 80%, нет swap на пике | метрики во время теста | графики | B | |
| 8.4 | Spill на NVMe, очистка при рестарте настроена | конфиг entrypoint / `ExecStartPre` | выдержка | C | |
| 8.5 | Профиль M/L: отказ одного узла proxy не прерывает сервис | остановка одного узла/pod под нагрузкой | запись теста | B (M/L) | |

## 9. Эксплуатационная готовность

| # | Требование | Как проверить | Доказательство | Вес | Статус |
|---|---|---|---|---|---|
| 9.1 | Дежурство назначено, контакты эскалации актуальны | график on-call | ссылка | B | |
| 9.2 | Дежурные прошли [runbook](runbook.md): breaker reset, откат релиза, компрометация CA (tabletop) | запись tabletop | протокол | B | |
| 9.3 | Процедура обновления и отката отрепетирована на staging | [upgrade guide](upgrade-guide.md) | лог репетиции | B | |
| 9.4 | Уведомление пользователей о TLS-инспекции и правовое согласование | документ ИБ/юристов | ссылка | B | |
| 9.5 | Список доменов-исключений (pinning) согласован с владельцами бизнес-приложений | реестр с владельцами и сроками | ссылка | C | |

---

## 10. Решение

| Итог | Условие |
|---|---|
| **go** | Все пункты **B** выполнены с доказательствами |
| **go-with-conditions** | Все **B** выполнены; открытые **C** имеют владельца, срок и метод проверки |
| **no-go** | Любой невыполненный **B** |

| Роль | Имя | Дата | Подпись |
|---|---|---|---|
| Владелец сервиса | | | |
| Operations / DevOps lead | | | |
| Security lead / SOC | | | |
| Network / infrastructure | | | |
