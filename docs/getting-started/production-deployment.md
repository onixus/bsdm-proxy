# Production deployment (v1.0 GA)

Руководство по вводу BSDM-Proxy **v1.0** в промышленную эксплуатацию. Оно
продолжает [пилот Hybrid](pilot-deployment.md): тот же принцип «скучного» стека
без experimental-модулей, но с требованиями к отказоустойчивости, секретам,
мониторингу, бэкапам и процедуре обновления.

> [!IMPORTANT]
> Документ описывает **GA-скоуп v1.0**. Всё, что в нём помечено как beta/lab/frozen,
> не входит в гарантии релиза и в prod-профиле выключено. Фактическая зрелость
> функций — в [матрице статуса](../project-status.md); перед go-live пройдите
> [production readiness checklist](../ops-and-dev/production-readiness-checklist.md).

Связанные документы:

| Документ | Назначение |
|---|---|
| [Production readiness checklist](../ops-and-dev/production-readiness-checklist.md) | Go-live: пункт → проверка → доказательство |
| [Upgrade guide 0.9.x → 1.0](../ops-and-dev/upgrade-guide.md) | Миграция с пилотных версий |
| [Runbook инцидентов](../ops-and-dev/runbook.md) | Proxy down, breaker, компрометация CA, DNS, аналитика, откат |
| [Capacity planning](../architecture/capacity-planning.md) · [Ресурсный профиль модулей](../architecture/module-resource-profile.md) | Сайзинг |
| [CA lifecycle](../ops-and-dev/ca-lifecycle.md) · [Backup & restore](../ops-and-dev/backup-restore.md) | Ключи и восстановление |
| [Control plane security](../ops-and-dev/control-plane-security.md) | Токены, bind, сетевая изоляция |

---

## 1. GA-скоуп v1.0

Скоуп зафиксирован архитектурным ревью релиз-кандидата и совпадает с колонкой
«GA v1.0» в [матрице статуса](../project-status.md#ga-скоуп-v10). Принцип: GA — это
то, у чего есть security boundary, тесты, документированный путь и безопасный
prod-дефолт **в коде**, а не только в example-env.

### Входит в GA

| Компонент | Prod default | Что гарантируется / ключевые параметры |
|---|---|---|
| **Forward proxy + CONNECT** | ON | HTTP/1.1 forward, `CONNECT`-туннели, удаление hop-by-hop, `Host` = authority, SSRF-проверка по разрешённым адресам; `HTTP_PORT=3128` |
| **Hybrid Policy** `selective-mitm` | ON | MITM только для `MITM_CATEGORIES`; `full-mitm` запрещён в `DEPLOYMENT_PROFILE=production` |
| `POLICY_MODE=sni` | — | без терминирования TLS. Фильтрация выполняется по **authority из `CONNECT`**: ClientHello не разбирается, поэтому domain fronting и `CONNECT <IP>:443` доменными правилами не ловятся (реальный SNI-контроль — 1.1) |
| **MITM circuit breaker + pinning exceptions** | ON | blind `CONNECT` при сбоях TLS, аудит, ручной сброс ([ADR 0007](../adr/0007-mitm-circuit-breaker.md)); `PINNING_EXCEPTIONS_PATH`, `PINNING_AUDIT_LOG_PATH`. См. ограничения в §7a |
| **L1 cache + mmap spill** | ON | shared cache по RFC 9111: ответы с `Cookie`/`Authorization`/`Set-Cookie`/`Vary` не хранятся; `CACHE_CAPACITY`, `CACHE_SPILL_DIR` |
| **ACL** (blocklist-модель, `default_action=allow`) | ON | `ACL_ENABLED=true`; запрещено то, что запрещено явно |
| **Categorization: UT1, custom DB** | ON | `CATEGORIZATION_ENABLED`, `UT1_ENABLED` |
| **Rate limiting (локальный)** | ON | на узел; distributed — frozen |
| **Аутентификация Basic** | ON | Argon2id, файл пользователей `0600`; без файла в production — отказ старта |
| **Control REST `/api/*`, ACL REST, Admin Console** | ON, токен обязателен | Bearer fail-closed, `/admin/` встроена в образ; `CONTROL_API_TOKEN`, `ACL_API_TOKEN` |
| **`/metrics`, `/health`, `/ready`** | ON | `METRICS_REQUIRE_AUTH=true` или bind на mgmt-IP |
| **dns-sinkhole UDP + RPZ API** | ON (core) | первый рубеж блокировок, RPZ API с аудитом и confirm-гейтом; `53/udp` (Compose prod; в пилоте `:5353`), mgmt `:8092` не публикуется |
| **Аналитика** | опционально | cache-indexer + Search API (fail-closed, раздельные search/ingest токены): Lite HTTP event sink + SQLite в Compose prod-профиле, Kafka → ClickHouse для профилей M/L |
| **PAC/WPAD** | OFF до `PAC_PROXY` | отдельный listener, hot reload bypass-файла |

### Beta — opt-in, вне гарантий GA

Включайте только после отдельной приёмки на своём стенде; в prod-профиле OFF:

| Модуль | Ограничение |
|---|---|
| Redis L2 | нет гайда по AUTH/TLS, failover не проверен; при включении — `rediss://` + AUTH |
| Hierarchy ICP/HTCP, peer discovery | discovery без аутентификации — держать OFF |
| Categorization online (URLhaus/PhishTank/OTX), RKN sync | внешняя зависимость на hot path; RKN — только с URL оператора, без стороннего fallback |
| LDAP / NTLM / Kerberos | Cargo features; NTLM/Kerberos кэшируют аутентификацию по IP |
| gRPC control plane | `CONTROL_GRPC_ENABLED=false` |
| `alert-worker`, `ml-worker` + threat-score | `THREAT_SCORE_BLOCK_THRESHOLD=0` — только предупреждение |
| `threat-intel` collector + proxy `ti_shadow` | observe-only допустим в prod (`TI_ENFORCEMENT_MODE=shadow`) |
| TI enforce (`ti_enforce`, SOAR, публикация RPZ) | только по критериям [ADR 0008](../adr/0008-threat-intel-shadow-mode.md) с отдельной подписью |
| dns-sinkhole DoH/DoT | `DNS_SINKHOLE_DOH_ENABLED=false`, `DNS_SINKHOLE_DOT_ENABLED=false` |
| Semantic/AI cache, Qdrant | `SEMANTIC_CACHE_ENABLED=false` |

### Lab / frozen — выключено в prod

| Модуль | Статус | Как убедиться, что выключен |
|---|---|---|
| eBPF/XDP | lab | `bsdm_proxy_ebpf_armed == 0` |
| Agent Contract (enroll/policy/CRL/OCSP), control mTLS `:9443` | lab | `CONTROL_MTLS_ENABLED=false`; agent-роуты не используются |
| AmneziaWG API / BSDM Connect | lab | `AWG_CONFIG_PATH` не задан, профиль `awg` не запущен |
| OIDC + reverse proxy (ZTNA/IAP) | frozen | reverse proxy не включён |
| WASM, ICAP, native DLP/CASB | frozen | `WASM_ENABLED`, `ICAP_ENABLED`, `DLP_ENABLED` не `true`; `WASM_FAIL_OPEN=false` |
| Distributed rate limit / global sessions / threat sync | frozen | scaffolding, без Redis-пути |
| `full-mitm` | lab | отклоняется при `DEPLOYMENT_PROFILE=production` |

Расширение скоупа после go-live — отдельное решение с собственной записью в
[go / no-go](../ops-and-dev/pilot-go-no-go-template.md).

---

## 2. Топология и сайзинг

Все цифры — стартовые точки, выведенные из
[capacity-planning.md](../architecture/capacity-planning.md) и замеров
[module-resource-profile.md](../architecture/module-resource-profile.md). Подтвердите
их нагрузочным тестом на трафике своей площадки
([hybrid load test](../ops-and-dev/load-test-selective-mitm.md)).

| Профиль | Пользователи / пик | Топология | Узлы |
|---|---|---|---|
| **S** | до ~150 / 50–100 rps | один хост, без HA data plane | 12 vCPU · 24 GiB · 200 GB NVMe · 1 GbE |
| **M** | ~1 000 / 150–300 rps | 2 независимых edge (proxy + dns-sinkhole) за L4-балансировщиком + analytics-хост. Кэш, состояние breaker и cert cache между узлами не разделяются (HA одного сайта — roadmap 1.2) | edge: 4 vCPU · 8 GiB · 60 GB ×2; analytics: 12 vCPU · 32 GiB · 300 GB |
| **L** | ~5 000 / ~350+ rps | Kubernetes: proxy Deployment ≥3 реплик, внешние Kafka/ClickHouse | см. [k8s-architecture.md](../ops-and-dev/k8s-architecture.md#исторический-ha-sizing-5k-users-350-peak-rps) |

Правила, которые чаще всего нарушают в проде:

- **CPU определяется MITM, а не числом запросов.** Путь запроса стоит ~26 µs CPU,
  выпуск листа на новый SNI с RSA-4096 CA — ~1.86 мс (с ECDSA P-256 — ~24 µs).
  При широком множестве доменов выпускайте prod-CA на ECDSA P-256 или закладывайте
  CPU на подписи.
- **RAM proxy — это списки и кэш.** L1 ≈ объём inline-тел × 1.04; UT1 полный — сотни
  МБ; TI shadow ~260 Б на домен. Лимит контейнера не ниже 4 GiB (профиль S/M).
- **Spill ограничивает heap, но не RSS** (page cache в cgroup). Держите
  `CACHE_SPILL_DIR` на NVMe и **очищайте его при рестарте** — после `SIGKILL`
  файлы остаются.
- **Сокетные буферы** `TCP_SNDBUF_BYTES` (512 КиБ на соединение) не видны в RSS,
  но учитываются cgroup: 1000 соединений ≈ 1 GiB.
- **Redis без `maxmemory` запрещён** (`allkeys-lfu`).
- **threat-intel** (если включён shadow) — лимит 1 GiB и том ≥ 2 GB.

Analytics storage: `rows = events/day × retention_days`,
`clickhouse = rows × 0.3–1 КБ × 3`. Retention задаётся явно (ClickHouse TTL,
Kafka `retention.hours`, Prometheus `retention.time`) — дефолты пилота (5 суток)
пересмотрите под требования ИБ и законодательства.

Триггеры пересмотра сайзинга: CPU proxy > 70% дольше 15 минут, host RAM > 80% или
swap, растущий Kafka consumer lag, ClickHouse merges не успевают, p95 добавленной
latency выше SLO, spill > 70% диска.

---

## 3. Варианты поставки

Во всех вариантах используются одни и те же образы/бинарники релиза
`v1.0.0`: `ghcr.io/onixus/bsdm-{proxy,cache-indexer,alert-worker,ml-worker,dns-sinkhole,threat-intel}`.
Перед развёртыванием проверьте подпись и SBOM образов (см. §3.4).

### 3.1 Docker Compose (профиль S)

Prod-профиль — [`deploy/compose/docker-compose.prod.yml`](../../deploy/compose/docker-compose.prod.yml), **самостоятельный**
файл (не overlay поверх `docker-compose.yml`). Непривилегированные настройки
лежат в [`deploy/compose/prod.env.example`](../../deploy/compose/prod.env.example) → копия `deploy/compose/prod.env`.
Свойства профиля: только образы по `BSDM_IMAGE_TAG` (без `build:`), контейнеры
non-root, `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, healthchecks и
лимиты ресурсов.

| Сервис | В профиле | Примечание |
|---|---|---|
| `proxy` | всегда | MITM CA монтируется `../../certs → /certs:ro` |
| `dns-sinkhole` | всегда | DoH/DoT выключены |
| `cache-indexer` (SQLite, Search API) | `--profile analytics` | proxy отправляет события по `EVENT_SINK_URL`, без Kafka/ClickHouse |
| Kafka, ClickHouse, alert/ml-worker, threat-intel, Grafana, ICAP | **нет** | полный аналитический контур — внешний (профиль M/L) |

В профиле явно зафиксированы kill-switch'и: `EBPF_XDP_ENABLED=false`,
`EBPF_XDP_ALLOW_RUNTIME_ENABLE=false`, `WASM_ENABLED=false`, `ICAP_ENABLED=false`,
`DLP_ENABLED=false`, `CONTROL_GRPC_ENABLED=false`, `TI_ENFORCEMENT_MODE=shadow`,
`TI_ENFORCE_ENABLED=false`, `CONTROL_API_ALLOW_INSECURE=false`.

Секреты передаются через Compose `secrets:` из файлов в
`deploy/compose/secrets/` (каталог git-ignored, путь меняется `BSDM_SECRETS_DIR`):
`control_api_token`, `metrics_auth_token`, `basic_auth_users`,
`search_api_token`, `ingest_api_token` — **все пять обязательны**, даже без
analytics; пустой или отсутствующий файл → FATAL при старте.
Entrypoint-обёртка читает `/run/secrets/<name>` и экспортирует
`CONTROL_API_TOKEN`, `METRICS_AUTH_TOKEN` (отдельный scrape-токен), `EVENT_SINK_TOKEN`
(= ingest) и `SEARCH_UPSTREAM_TOKEN` (= search) для proxy, `SEARCH_API_TOKEN` /
`INGEST_API_TOKEN` для indexer перед запуском процесса — сами сервисы переменных
`*_FILE` для токенов не поддерживают. Контейнеры работают от uid/gid `1000`, а
обычный (не Swarm) Compose монтирует файлы секретов с владельцем и правами хоста.

Публикуются только data plane: proxy `:3128` на `PROXY_BIND` (обязателен,
клиентский IP) и DNS `:53/udp` на `DNS_BIND` (по умолчанию `127.0.0.1`). Control
plane `:9090` — только на `127.0.0.1` (`METRICS_HOST_PORT`); dns-sinkhole `:8092`
(reload зоны без аутентификации) и cache-indexer `:8080` не публикуются. Сети:
`edge` (egress) и `backend` (`internal: true`). Все сервисы — uid `1000`,
`read_only` + tmpfs `/tmp`, `cap_drop: [ALL]` без `cap_add` (sinkhole слушает 53
через sysctl `net.ipv4.ip_unprivileged_port_start=53`). ACL-файл монтируется
`:ro` (`ACL_AUTO_RELOAD=false`): правка файла + рестарт. Образы можно закрепить
по digest: `BSDM_PROXY_IMAGE`, `BSDM_DNS_SINKHOLE_IMAGE`, `BSDM_CACHE_INDEXER_IMAGE`.

```bash
# 1. Настройки
cp deploy/compose/prod.env.example deploy/compose/prod.env
#   обязательно: BSDM_IMAGE_TAG=1.0.0, PROXY_BIND=<клиентский IP>; DNS_BIND (default 127.0.0.1)
#   с --profile analytics: EVENT_SINK_URL=http://cache-indexer:8080/api/events,
#                          SEARCH_UPSTREAM_URL=http://cache-indexer:8080

# 2. Секреты
install -d -m 0700 deploy/compose/secrets
for s in control_api_token metrics_auth_token search_api_token ingest_api_token; do
  openssl rand -hex 32 > "deploy/compose/secrets/$s"
done
cp /path/to/basic-auth-users.json deploy/compose/secrets/basic_auth_users   # scripts/gen-basic-auth-user.sh, не example

# 3. Prod-CA (см. §4): ./scripts/gen-ca.sh или корпоративный sub-CA в ./certs; владелец — uid контейнера
sudo chown 1000:1000 deploy/compose/secrets/* certs/ca.key certs/ca.crt
sudo chmod 0400 deploy/compose/secrets/* certs/ca.key

# 4. Проверка и запуск из опубликованных образов
C="docker compose -f deploy/compose/docker-compose.prod.yml --env-file deploy/compose/prod.env"
$C config --quiet
$C --profile analytics pull
$C --profile analytics up -d
$C ps
```

Ожидаемый результат (проверено на референсном запуске): `/health` → 200;
`/metrics` без токена → 401, с metrics-токеном → 200; control API без токена → 401;
proxy без auth → 407, с auth → 200 (HTTP и HTTPS); запросы к `127.0.0.1` и
`169.254.169.254` через proxy → 403; процесс с uid 1000, `CapEff=0`,
`NoNewPrivs=1`, rootfs read-only.

Не используйте `--build` в проде: образ должен быть тем, чью подпись вы
проверили. Не объединяйте prod-профиль с lab-оверлеями (`awg`, `hierarchy`,
`ha`, `test`) и с базовым `docker-compose.yml`.

### 3.2 Kubernetes / Helm (профили M и L)

```bash
kubectl create namespace bsdm-proxy
# CA и токены — только через Secret (External Secrets / Sealed Secrets / Vault)
kubectl -n bsdm-proxy create secret generic bsdm-control \
  --from-literal=control-api-token="$(openssl rand -hex 32)"
kubectl -n bsdm-proxy create secret generic bsdm-metrics \
  --from-literal=metrics-auth-token="$(openssl rand -hex 32)"
kubectl -n bsdm-proxy create secret generic bsdm-basic-auth \
  --from-file=basic-auth-users.json=./basic-auth-users.json
kubectl -n bsdm-proxy create secret generic bsdm-mitm-ca \
  --from-file=ca.crt=./certs/ca.crt --from-file=ca.key=./certs/ca.key

helm lint charts/bsdm -f charts/bsdm/values-production.yaml
helm upgrade --install bsdm charts/bsdm \
  --namespace bsdm-proxy \
  -f charts/bsdm/values-prod.yaml \
  -f charts/bsdm/values-production.yaml \
  --set image.tag=1.0.0 \
  --atomic --timeout 10m
```

[`values-production.yaml`](../../charts/bsdm/values-production.yaml) — security-baseline
GA: Pod Security Standards **restricted**, NetworkPolicy (deny-all baseline;
`:9090` — только namespace мониторинга и `networkPolicy.controlPlaneNamespaces` /
`controlPlaneCidrs`), 3 реплики proxy, HPA 3–10, PDB `minAvailable: 2`,
anti-affinity по узлам и зонам, 2 реплики dns-sinkhole (порт 53 через sysctl
`net.ipv4.ip_unprivileged_port_start`, без `NET_BIND_SERVICE`), analytics-компоненты
выключены, `proxy.disableLabFeatures: true`, `proxy.allowAnonymousProxy: false`,
`MITM_CA_DIR` = `mitm.certMountPath`. Сайзинг под ~5k пользователей берётся из
`values-prod.yaml`; production-оверлей подключается **последним**.

Рендер **падает**, если нет Secret-ов `bsdm-control` (`control-api-token`) или
`bsdm-basic-auth` (`basic-auth-users.json`) — fail-closed вместо соблазна
включить `CONTROL_API_ALLOW_INSECURE`. `bsdm-metrics` (`metrics-auth-token`)
использует ServiceMonitor, `bsdm-mitm-ca` — proxy. Ключи values:
`proxy.controlApi.*`, `proxy.metricsAuth.*`, `proxy.basicAuth.*`,
`proxy.allowedConnectPorts`, `proxy.maxRequestBodyBytes`, `proxy.searchUpstream.*` —
см. комментарии в файле и
[charts/bsdm/README.md](../../charts/bsdm/README.md#security-contract-breaking-since-062).
`networkPolicy.proxyIngressCidrs` / `proxyClientNamespaces` по умолчанию пусты —
**задайте сети клиентов**, иначе они будут отрезаны.

Analytics plane (cache-indexer → внешний ClickHouse) разворачивается отдельным
релизом: [k8s-architecture.md](../ops-and-dev/k8s-architecture.md).

### 3.3 systemd (VM / bare metal)

```bash
curl -fsSL https://raw.githubusercontent.com/onixus/bsdm-proxy/main/scripts/install-release.sh \
  | sudo bash -s -- --version 1.0.0
# офлайн: sudo ./scripts/install-release.sh --archive bsdm-proxy-1.0.0-linux-<arch>.tar.gz
```

Скрипт сверяет `.sha256`, ставит статические бинарники в `/opt/bsdm-proxy`,
конфиги в `/etc/bsdm-proxy` и юниты из [`packaging/systemd/`](../../packaging/systemd/).
Юнит `bsdm-proxy.service` уже захарденен (`ProtectSystem=strict`, пустой
`CapabilityBoundingSet`, `SystemCallFilter`, `MemoryMax=4G`) и **не стартует без**
`/etc/bsdm-proxy/bsdm-proxy.env`. Перед `systemctl enable --now bsdm-proxy`:

1. CA в `/etc/bsdm-proxy/certs` (`ca.key` `0600`, владелец `bsdm-proxy`).
2. В `bsdm-proxy.env`: `DEPLOYMENT_PROFILE=production`, `POLICY_MODE=selective-mitm`,
   `CONTROL_API_TOKEN`, `METRICS_BIND` на management-интерфейс,
   `EBPF_XDP_ENABLED=false`. Сам файл — `0640 root:bsdm-proxy`.
3. Лимиты под свой профиль — drop-in `/etc/systemd/system/bsdm-proxy.service.d/20-limits.conf`.
4. Очистка spill при рестарте: `ExecStartPre=` в drop-in, удаляющий содержимое
   `CACHE_SPILL_DIR`.

### 3.4 Проверка артефактов релиза

- Native-тарболл: `sha256sum -c bsdm-proxy-1.0.0-linux-<arch>.tar.gz.sha256`.
- Образы: `.github/workflows/docker-publish.yml` по тегу `v*` собирает все шесть
  образов (multi-arch), прогоняет trivy-гейт (CRITICAL/HIGH, ignore-unfixed),
  публикует SBOM (SPDX) и подписывает образы cosign keyless с attestation SBOM:

  ```bash
  ID='^https://github.com/onixus/bsdm-proxy/\.github/workflows/docker-publish\.yml@refs/tags/v.*$'
  ISS=https://token.actions.githubusercontent.com
  cosign verify ghcr.io/onixus/bsdm-proxy:1.0.0 \
    --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISS"
  # SBOM (SPDX attestation)
  cosign verify-attestation --type spdxjson \
    --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISS" \
    ghcr.io/onixus/bsdm-proxy:1.0.0
  ```

- Native-тарболл, кроме `.sha256`, подписан sigstore-бандлом (release-воркфлоу
  публикует также SPDX SBOM):

  ```bash
  cosign verify-blob bsdm-proxy-1.0.0-linux-<arch>.tar.gz \
    --bundle bsdm-proxy-1.0.0-linux-<arch>.tar.gz.sigstore.json \
    --certificate-identity-regexp '^https://github.com/onixus/bsdm-proxy/\.github/workflows/release\.yml@refs/tags/v.*$' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

- Образы, опубликованные резервным `Jenkinsfile.publish`, подписаны ключом:
  `cosign verify --key cosign.pub <image>`.

- Используйте digest (`@sha256:…`) вместо тега в GitOps/Compose.

---

## 4. CA и ключи

Prod-CA выпускается **заново** — lab/pilot CA в проде не используется.

| Требование | Как |
|---|---|
| Профиль | `CA:TRUE, pathlen:0`, `keyUsage=keyCertSign,cRLSign`, срок 730 дней ([ca-lifecycle.md](../ops-and-dev/ca-lifecycle.md)) |
| Алгоритм | RSA-4096 по умолчанию; ECDSA P-256 снижает CPU выпуска листов ~70× — решение фиксируется до go-live |
| Хранение | `ca.key` `0400` (или `0440` с выделенной группой сервиса / K8s `fsGroup`), read-only mount, не на RWX/общем хранилище, не в образе и не в git |
| Доступ | Только сервисная учётка proxy и группа ротации CA; аудит чтения Secret/Vault |
| Бэкап | Зашифрованный (age/gpg), отдельно от бэкапов приложения, dual control |
| Распространение | Только `ca.crt`, через MDM/GPO; дата истечения — в календарь ротации |
| Ротация | Двухфазная `scripts/rotate-ca.sh prepare → activate`; учение `make rotate-ca-drill` перед go-live |

В `DEPLOYMENT_PROFILE=production` proxy **отказывается стартовать**, если в
`MITM_CA_DIR` нет `ca.crt`, ключ не соответствует сертификату, CA истёк или права
`ca.key` шире `0440` (доступ для «прочих» или запись для группы). CA читается
только из `MITM_CA_DIR` — legacy-пути `/certs` и `./certs` в production не
используются. Срок действия экспортируется метрикой
`bsdm_proxy_mitm_ca_not_after_timestamp_seconds` — алерт см. в §8.
Порядок действий при компрометации — [runbook](../ops-and-dev/runbook.md#3-компрометация-mitm-ca).

---

## 5. Секреты

| Секрет | Потребитель | Обязателен |
|---|---|---|
| `CONTROL_API_TOKEN` | proxy control plane, Admin Console | **да** — без него proxy не стартует в production |
| `ACL_API_TOKEN` | `/api/acl/*` | рекомендуется (иначе наследует CONTROL) |
| `SEARCH_API_TOKEN` | cache-indexer Search API | **да** при `SEARCH_API_ENABLED=true` |
| `SEARCH_UPSTREAM_TOKEN` | proxy → cache-indexer (same-origin Search через control plane) | по умолчанию = `SEARCH_API_TOKEN`; токен вызывающего больше не пересылается |
| `INGEST_API_TOKEN` (`ingest_api_token` в Compose) | `POST /api/events` cache-indexer (HTTP `EVENT_SINK_URL`) | **отдельный** от search-токена: ingest по существующему `event_id` перезаписывает событие |
| `METRICS_AUTH_TOKEN` / `METRICS_REQUIRE_AUTH=true` | scrape `/metrics` (отдельный от control-токена) | **да** в prod-профилях Compose/Helm |
| `TI_API_TOKEN` | `threat-intel` SOAR API | да, если профиль включён |
| `BASIC_AUTH_USERS_FILE` | Basic auth (Argon2id) | **да** при `AUTH_ENABLED=true` (иначе отказ старта в production); файл `0600` |
| ClickHouse credentials | cache-indexer, alert/ml-worker | да; в K8s — `existingSecret` |
| `GRAFANA_ADMIN_PASSWORD` | Grafana | да |
| `ca.key` | proxy | при MITM |

Правила:

1. Токены — не короче 32 байт (`openssl rand -hex 32`), уникальные на окружение.
2. Секреты не попадают в git, values-файлы, ConfigMap, shell history и тикеты.
3. `*_ALLOW_INSECURE=true` в проде запрещены (`CONTROL_API_ALLOW_INSECURE`,
   `SEARCH_API_ALLOW_INSECURE`, `TI_API_ALLOW_INSECURE`).
4. Ротация токенов — не реже раза в 90 дней и при уходе оператора: обновить
   секрет → рестарт/rollout сервиса → обновить токен в Admin Console и Prometheus.

---

## 6. Сеть, TLS control plane и hardening data plane

Control-листенер (`METRICS_PORT=9090`: `/api/*`, `/admin/`, `/metrics`) работает по
**plain HTTP** — встроенного TLS для него нет (TLS есть только у отдельного
agent mTLS-порта `CONTROL_MTLS_BIND`, lab). Поэтому:

1. Привязка к management-сети: `METRICS_BIND=127.0.0.1` или адрес mgmt-интерфейса;
   в Compose/K8s — публикация только во внутреннюю сеть / `ClusterIP`.
2. Firewall / security group / NetworkPolicy: `9090`, `8080`, `8092`, `8093`,
   ClickHouse, Kafka, Redis недоступны из клиентской сети и интернета.
3. Доступ операторов к `/admin/` и `/api/*` вне хоста — **только через reverse
   proxy с TLS** (nginx/Envoy/ingress) и SSO или mTLS перед ним. Bearer-токен по
   незашифрованному каналу через сеть не передаётся.
4. Prometheus скрейпит с Bearer (`METRICS_REQUIRE_AUTH=true`) из той же
   management-сети.
5. Data plane `:3128` открыт только для клиентских подсетей.

Проверки fail-closed — [control-plane-security.md](../ops-and-dev/control-plane-security.md#quick-verification).

### Обязательные настройки data plane

Независимо от варианта поставки задайте явно (часть дефолтов кода рассчитана на
лабораторию):

| Переменная | Prod-значение | Зачем |
|---|---|---|
| `BLOCK_LOOPBACK_FORWARDING` | `true` (default в production с v1.0; не переопределять) | клиенты proxy не должны достигать служебных сервисов узла (Redis, `:9090`, ClickHouse) через `GET http://127.0.0.1…` / `CONNECT 127.0.0.1:…` |
| `ALLOWED_CONNECT_PORTS` | `443` (+ согласованные, например `8443`) — **задать явно**, дефолта нет | без значения `CONNECT` разрешён на любой порт; ограничение как `SSL_ports` в Squid |
| `ALLOW_ANONYMOUS_PROXY` | не задавать | при `AUTH_ENABLED=false` без ACL default-deny + allow `IpRange` по клиентским подсетям proxy в production не стартует; `true` — осознанный opt-out |
| `MAX_REQUEST_BODY_BYTES` | `67108864` (64 MiB, default) | тело запроса буферизуется в RAM; сверх лимита — `413` |
| `UPSTREAM_CONNECT_TIMEOUT_MS` / `UPSTREAM_RESPONSE_TIMEOUT_MS` | `10000` / `60000` (default) | таймаут соединения и ожидания заголовков ответа upstream |
| `BASIC_AUTH_MAX_CONCURRENT_VERIFICATIONS` | по числу CPU (default) | ограничение параллельных Argon2-проверок; при флуде — ответ «overloaded» |
| `MITM_CIRCUIT_BREAKER_MIN_CLIENTS` / `MITM_CIRCUIT_BREAKER_COOLDOWN_SECS` | `3` / `900` (default) | trip только от ≥ 3 различных IP клиентов, авто-восстановление через 15 мин |
| `AGENT_API_ENABLED` / `AWG_API_ENABLED` / `LAB_API_ENABLED` | не задавать | в production lab-маршруты (agent, AmneziaWG, cluster, WASM, …) отвечают `404` |
| `PERF_FAST_CACHE_HIT` / `BSM_PERF_MODE` | не задавать (в production игнорируются) | режим отдаёт кэш **до** ACL и SSRF-проверки — небезопасен для SWG |
| `METRICS_BIND` | management-IP или `127.0.0.1` | не `0.0.0.0` |
| `DLP_ENABLED` | `false` | frozen-модуль вне GA |

---

## 7. Аутентификация пользователей

- GA: **Basic** (`AUTH_ENABLED=true`, `BASIC_AUTH_USERS_FILE`, Argon2id; пароли
  генерирует `scripts/gen-basic-auth-user.sh`). Proxy-Authorization по Basic
  передаётся base64 — клиентский сегмент должен быть доверенным.
- LDAP/NTLM/Kerberos — beta: требуют сборки с соответствующей Cargo feature и
  интеграционного стенда ([authentication.md](../features/authentication.md)).
- Пример пользователей `config/basic-auth-users.example.json` содержит публичные
  хеши — в проде запрещён.
- **Без proxy-auth (`AUTH_ENABLED=false`)** пользователь не идентифицируется
  (имя берётся только из proxy-auth), политики строятся по IP/подсетям. В
  production такой режим требует ACL с `ACL_DEFAULT_ACTION=deny` и хотя бы одним
  включённым allow-правилом `IpRange` по клиентским подсетям, или явного
  `ALLOW_ANONYMOUS_PROXY=true`. Deny-правила по IP прокси «закрытым» не делают.
- При флуде неверных паролей Basic может отвечать «overloaded» (семафор Argon2,
  `BASIC_AUTH_MAX_CONCURRENT_VERIFICATIONS`); per-IP backoff — 1.1.
- NTLM/Kerberos (beta) кэшируют результат аутентификации по IP клиента — не
  используйте их за NAT, терминальными серверами и VDI.

---

## 7a. Известные ограничения безопасности v1.0

Список сформирован по security-ревью релиз-кандидата; актуальное состояние —
раздел `Security` в [CHANGELOG.md](../../CHANGELOG.md) и
[roadmap](../roadmap.md). Компенсирующие меры обязательны:

| Ограничение | Компенсирующая мера | План |
|---|---|---|
| Control plane: один Bearer-токен на все операции, без RBAC; токен читается при старте (ротация = рестарт); аудит `config/apply` пишется только в лог | обращаться с `CONTROL_API_TOKEN` как с ключом CA: доступ только у security-админов, только через TLS reverse proxy; логи proxy — в SIEM | 1.1 (RBAC, audit log, TLS/OIDC) |
| MITM circuit breaker: три сговорившихся клиента (разных IP) могут на 15 минут (`MITM_CIRCUIT_BREAKER_COOLDOWN_SECS=900`) перевести домен в blind `CONNECT` — без инспекции | алерт на `increase(bsdm_proxy_mitm_circuit_breaker_trips_total[5m]) > 0`, разбор trip'а и ручной reset ([runbook § 2](../ops-and-dev/runbook.md#2-mitm-circuit-breaker-сработал)); узкий `MITM_CATEGORIES` | 1.1 (классы TLS-alert, fail-closed для malware/phishing) |
| Admin Console `config/apply` не меняет адреса назначения (ICAP, LDAP, OIDC, Kafka, ClickHouse, Redis, вебхуки, AI-бэкенды, peers, фиды, RKN), `*_BIND`, eBPF и токены; значения с `\`, кавычками и пробелами по краям отклоняются | такие параметры и секреты — правкой env-файла / Secret на хосте и рестартом | 1.1 (отдельный security-scope токен) |
| `CONNECT`: порт и IP-литералы проверяются до `200`, а адрес, полученный резолвом имени, — уже после (туннель рвётся без `403`) | норма для клиента; мониторить отказы в логах/метриках | 1.1 |
| `ALLOWED_CONNECT_PORTS` без дефолта — `CONNECT` на любой порт | задать `ALLOWED_CONNECT_PORTS=443` (+ согласованные) | 1.1 (дефолт и разделение портов) |
| События аналитики содержат URL расшифрованных запросов (включая query); Kafka и ClickHouse — без TLS/SASL | доступ к Kafka/ClickHouse/Search API — только SOC; изолированная сеть; retention и доступ — решение DPO (DPIA) | 1.1 (privacy-профили, TLS/SASL) |
| cache-indexer: ingest по существующему `event_id` перезаписывает событие | отдельный `INGEST_API_TOKEN`, известный только proxy | 1.1 (append-only) |
| `POLICY_MODE=sni` фильтрует authority из `CONNECT`, а не SNI из ClientHello | доменные deny-правила дополнять правилами по IP; `CONNECT` к голым IP ограничивать ACL | 1.1 |
| Basic auth: нет per-IP backoff — флуд неверных паролей вытесняет легитимные входы («overloaded»), без OOM | rate limit / firewall на `:3128`; мониторинг `bsdm_proxy_auth_password_verifications_total{result="failure"}` | 1.1 |
| dns-sinkhole DoT/DoH: лимиты только глобальные (`DNS_SINKHOLE_MAX_TCP_CONNECTIONS=512`, `DNS_SINKHOLE_MAX_INFLIGHT=1024`), без лимита на IP | DoH/DoT вне GA и выключены; UDP — только во внутренней сети | 1.1 |
| Нет таймаута на чтение тела ответа upstream (slow-drip); есть только connect (10 с) и до заголовков (60 с) | мониторинг `bsdm_proxy_upstream_connections_active`, `requests_in_flight` | 1.1 |
| RPZ-фиды по `http://` допускаются (подмена фида при MITM) | подключать фиды только по `https://`; `dryRun` перед применением | 1.1 |
| MISS-путь схлопывает несколько `Set-Cookie` upstream в один | известный функциональный баг: при проблемах входа на сайты с несколькими cookie — проверить через `X-Cache-Status`; приватные ответы при этом не кэшируются | 1.0.x |
| Reverse-proxy режим (frozen) не проверяет `Host` | reverse proxy вне GA, не включать | при выходе из Scope Freeze |
| Гонка двух одновременных enroll с одним новым `device_id` (agent, lab) | agent API выключен в production (`404`) | 1.2 |
| NTLM/Kerberos (beta) кэшируют аутентификацию по IP клиента | не использовать за NAT/VDI/терминальными серверами; фичи вне GA | блокер GA auth-ntlm/kerberos (1.2) |
| `kerberos_keytab` распространяется под AGPL-3.0; `rsa` (Marvin, RUSTSEC-2023-0071) через `sspi` | не собирать `auth-kerberos`/`auth-ntlm` для дистрибуции без юр. решения | 1.2 |
| Experimental DLP пропускает сигнатуры на границе chunk | DLP вне GA, выключен | при выходе из Scope Freeze |
| `rustls-pemfile` unmaintained (RUSTSEC-2025-0134, warning) | недостижимо как уязвимость; отслеживается cargo-deny | 1.1 |

Исправленные в RC находки — SSRF по разрешённым адресам, приватные ответы в
кэше, Host ≠ authority, лимиты тел, allowlist ключей `config/apply`, CA
fail-closed, breaker от ≥ 3 клиентов с cooldown, open-proxy guard, lab-маршруты
`404`, раздельный search-токен, hardening dns-sinkhole и cache-indexer —
перечислены в разделе `Security` CHANGELOG `[1.0.0-rc.1]`.

---

## 8. Мониторинг и алерты

Минимальный набор, который должен быть подключён до go-live (Prometheus +
Alertmanager → дежурный канал):

| Сигнал | PromQL / источник | Порог (стартовый) |
|---|---|---|
| Proxy недоступен | `up{job=~".*proxy.*"} == 0` | 1 мин |
| Ошибки upstream | `rate(bsdm_proxy_upstream_errors_total[5m]) / rate(bsdm_proxy_upstream_requests_total[5m])` | > 5% 10 мин |
| Латентность | `histogram_quantile(0.95, sum by (le) (rate(bsdm_proxy_request_duration_seconds_bucket[5m])))` | > SLO 10 мин |
| Перегрузка | `bsdm_proxy_requests_in_flight`, CPU контейнера/юнита | > 70% CPU 15 мин |
| MITM breaker trip | `increase(bsdm_proxy_mitm_circuit_breaker_trips_total[5m]) > 0` (`BsdmMitmBreakerTripped`) | любой trip — разбор дежурным |
| Доля bypass | `increase(bsdm_proxy_policy_decision_source_total{source="pinning-bypass"}[15m])` | рост без известной причины |
| Потеря событий | `rate(bsdm_proxy_kafka_queue_dropped_total[5m]) > 0`, `rate(bsdm_proxy_kafka_send_errors_total[5m]) > 0` | 5 мин |
| Индексация | `rate(cache_indexer_insert_errors_total[5m]) > 0` | 10 мин |
| DNS sinkhole | `up{job=~".*dns.*"} == 0`, `rate(dns_sinkhole_errors_total[5m])` | 1 мин / рост |
| Rate limit / ACL | `bsdm_proxy_rate_limit_rejected_total`, алерт `BsdmProxyAclDenyBurst` | всплеск |
| Инварианты скоупа | `bsdm_proxy_ebpf_armed != 0`, алерт `BsdmTiEnforcementActive` | немедленно |
| Срок CA | `bsdm_proxy_mitm_ca_not_after_timestamp_seconds - time()` (`BsdmMitmCaExpiringSoon`) | < 30 / < 7 дней |
| Диск | spill, ClickHouse, Kafka volume | > 70% / 85% |

Готовые правила: [`prometheus/alerts/mitm.yml`](../../prometheus/alerts/mitm.yml) —
`BsdmMitmBreakerTripped` (любой trip) и `BsdmMitmCaExpiringSoon` (warning < 30 дней,
critical < 7 дней); прочие в [`prometheus/alerts/`](../../prometheus/alerts/) (alert-worker,
TI shadow) и Grafana-дашборды в [`grafana/dashboards/`](../../grafana/dashboards/).
Логи: JSON-формат и уровни — [logging.md](../ops-and-dev/logging.md).

---

## 9. Бэкапы и восстановление

| Актив | Частота | Метод | RPO / RTO (по умолчанию) |
|---|---|---|---|
| `ca.key`/`ca.crt` + `certs/archive/` | при выпуске/ротации | зашифрованный архив, vault, dual control | 0 / ≤ 1 ч |
| `bsdm-proxy.env`, секреты | при изменении | secret store | — |
| ACL (`ACL_RULES_PATH`), pinning exceptions, RPZ state (`DNS_RPZ_STATE_DIR`) | ежедневно + при изменении | файловый бэкап / GitOps | ≤ 24 ч |
| Аудит (`PINNING_AUDIT_LOG_PATH`, `rpz-audit.jsonl`, `TI_SOAR_AUDIT_PATH`) | ежедневно | ship в SIEM / WORM | ≤ 24 ч |
| ClickHouse `bsdm` | ежедневно | `scripts/backup-clickhouse.sh` (Native + `COUNTS.txt`) | ≤ 24 ч / ≤ 4 ч |
| Kafka, Prometheus TSDB | не требуется | короткий retention | — |

Восстановление проверяется учением до go-live и затем ежеквартально:
[backup-restore.md](../ops-and-dev/backup-restore.md),
[pilot-drills-runbook.md](../ops-and-dev/pilot-drills-runbook.md). Бэкап, который ни
разу не восстанавливали, бэкапом не считается.

---

## 10. Обновление и откат

Политика:

- **Patch (1.0.x)** — совместим по конфигурации и схеме, rolling update.
- **Minor (1.x)** — может добавлять переменные и колонки ClickHouse (только
  аддитивно, `ADD COLUMN IF NOT EXISTS` применяет cache-indexer при старте);
  читайте release notes.
- Схема ClickHouse не откатывается: новые колонки остаются, старая версия их
  игнорирует.

Процедура (все варианты):

1. Прочитать `CHANGELOG.md` / release notes, проверить подпись артефактов (§3.4).
2. Бэкап: CA, env/секреты, ACL/pinning/RPZ state, свежий дамп ClickHouse.
3. Прогон на staging с prod-флагами + smoke (`/health`, `/ready`, HTTPS через MITM,
   Search API).
4. Обновление:
   - Compose: `BSDM_IMAGE_TAG=<new>` → `pull` → `up -d` (proxy рестартует с
     `SHUTDOWN_TIMEOUT_SECONDS`, при одном узле — окно обслуживания);
   - Helm: `helm upgrade --atomic` (RollingUpdate + PDB, `preStop` drain);
   - systemd: `install-release.sh --version <new>` → `systemctl restart bsdm-proxy`.
5. Наблюдение 30 минут: ошибки upstream, p95, `pinning-bypass`, Kafka drops.

Откат: вернуть предыдущий тег/версию тем же способом (`helm rollback bsdm <rev>`,
`BSDM_IMAGE_TAG=<old>`, `install-release.sh --version <old>`), восстановить
конфигурацию из бэкапа шага 2. Подробно — [runbook § 7](../ops-and-dev/runbook.md#7-откат-релиза)
и [upgrade guide](../ops-and-dev/upgrade-guide.md).
