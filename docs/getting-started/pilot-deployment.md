# Пилот: Hybrid Policy (Selective MITM)

Референсный **Phase B** профиль для функционального пилота ~100 пользователей
на одном сервере. Цель — скучный, воспроизводимый подъём **без experimental
модулей** и без «племенного знания».

Связанные артефакты:

| Артефакт | Назначение |
|---|---|
| [`docker-compose.pilot.yml`](../../docker-compose.pilot.yml) | Hybrid defaults + resource caps + 5-day retention |
| [Load-test profile](../ops-and-dev/load-test-selective-mitm.md) | 100-user Hybrid нагрузка (#269) |
| [CA lifecycle](../ops-and-dev/ca-lifecycle.md) | Выпуск / ротация MITM CA |
| [Project status](../project-status.md) | Зрелость функций |

Issue tracking: **#270** (этот документ + compose), **#269** (load-test).

---

## Что входит в пилот (Hybrid core)

| Компонент | Статус в пилоте |
|---|---|
| HTTP/HTTPS forward proxy, CONNECT | **Да** |
| `POLICY_MODE=selective-mitm` | **Да** (default) |
| Selective MITM по `MITM_CATEGORIES` | **Да** |
| SNI path (без расшифровки) | **Да** |
| ACL | **Да** (`ACL_ENABLED=true` в pilot overlay) |
| Auth (Basic/LDAP/…) | **Опционально** (`AUTH_ENABLED`) |
| Categorization / UT1 | **Опционально** (включать после подготовки feeds) |
| L1 cache + spill | **Да** |
| Kafka → cache-indexer → ClickHouse → Search API | **Да** (base compose) |
| Prometheus / Grafana | **Да** |
| DNS sinkhole (UDP) | **Да (day-1)** — сервис `dns-sinkhole` в base compose; host **:5353** (на macOS часто **:15353** — mDNS занимает 5353; см. [pilot-dns.md](pilot-dns.md)) |
| Admin Console `/admin/` | **Да** — SPA встроена в proxy image (`ADMIN_CONSOLE_DIR=/opt/bsdm/admin-console`), URL `http://localhost:9090/admin/` |

## Что **не** входит (по умолчанию выключено)

Experimental / frozen scope — **не** поднимать в первом пилоте:

- ICAP / ClamAV (`--profile icap`)
- AmneziaWG / BSDM Connect
- eBPF / XDP
- WASM plugins как security boundary
- Standalone Trust-UI (`--profile experimental-trust-ui`)
- Global session / threat-sync multi-node scaffolding
- DLP/CASB enforcement (engine может существовать в процессе — см. ниже)
- Production HA / multi-cluster

Alert-worker и ml-worker — **второй шаг** (`--profile alerts` / `ml`), не часть
«дня 1» Hybrid core.

### DLP

Pilot overlay sets **`DLP_ENABLED=false`** (default in code as well). No control-API
wipe is required on restart. To evaluate experimental signatures in a lab only:

```bash
export DLP_ENABLED=true
# optional runtime clear (not persisted):
curl -X POST http://127.0.0.1:9090/api/security/dlp \
  -H "Authorization: Bearer ${CONTROL_API_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data '[]'
```

---

## Acceptance criteria (что значит «пилот успешен»)

### A. Stand-up

- [ ] `docker compose -f docker-compose.yml -f docker-compose.pilot.yml up -d --build` поднимает proxy, kafka, clickhouse, cache-indexer, prometheus, grafana, dns-sinkhole
- [ ] `GET :9090/health` и `GET :9090/ready` → ok
- [ ] `GET :9090/admin/` → Admin Console SPA (встроена в image)
- [ ] `GET :8080/health` (indexer) → ok; Search API: `GET :8080/api/search?limit=1` с `Authorization: Bearer $SEARCH_API_TOKEN`
- [ ] Admin Console → Settings → Console API: **single endpoint** `http://localhost:9090` + Control token (Search same-origin via control-plane proxy to indexer; optional advanced Search `:8080`)
- [ ] Experimental profiles **не** указаны в команде запуска
- [ ] Заданы `CONTROL_API_TOKEN`, `ACL_API_TOKEN`, `SEARCH_API_TOKEN` (не дефолтные пустые в проде)
- [ ] `CONTROL_API_ALLOW_INSECURE` / `SEARCH_API_ALLOW_INSECURE` **не** `true` на пилоте
- [ ] Control/metrics не торчат в internet (firewall / `METRICS_BIND` / private network) — см. [control-plane-security.md](../ops-and-dev/control-plane-security.md)
- [ ] `DLP_ENABLED=false` (default) — no post-start DLP wipe required
- [ ] ACL persist: `ACL_RULES_PATH` указывает на **writable** path (каталог, не single-file `:ro` mount — иначе `*.tmp` Permission denied). Рекомендация: volume `/etc/bsdm-proxy` или `/var/lib/bsdm-proxy/acl-rules.json`
- [ ] `CONFIG_ENV_PATH` (Settings → Apply) — writable path, не cwd `/` в контейнере
- [ ] Admin Settings → **Reload from node** before Apply; Apply is a **delta** (won't dump form defaults over pilot paths). ACL file rewrite from Filtering checkboxes is **opt-in** — manage rules under **Policies**
- [ ] Backup/restore drill once: `./scripts/drill-backup-restore.sh` (or CA-only with `SKIP_CLICKHOUSE=1`) — [backup-restore.md](../ops-and-dev/backup-restore.md)
- [ ] If auth is on: `BASIC_AUTH_USERS_FILE` mounted + `./scripts/run-auth-pilot-smoke.sh` green — [pilot-auth.md](pilot-auth.md)
- [ ] DNS: `./scripts/run-dns-pilot-smoke.sh` green (blocked.test / badsite.test / example.com) — [pilot-dns.md](pilot-dns.md)
- [ ] Admin Console: primary nav only Hybrid pages; frozen routes show Frozen banner; mutations blocked without token (Settings → Console API)
- [ ] Observability: Dashboard decision_source bar + Logs filter; optional alert-worker pilot pack ([pilot-alerts.md](pilot-alerts.md))
- [ ] Optional Phase C lab: `./scripts/run-agent-pilot-smoke.sh` green — [pilot-agent.md](pilot-agent.md)
- [ ] Optional day-2+ ML: `--profile ml` + `./scripts/run-ml-pilot-smoke.sh` — [pilot-ml.md](pilot-ml.md)

### B. Hybrid path

- [ ] `POLICY_MODE=selective-mitm`, `DEPLOYMENT_PROFILE=production`
- [ ] `full-mitm` **не** используется (и не проходит без `ALLOW_FULL_MITM`)
- [ ] MITM CA установлен на тестовых клиентах; `curl --cacert certs/ca.crt -x … https://…` работает
- [ ] Pinning exceptions registry смонтирован (`PINNING_EXCEPTIONS_PATH`)
- [ ] В метриках есть `bsdm_proxy_policy_decision_source_total` (после трафика)

### C. Observability

- [ ] События попадают в ClickHouse / Search API (`/api/search?limit=5`)
- [ ] Prometheus scrape proxy metrics
- [ ] Retention: ClickHouse pilot TTL 5d, Prometheus `5d`, Kafka ≤ 48h

### D. Load probe

- [ ] Прогнан `./scripts/run-hybrid-load-test.sh` (100 users / ≥30s)
- [ ] Отчёт в `docs/ops-and-dev/load-test-results/` (или локальный latest.md)
- [ ] Error rate и latency p95/p99 записаны; proxy не упал

### E. Out of scope explicit

- [ ] ICAP / AWG / eBPF / WASM **не** включены
- [ ] Agent UI / production multi-OS agent **не** требуется для pass (lab spike optional — [pilot-agent.md](pilot-agent.md))

---

## Нагрузочная модель

| Параметр | Расчётное значение |
|---|---:|
| Именованные пользователи | 100 |
| Одновременно активные | 50–70 |
| Средняя нагрузка | 3–6 proxy requests/s |
| Расчётный пик | 50–100 proxy requests/s |
| События | до 500 000 в сутки |
| HTTPS MITM | **селективно** (категории), не 100% |
| Рабочий трафик | 100–200 Mbit/s |
| Горячее хранение | ≤ 5 суток |

Методика и скрипт: [load-test-selective-mitm.md](../ops-and-dev/load-test-selective-mitm.md).

---

## Ресурсы (один Linux-хост)

| Профиль | vCPU | RAM | NVMe | Сеть |
|---|---:|---:|---:|---:|
| Минимальный функциональный | 8 | 16 GiB | 150 GB | 1 Gbit/s |
| **Рекомендуемый** | **12** | **24 GiB** | **200 GB** | **1 Gbit/s** |
| С запасом для load-test | 12–16 | 32 GiB | 250 GB | 1 Gbit/s |

### Бюджет контейнеров (pilot overlay)

| Компонент | vCPU | RAM |
|---|---:|---:|
| proxy | 4 | 4 GiB |
| ClickHouse | 3 | 6 GiB |
| Kafka + ZK | ~1.5 | ~3 GiB |
| cache-indexer | 0.5 | 512 MiB |
| Prometheus + Grafana | ~1.25 | ~2.5 GiB |

---

## Compose override

[`docker-compose.pilot.yml`](../../docker-compose.pilot.yml) задаёт:

- Hybrid: `POLICY_MODE=selective-mitm`, `MITM_CATEGORIES`, production profile
- ACL on by default; auth/categorization off until configured
- Resource limits (~12 vCPU / ~18 GiB container budget)
- Prometheus retention 5d, Kafka 48h, ClickHouse pilot TTL SQL
- Отдельный spill volume

```bash
export CONTROL_API_TOKEN="$(openssl rand -hex 16)"
export ACL_API_TOKEN="$(openssl rand -hex 16)"
export SEARCH_API_TOKEN="$(openssl rand -hex 16)"

# Optional auth (Basic users file — see pilot-auth.md; example password pilot-secret):
# export AUTH_ENABLED=true
# export BASIC_AUTH_USERS_HOST=./config/basic-auth-users.example.json
# export CATEGORIZATION_ENABLED=true
# export UT1_ENABLED=true

./scripts/gen-ca.sh
docker compose \
  -f docker-compose.yml \
  -f docker-compose.pilot.yml \
  up -d --build
```

Не коммитьте секреты и не кладите токены в shell history production-хоста.

### Стартовый env proxy (канон)

```env
DEPLOYMENT_PROFILE=production
POLICY_MODE=selective-mitm
MITM_ENABLED=true
MITM_CATEGORIES=malware,phishing,illegal-content

WORKER_COUNT=2
CACHE_CAPACITY=20000
CACHE_SHARDS=16
CACHE_TTL_SECONDS=3600
CACHE_SPILL_THRESHOLD_BYTES=262144
CACHE_SPILL_DIR=/var/cache/bsdm-spill
CACHE_COMPRESSION=zstd
MAX_CACHE_BODY_SIZE=4194304

KAFKA_SAMPLE_RATE=0
METRICS_SAMPLE_RATE=10
STREAMING_MISS_ENABLED=true

ACL_ENABLED=true
AUTH_ENABLED=false
CATEGORIZATION_ENABLED=false
```

`CACHE_CAPACITY` — общее число записей L1 на процесс (делится между шардами).

---

## Хранение ≤ 5 суток

Pilot overlay монтирует
[`pilot_retention.sql`](../../scripts/clickhouse/pilot_retention.sql) на **новый**
volume. Для уже инициализированного ClickHouse примените TTL вручную (см. SQL в
том же файле) до приёмочного трафика.

Дополнительно:

- Kafka retention 24–48h
- Prometheus `--storage.tsdb.retention.time=5d`
- spill: отдельный volume, лимит 25–30 GB на хосте

---

## Запуск и smoke

```bash
docker compose -f docker-compose.yml -f docker-compose.pilot.yml ps

curl -fsS http://127.0.0.1:9090/health
curl -fsS http://127.0.0.1:9090/ready
curl --cacert certs/ca.crt -x http://127.0.0.1:3128 https://httpbin.org/get
curl -fsS 'http://127.0.0.1:8123/?query=SELECT+count()+FROM+bsdm.http_cache'
curl -fsS 'http://127.0.0.1:8080/api/search?limit=5' \
  -H "Authorization: Bearer ${SEARCH_API_TOKEN}"
```

Load probe:

```bash
CONCURRENT_USERS=100 TEST_DURATION=60 ./scripts/run-hybrid-load-test.sh
```

### Второй шаг (не день 1)

```bash
export ALERT_WEBHOOK_URL='https://siem.example.invalid/bsdm'
export ML_MODEL='ueba_zscore_v0'
docker compose \
  -f docker-compose.yml \
  -f docker-compose.pilot.yml \
  --profile alerts --profile ml \
  up -d --build
```

---

## Критерии пересмотра сайзинга

Увеличивайте ресурсы или разделяйте plane, если:

- CPU proxy > 70% более 15 минут;
- host RAM > 80% или swap;
- Kafka consumer lag растёт непрерывно;
- ClickHouse merges не успевают;
- p95 добавленной latency выше вашего SLO;
- стабильный трафик > 300 Mbit/s;
- spill > 70% выделенного диска.

Следующий шаг после успешного пилота — две реплики proxy и отдельный analytics
host (по измерениям, не по линейному масштабу «×N пользователей»).
