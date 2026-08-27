# Анализ конфигураций по CIS Benchmarks (2026-08-27)

Статический аудит конфигураций репозитория по применимым CIS Benchmarks:

| Бенчмарк | Область | Файлы |
|---|---|---|
| CIS Docker Benchmark v1.6/1.7 (разделы 4, 5) | Образы и рантайм контейнеров | `Dockerfile`, `proxy/Dockerfile`, `cache-indexer/Dockerfile`, `docker-compose.yml`, `deploy/compose/*` |
| CIS Kubernetes Benchmark v1.9 (раздел 5 Policies) + Pod Security Standards | Helm-чарт | `charts/bsdm/**` |
| CIS NGINX Benchmark | Reverse-proxy для Search API | `config/search-cors.nginx.conf` |
| CIS Distribution Independent Linux (элементы) | Установка, systemd, CA, секреты | `packaging/**`, `scripts/installer/**`, `scripts/*.sh`, `bsdm-proxy.env` |

Инструменты (`trivy`, `hadolint`, `kube-score`, `checkov`, `helm`, `nginx -t`, `systemd-analyze security`)
в среде аудита недоступны — анализ выполнен ручным чтением файлов. Изменения в конфигурации
не вносились; документ фиксирует находки.

## Сводная статистика

| Область | PASS | FAIL | WARN | N/A |
|---|---|---|---|---|
| Docker (Dockerfile + compose) | 8 | 10 | 5 | 0 |
| Kubernetes (Helm-чарт) | 17 | 10 | 14 | 3 |
| NGINX | 0 | 15 | 8 | 1 |
| Linux / установка / systemd | 24* | 14 | 12 | 0 |

\* включая 3 PARTIAL PASS.

Соответствие Pod Security Standards: `baseline` — да, `restricted` — **нет** (блокирует отсутствие `seccompProfile`).

---

## Статус исправлений

Документ фиксирует результат аудита на 2026-08-27 и намеренно не переписывается
по мере исправлений. Ниже — что закрыто с тех пор.

**Закрыто:**

- `SYS_MODULE` у amneziawg; `cap_drop: [ALL]` + `no-new-privileges`, `pids`,
  cpu/memory лимиты и `read_only` во всех compose-стеках; не-data-plane порты
  привязаны к loopback; Grafana fail-closed; образы пиннуты; legacy-Dockerfile'ы
  удалены.
- Helm-чарт доведён до PSS `restricted`: `seccompProfile`, отключён automount
  SA-токена, секреты перенесены в Secret, NetworkPolicy покрывает все workload'ы,
  исправлен баг с `monitoringNamespace`.
- systemd: профиль hardening распространён на все юниты; закрыта инъекция в
  unit-файл через `--prefix`; `umask 077` до генерации CA; секреты убраны из argv;
  CA переехал в `/etc/bsdm-proxy/certs`.
- nginx: bind на loopback, CORS-whitelist, security-заголовки, лимиты и таймауты.
- Пароли: несолёный SHA-256 заменён на Argon2id с версионированными хешами и
  прозрачной миграцией при входе; файл пользователей пишется 0600.
- CA: срок сокращён до 2 лет, добавлены `basicConstraints=pathlen:0` и
  `keyUsage` (оба критические) — для вновь выпускаемых CA. Passphrase к ключу
  сознательно не добавляется: он ломает автостарт сервиса.
- Fail-open дефолты: `ICAP_FAIL_OPEN=false`, `*_ALLOW_INSECURE` в `:-false`,
  auth и ACL включены в эталонных конфигах.

**Осознанно не исправлено:**

- `ACL_DEFAULT_ACTION` остаётся `allow`. Поставляемый набор правил — blocklist
  (85 правил, все `deny`, ни одного `allow`), поэтому deny-дефолт заблокировал бы
  весь трафик, а не ужесточил политику; вдобавок значение из JSON-файла правил
  перекрывает эту переменную. Перевод ACL в fail-closed требует baseline из
  allow-правил и идёт отдельной работой.
- `curl | sudo bash` в `scripts/install-binaries.sh`: SHA-256 артефакта
  проверяется, но подписи (cosign/GPG) нет — это гейт релизного пайплайна,
  а не скрипта.
- `proxy/src/tls.rs` резолвит CA по захардкоженному `/certs`; переезд прикрыт
  симлинком, настоящий фикс — переменная `MITM_CA_DIR`.
- Нет сигнализации об истечении CA. При сроке 2 года это главный операционный
  риск: нужна метрика срока и алерт.

## Критические и высокоприоритетные находки (сводный топ)

1. **[CRITICAL] `SYS_MODULE` у amneziawg** — `deploy/compose/docker-compose.awg.yml:24-26`. Возможность загрузки модулей ядра = эквивалент root на хосте, у стороннего `:latest`-образа с UDP-портом наружу. Убрать capability, грузить модуль на хосте; оставить только `NET_ADMIN` + `cap_drop: [ALL]`.
2. **[HIGH] `Authorization` по plaintext HTTP на 0.0.0.0** — `config/search-cors.nginx.conf:3,22`. Токен Search API уходит открытым текстом. TLS либо `listen 127.0.0.1:80`.
3. **[HIGH] CORS reflect-any-Origin + credentials** — `search-cors.nginx.conf:8,11,25,26`. Любой сайт в браузере оператора читает Search API от его имени. Whitelist через `map`.
4. **[HIGH] Fail-open дефолты control-plane в compose** — `docker-compose.yml:115-119,133-136,195`, `deploy/compose/docker-compose.lite.yml:31`: `MITM_ENABLED=true` при `AUTH_ENABLED=false`, `ACL_DEFAULT_ACTION=allow`, `*_ALLOW_INSECURE=true`, порт 9090 на всех интерфейсах. Эталонный `bsdm-proxy.env` задаёт безопасные значения — привести compose к нему.
5. **[HIGH] Секреты в ConfigMap** — `charts/bsdm/templates/indexer-configmap.yaml:24-26` (`SEARCH_API_TOKEN`), `configmap-env.yaml:39-41` (`PHISHTANK_API_KEY`). Перенести в Secret + `secretKeyRef`.
6. **[HIGH] Plaintext-fallback секретов в PodSpec** — `indexer-deployment.yaml:49-52` (пароль ClickHouse), `threat-intel-deployment.yaml:55-59` (SOAR-токен). Оставить только ветки `existingSecret`, иначе `fail`.
7. **[HIGH] `automountServiceAccountToken` не отключён** — все 6 podSpec + `serviceaccount.yaml`. RBAC пустой, K8s API компонентам не нужен; токен в поде MITM-прокси — готовая цепочка эскалации. Выставить `false`.
8. **[HIGH] Нет `seccompProfile: RuntimeDefault`** — `charts/bsdm/values.yaml:28-38`. В restricted-namespace admission отклонит все 6 Deployment'ов.
9. **[HIGH] `no-new-privileges` и `cap_drop: [ALL]` отсутствуют во всех compose-сервисах** (CIS 5.25/5.3). Для `dns-sinkhole` понадобится `cap_add: [NET_BIND_SERVICE]` (bind :53 под uid 1000).
10. **[HIGH] Пять systemd-юнитов из шести без hardening** — `packaging/systemd/bsdm-{proxy,cache-indexer,alert-worker,ml-worker}.service`, `packaging/agent/systemd/bsdm-agent.service` содержат только `User=` и `NoNewPrivileges=`. Эталонный блок (13/13 директив) уже есть в `bsdm-threat-intel.service:22-44` — скопировать с поправкой на `ReadWritePaths` и capabilities для eBPF у proxy.
11. **[HIGH] Инъекция в unit-файл через `--prefix`** — `packaging/install.sh:140-142`: невалидированный `PREFIX` подставляется `sed`-ом в systemd-юнит, исполняемый root. Валидатор `validate_install_path()` уже существует в `scripts/installer/common.sh` — вызвать его.
12. **[HIGH] `curl | sudo bash` без подписи артефактов** — `scripts/install-binaries.sh:6`; SHA-256 проверяется (:106-114), но с того же хоста, подписи (cosign/GPG) нет.
13. **[HIGH] Root-контейнеры в legacy Dockerfile** — `proxy/Dockerfile`, `cache-indexer/Dockerfile`: нет `USER`, нет `HEALTHCHECK`; дублируют unified `Dockerfile`. Лучше удалить.

## Средний приоритет

- **Docker**: memory-лимит отсутствует у `alertmanager` и во всех `deploy/compose/*`; CPU-лимиты только в `pilot.yml`, не в базовом compose; `pids_limit` нигде; `read_only: true` нигде (для bsdm-сервисов внедряется дёшево — пишущие пути уже в томах); базовые образы не пиннуты по digest (`rust:alpine` вообще без версии; `:latest` у ICAP/AWG/httpbin/GHCR); чувствительные порты (ClickHouse 8123/9000 без пароля, Kafka 9092 PLAINTEXT, Grafana admin/admin :3000, Prometheus с `--web.enable-lifecycle`, Redis без пароля) опубликованы на 0.0.0.0 — привязать к 127.0.0.1.
- **Kubernetes**: NetworkPolicy выключена по умолчанию и покрывает только proxy/threat-intel (indexer/alert-worker/ml-worker/dns-sinkhole открыты любому поду кластера); нет default-deny; egress :53 разрешён куда угодно (DNS-эксфильтрация); ingress `ipBlock 10.0.0.0/8` включает pod CIDR; баг: `networkpolicy.yaml:27` игнорирует `networkPolicy.monitoringNamespace` (захардкожен `monitoring`).
- **NGINX**: нет `server_tokens off`, лимитов и таймаутов (`client_*_timeout`, `proxy_*_timeout`, `limit_req`), security-заголовков (XFO, nosniff, CSP, Referrer-Policy), ограничения методов; `Vary: Origin` отсутствует в preflight-ветке.
- **Linux/установка**: гонка прав при генерации MITM CA (`installer/common.sh:139-146`, `install-binaries.sh:136-143` — нет `umask 077` до `openssl`, в отличие от эталонного `gen-ca.sh:30`); 10-летний CA без passphrase и без `pathlen:0`/keyUsage-ограничений; CA в `/certs` (вне FHS); несолёный SHA-256 для паролей + пароль в argv (`gen-basic-auth-user.sh`); токены агента в argv установщиков (`packaging/agent/install-linux.sh:43-44`, fleet); `EnvironmentFile=-` (silent-fail → старт на встроенных дефолтах); fail-open дефолты `ACL_DEFAULT_ACTION=allow`, `ICAP_FAIL_OPEN=true` в `bsdm-proxy.env`; `HTCP_BIND`/`DOH_BIND`/`DOT_BIND` на 0.0.0.0.

## Что уже хорошо

- Unified `Dockerfile`: non-root `USER bsdm`, минимальный рантайм, `COPY` вместо `ADD`, `HEALTHCHECK` на всех стадиях, нет секретов, нет docker.sock-маунтов, нет `privileged`/`pid: host`, выделенные bridge-сети, нет привилегированных хост-портов.
- Helm-чарт проходит PSS `baseline`: `runAsNonRoot`, `drop: [ALL]`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem`, resources у всех, только ClusterIP, probes/PDB/HPA, нет hostPath, mitm-секрет монтируется файлом с `0440`.
- `scripts/gen-ca.sh` / `rotate-ca.sh` — образцовые: `umask 077`, `chmod 600`, проверка прав ключа перед использованием, атомарная ротация с rollback, валидация CN.
- `bsdm-threat-intel.service` — полный systemd-hardening (эталон для остальных юнитов).
- Секреты не закоммичены; установщики используют `set -euo pipefail`, `mktemp`+`trap`, не печатают секреты, не перезатирают существующие.

## Рекомендуемые CI-гейты

Находки выше ловятся автоматически; в пайплайне их сейчас нет:

- `hadolint` для Dockerfile; `trivy config` для compose/Helm (IaC);
- `trivy image --exit-code 1 --severity HIGH,CRITICAL` + SBOM + подпись образов (cosign) — закрывает CIS 4.11;
- запрет-паттерны в CI: `privileged`, `docker.sock`, `cap_add: SYS_*` (регресс с `SYS_MODULE` прошёл ревью незамеченным);
- `helm template | kube-score` / `checkov` для чарта.

---

Подробные потабличные результаты по каждой проверке (ID CIS, статус, файл:строка,
доказательство, рекомендация) зафиксированы в сессии аудита; данный документ — сводка
для приоритизации. Исправления предлагается вносить отдельными PR по областям
(compose-hardening, chart-hardening, systemd-hardening, nginx, installer).
