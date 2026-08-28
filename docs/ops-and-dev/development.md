# Разработка и тестирование

Руководство для разработчиков BSDM-Proxy.

## Требования

| Компонент | Версия |
|-----------|--------|
| Rust | **1.88+** (рекомендуется latest stable) |
| Cargo | stable |
| librdkafka | dev-пакет (`librdkafka-dev`) — только при сборке с feature `kafka` (default) |
| protoc | `protobuf-compiler` — только при сборке с feature `grpc` |
| OpenSSL | dev-пакет (`libssl-dev`) |

**Debian/Ubuntu:**
```bash
sudo apt-get install -y \
  libssl-dev pkg-config cmake librdkafka-dev libclang-dev protobuf-compiler
```

## Структура workspace

Полная карта репозитория: [structure.md](../architecture/structure.md).

```
bsdm-proxy/
├── proxy/              # Основной прокси (bin: proxy)
│   └── src/
│       ├── main.rs, proxy_service.rs, control_api.rs
│       ├── miss_coalesce.rs, semantic_cache.rs, threat_score_cache.rs
│       ├── hierarchy*, peers, icp/htcp, rate_limit, upstream, tls, metrics
│       └── lib.rs
├── cache-indexer/      # Kafka|HTTP → ClickHouse|SQLite + Search API
├── ml-worker/          # M5 features/scores + threat-score API
├── dns-sinkhole/       # Optional DNS RPZ-lite sidecar (P3)
├── threat-intel/       # Фоновый сбор фидов угроз (Shadow Mode)
├── alert-worker/       # M4 webhook alerts
├── bsdm-events/        # Shared CacheEvent types
├── bsdm-wasm-sdk/      # WASM plugin SDK
├── e2e/                # Smoke и E2E тесты
├── admin-console/      # Unified admin UI (React)
├── charts/bsdm/        # Helm chart для Kubernetes
├── config/             # Примеры ACL-правил
├── packaging/          # Release-пакет (systemd, install.sh)
├── scripts/            # build-package, run-*-tests, pre-push-check, clickhouse SQL
├── grafana/            # Datasources + dashboards (Prometheus, ClickHouse)
├── prometheus/         # Scrape config
├── deploy/compose/     # Профильные compose-файлы (lite, pilot, ha, ...)
└── docs/               # Документация
```

## Сборка

```bash
# Debug (default: auth-basic + kafka)
cargo build -p bsdm-proxy --bin proxy

# Optional gRPC control plane (needs protoc; runtime: CONTROL_GRPC_ENABLED=true)
cargo build -p bsdm-proxy --features grpc --bin proxy

# Optional Wasm plugin host (runtime: WASM_ENABLED + WASM_MODULE_PATH)
cargo build -p bsdm-proxy --features wasm --bin proxy

# Optional ICAP (runtime: ICAP_ENABLED + ICAP_URL) — always compiled; see docs/icap.md

# Lite — без rdkafka (HTTP EVENT_SINK only)
cargo build -p bsdm-proxy --no-default-features --features auth-basic --bin proxy
cargo build -p cache-indexer --no-default-features --bin cache-indexer

# Release (оба бинарника)
cargo build --release -p bsdm-proxy --bin proxy -p cache-indexer --bin cache-indexer
```

## Линтинг и форматирование

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

CI запускает `cargo fmt --check` — **перед каждым push** прогоняйте проверки:

```bash
./scripts/pre-push-check.sh
```

### Git pre-push hook (рекомендуется)

Автоматически запускает `fmt --check` и `clippy` перед `git push`:

```bash
./scripts/install-git-hooks.sh
```

Один раз пропустить: `git push --no-verify`

Проверка вручную без hook:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

### Единый CI-контракт

Команды CI не дублируются в Jenkinsfile и GitHub Actions. Переносимый entrypoint:

```bash
./scripts/ci/run.sh --help
./scripts/ci/run.sh rust-all
./scripts/ci/run.sh docs
RUN_UI_TESTS=0 ./scripts/ci/run.sh admin-console
./scripts/ci/run.sh release-validate
```

Для полного локального прогона без security audit, packaging и load test:

```bash
make ci
```

`security-audit` требует установленный `cargo-audit`, а `load-test` — Docker
Buildx/Compose, `curl` и `wrk`. Публикующие скрипты не входят в `make ci` и не
запускаются без отдельного release gate.

## Jenkins CI/CD

Корневой [Jenkinsfile](../../Jenkinsfile) предназначен для **Multibranch
Pipeline**. Branch и pull request builds запускают параллельные Rust, RustSec,
documentation и frontend gates. Load test и CD-стадии отделены параметрами.

### Требования к Jenkins

Минимальные controller plugins:

- Pipeline: Declarative и Git;
- Credentials Binding;
- Timestamper.

Рекомендуемые agent labels и содержимое:

| Label по умолчанию | Требования |
|---|---|
| `linux && bsdm-ci` | Rust 1.88+, Node.js 24+, Python 3, `cargo-audit`, native build packages |
| `linux && docker` | Docker Buildx/Compose, `curl`, `wrk`, доступ к Docker daemon |
| `linux && amd64 && bsdm-ci` | Native x86_64 package build |
| `linux && arm64 && bsdm-ci` | Optional native aarch64 package build |

Для Debian/Ubuntu Rust-agent нужны пакеты из раздела «Требования» выше. Для UI
smoke Chromium dependencies должны быть установлены в образе агента; сам browser
кэшируется Playwright в пользовательском каталоге.

Load-test wrapper перед запуском временно назначает сгенерированной CA владельца
`CA_RUNTIME_UID:CA_RUNTIME_GID` (по умолчанию `1000:1000`, пользователь контейнера)
и восстанавливает исходного владельца при cleanup. Если Docker-agent работает под
другим UID, ему нужен passwordless `sudo chown`; режимы каталога `700` и ключа
`600` не ослабляются.

Создайте Multibranch Pipeline, укажите GitHub repository и оставьте Script Path
`Jenkinsfile`. Для release jobs включите в GitHub Branch Source trait обнаружение
тегов: `buildingTag()` и `TAG_NAME` доступны только для tag branch. Значения labels
можно переопределить параметрами job без изменения репозитория.

### Параметры и release gates

| Параметр | По умолчанию | Поведение |
|---|---:|---|
| `RUN_UI_TESTS` | `true` | Chromium smoke для Admin Console |
| `RUN_LOAD_TESTS` | `false` | Lite/hybrid Docker profile и архив результата |
| `BUILD_PACKAGES` | `false` | Native amd64 package для non-tag build |
| `BUILD_ARM64_PACKAGE` | `false` | Дополнительная сборка на arm64-agent |
| `PUBLISH_GITHUB_RELEASE` | `false` | Публикация package artifacts только из tag build |
| `PUBLISH_GHCR_IMAGE` | `false` | Multi-platform Buildx push только из tag build |

Tag build всегда проверяет соответствие `vX.Y.Z` версии product crates,
`CHANGELOG.md`, `docs/releases/vX.Y.Z.md` и `Cargo.lock`, после чего собирает
amd64 package. Публикация требует одновременно tag build и явный boolean gate.
Существующий GitHub Release не перезаписывается; тег `latest` для GHCR обновляется
только стабильным релизом без prerelease suffix.

Credentials хранятся только в Jenkins Credentials Store:

| Credentials ID по умолчанию | Тип | Минимальные права |
|---|---|---|
| `bsdm-github-token` | Secret text | GitHub repository contents: write |
| `bsdm-ghcr` | Username with password/token | GitHub Packages: write |

Секреты подключаются через `withCredentials`, не передаются параметрами и не
сохраняются в artifacts. Для dry run включите только `BUILD_PACKAGES`; publish
flags оставьте выключенными.

Publish stages запускайте только на выделенных trusted agents без параллельных
untrusted jobs: credentials существуют в environment процесса во время binding.
Пока GitHub Actions `release.yml` и `docker-publish.yml` остаются включены, Jenkins
должен использоваться для CI и package dry run, а оба Jenkins publish flag должны
оставаться `false`. Перед переносом CD выберите один writer и отключите публикацию
во втором контуре, чтобы tag build не создавал конкурирующие releases/images.

## Тесты

### Workspace

```bash
cargo test --workspace --all-targets
```

Ожидаемый результат: зелёный suite (сотни unit/integration по workspace + e2e/smoke). Точное число — в CI.

### Smoke-тесты

In-process (поднимает proxy как subprocess):

```bash
./scripts/run-smoke-tests.sh
```

Против deploy/compose/docker-compose.test.yml:

```bash
docker compose -f deploy/compose/docker-compose.test.yml up -d --build
./scripts/run-smoke-tests.sh --external
```

**Ограничения external-режима:**
- `MITM_ENABLED=false` в test compose — HTTPS не кэшируется (CONNECT-туннель).
- Метрика `bsdm_proxy_requests_total` появляется после первого запроса через proxy.
- `./scripts/run-e2e-tests.sh --external` проверяет cache HIT для HTTPS — **может не пройти** без MITM; используйте in-process `./scripts/run-e2e-tests.sh`.

> Proxy Alpine image includes **wget** (not curl). Healthchecks in compose files use
> `wget -q -O- http://127.0.0.1:9090/health | grep -q ok`.

Покрытие: `/health`, `/ready`, `/metrics`, HTTP forward через прокси.

### E2E-тесты

```bash
./scripts/run-e2e-tests.sh
```

| Тест | Что проверяет |
|------|---------------|
| `e2e_cache_hit_on_repeat_request` | L1 cache HIT |
| `e2e_auth_requires_proxy_authorization` | 407 без auth, 200 с auth |
| `e2e_acl_denies_blocked_domain` | ACL deny |
| `e2e_connect_tunnel_establishes_tcp_path` | HTTP CONNECT без MITM |
| `e2e_mitm_https_with_self_signed_ca` | MITM + самоподписанный upstream CA |
| `e2e_upstream_tls_accepts_test_ca` | Прямой HTTPS к mock upstream |
| `e2e_hierarchy_parent_fetch_on_child_miss` | Child → parent peer fetch |
| `e2e_hierarchy_sibling_icp_hit` | Child → sibling ICP HIT |
| `e2e_hierarchy_parent_serves_cached_response_to_child` | Parent cache → child via peer |

E2E harness: `e2e/src/lib.rs` — `ProxyHarness`, mock upstream, test CA, hierarchy helpers.

### Hierarchy demo (Docker)

```bash
docker compose -f deploy/compose/docker-compose.hierarchy.yml up -d --build
curl -x http://127.0.0.1:3128 http://upstream/get
docker compose -f deploy/compose/docker-compose.hierarchy.yml down
```

3-tier stack: **child** (3128) → **sibling** (ICP, 3328) / **parent** (3228) → **upstream**.

### Redis L2 demo (Docker)

```bash
docker compose -f deploy/compose/docker-compose.redis-l2.yml up -d --build
curl -x http://127.0.0.1:3128 http://upstream/get          # MISS
docker compose -f deploy/compose/docker-compose.redis-l2.yml restart proxy-a  # clears L1 only
curl -x http://127.0.0.1:3128 http://upstream/get          # L2-HIT (x-cache-status)
docker compose -f deploy/compose/docker-compose.redis-l2.yml down
```

Переменные для тестов MITM:
- `UPSTREAM_CA_CERT` — proxy доверяет самоподписанному CA upstream
- `MITM_ENABLED=true`

### Запуск отдельного теста

```bash
cargo test -p bsdm-proxy-e2e --test e2e e2e_mitm_https_with_self_signed_ca -- --nocapture
```

### Admin Console (UI)

Локальный UI-тест не требует proxy, Kafka, ClickHouse и ML-worker: фикстурный
backend в `admin-console/test/local/` отдаёт все REST-эндпоинты и Prometheus
`/metrics`, которые читает консоль.

```bash
cd admin-console
npm ci
npm test          # unit-тесты (node --test)
npm run test:ui   # сборка + прогон Chromium по всем маршрутам консоли
```

`npm run test:ui` проверяет, что каждая страница рендерится на живых данных
(`Live`, без demo-badge и error state), frozen-маршруты показывают баннер
**Frozen**, и в браузере нет ошибок консоли и неудачных HTTP-запросов.
`UI_TEST_SCREENSHOTS=1` сохраняет по скриншоту на маршрут в
`admin-console/test/local/screenshots/`.

Ручной просмотр на тех же фикстурах: `npm run dev:mock` →
`http://127.0.0.1:5173/admin/`. Подробности — в
[admin-console/README.md](../../admin-console/README.md#local-ui-test).

## Release-пакет

```bash
./scripts/build-package.sh
```

Создаёт `dist/bsdm-proxy-<version>-linux-<arch>.tar.gz` с:
- бинарниками `proxy` и `cache-indexer`
- примерами конфигурации и systemd unit-файлами
- `install.sh` и `SHA256SUMS`

Версия берётся из `proxy/Cargo.toml` (например `0.6.1-1` → пакет
`0.6.1-1`, `0.2.3-test` → `0.2.3test`).

## Docker

См. [docker.md](../getting-started/deployment.md) — сборка образов, compose-стеки, troubleshooting.

## Kubernetes

См. [kubernetes.md](k8s-architecture.md) и [k8s-architecture.md](k8s-architecture.md) — Helm chart `charts/bsdm/`, probes, HA.

## GitHub Release (CI/CD)

Workflow [release.yml](../../.github/workflows/release.yml) публикует release при push тега `v*`.
Jenkins использует тот же `scripts/ci/validate-release.sh`, но publication в нём
дополнительно требует ручного `PUBLISH_GITHUB_RELEASE=true`.

### Порядок релиза

1. Убедиться, что версия в `proxy/Cargo.toml` и `cache-indexer/Cargo.toml` совпадает с тегом
2. Обновить `CHANGELOG.md` и `docs/releases/vX.Y.Z.md`
3. Merge PR с bump версии в `main`
4. Создать и push тег:

```bash
git checkout main && git pull
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' proxy/Cargo.toml | head -1)"
git tag -a "v${VERSION}" -m "BSDM-Proxy ${VERSION}"
git push origin "v${VERSION}"
```

5. GitHub Actions: **Validate** → **Build** (linux x86_64 + aarch64) → **Publish GitHub Release** с tar.gz

Текст release notes берётся из `docs/releases/vX.Y.Z.md` (fallback — секция в `CHANGELOG.md`):

```bash
./scripts/extract-release-notes.sh "v${VERSION}"
```

### Dry-run (без публикации)

Actions → **Release** → **Run workflow** — собирает пакеты и загружает artifacts, **без** создания GitHub Release (только при `workflow_dispatch`; публикация — только при push тега).

### Артефакты

| Платформа | Архив |
|-----------|--------|
| linux x86_64 | `bsdm-proxy-<version>-linux-x86_64.tar.gz` |
| linux aarch64 | `bsdm-proxy-<version>-linux-aarch64.tar.gz` (если arm runner доступен) |

Теги с `-` в имени (например `v0.2.3-test`) помечаются как **prerelease** автоматически.

## Roadmap и milestones

Полный план: [roadmap.md](../roadmap.md)

Создать GitHub milestones / blocker issues (archived — **do not re-run**):

```bash
# Historical only — see scripts/archive/README.md
ls scripts/archive/
```

Актуальный статус блокеров: [BLOCKERS.md](../project-status.md).

## Issue automation

При merge PR связанные GitHub issue закрываются автоматически:

| Способ | Пример | Поведение |
|--------|--------|-----------|
| Блокер в **заголовке** PR | `feat(proxy): rate limit (B6)` | Закрывает #37 |
| **`Closes #NN`** в теле PR | `Closes #37` | Закрывает #37 (стандарт GitHub + workflow) |
| **workflow_dispatch** | Actions → Close blocker issues | Ручное закрытие / backfill |
| **Скрипт** | `./scripts/close-blocker-issue.sh 6 65` | Локально через `gh` |

**Маппинг:** B*n* → issue #*(31+n)* (B1→#32 … B25→#56).

**Исключение B13 (#44):** auto-close только при `Closes #44` в теле PR (полная реализация NTLM). PR с docs-only и `(B13)` в заголовке **не** закрывают #44.

Шаблон PR: [.github/pull_request_template.md](../../.github/pull_request_template.md).

### Backfill (уже смерженные PR без Closes)

```bash
# Через GitHub Actions UI: Close blocker issues → Run workflow
#   blocker_id: 6, pr_number: 65
#   blocker_id: 7, pr_number: 67

# Или локально:
./scripts/close-blocker-issue.sh 6 65   # B6 → #37
./scripts/close-blocker-issue.sh 7 67   # B7 → #38
```

## CI

| Workflow | Trigger | Description |
|----------|---------|-------------|
| [ci.yml](../../.github/workflows/ci.yml) | push/PR → main | fmt, clippy, build, tests (unit + e2e + smoke), cargo-audit |
| [admin-console.yml](../../.github/workflows/admin-console.yml) | push/PR → main | npm lint, build, unit tests + local UI smoke test (Chromium over every route) |
| [load-test.yml](../../.github/workflows/load-test.yml) | push/PR → main | wrk high-intensity load test |
| [release.yml](../../.github/workflows/release.yml) | push tag `v*` / manual | test, build packages, GitHub Release |
| [docs.yml](../../.github/workflows/docs.yml) | push/PR → main | check local markdown links, sync wiki |

## Local proxy run

```bash
export HTTP_PORT=3128
export METRICS_PORT=9090
export MITM_ENABLED=true
export RUST_LOG=info,bsdm_proxy=debug   # см. docs/ops-and-dev/logging.md

# CA для MITM (обязательно)
mkdir -p certs
# ... сгенерировать ca.key / ca.crt (см. README)

cargo run -p bsdm-proxy --bin proxy
```

Подробнее о уровнях и модулях: [logging.md](logging.md).

Проверка:
```bash
curl http://127.0.0.1:9090/health
curl -x http://127.0.0.1:3128 https://httpbin.org/get
```

## Полезные env для разработки

```bash
AUTH_ENABLED=true
ACL_ENABLED=true
ACL_RULES_PATH=./config/acl-rules.test.json
CATEGORIZATION_ENABLED=false
MITM_ENABLED=false                    # старт без CA
UPSTREAM_CA_CERT=./certs/ca.crt       # для lab MITM с самоподписанным upstream

# Иерархический кеш (локальный тест с mock peer)
HIERARCHY_ENABLED=true
CACHE_PARENTS=127.0.0.1:18080
ICP_BIND=127.0.0.1:3130
```

Подробнее: [hierarchical-caching.md](../architecture/hierarchical-caching.md)
