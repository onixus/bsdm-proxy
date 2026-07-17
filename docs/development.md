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

Полная карта репозитория: [structure.md](structure.md).

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
├── alert-worker/       # M4 webhook alerts
├── bsdm-events/        # Shared CacheEvent types
├── e2e/                # Smoke и E2E тесты
├── admin-console/      # Unified admin UI (React)
├── charts/bsdm/        # Helm chart для Kubernetes
├── config/             # Примеры ACL-правил
├── packaging/          # Release-пакет (systemd, install.sh)
├── scripts/            # build-package, run-*-tests, pre-push-check, clickhouse SQL
├── grafana/            # Datasources + dashboards (Prometheus, ClickHouse)
├── prometheus/         # Scrape config
├── web-config/         # Legacy static config generator
└── docs/               # Документация
```

## Сборка

```bash
# Debug (default: auth-basic + kafka)
cargo build -p bsdm-proxy --bin proxy

# Optional gRPC control plane (needs protoc; runtime: CONTROL_GRPC_ENABLED=true)
cargo build -p bsdm-proxy --features grpc --bin proxy

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

Против docker-compose.test.yml:

```bash
docker compose -f docker-compose.test.yml up -d --build
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
docker compose -f docker-compose.hierarchy.yml up -d --build
curl -x http://127.0.0.1:1488 http://upstream/get
docker compose -f docker-compose.hierarchy.yml down
```

3-tier stack: **child** (1488) → **sibling** (ICP, 1490) / **parent** (1489) → **upstream**.

### Redis L2 demo (Docker)

```bash
docker compose -f docker-compose.redis-l2.yml up -d --build
curl -x http://127.0.0.1:1488 http://upstream/get          # MISS
docker compose -f docker-compose.redis-l2.yml restart proxy-a  # clears L1 only
curl -x http://127.0.0.1:1488 http://upstream/get          # L2-HIT (x-cache-status)
docker compose -f docker-compose.redis-l2.yml down
```

Переменные для тестов MITM:
- `UPSTREAM_CA_CERT` — proxy доверяет самоподписанному CA upstream
- `MITM_ENABLED=true`

### Запуск отдельного теста

```bash
cargo test -p bsdm-proxy-e2e --test e2e e2e_mitm_https_with_self_signed_ca -- --nocapture
```

## Release-пакет

```bash
./scripts/build-package.sh
```

Создаёт `dist/bsdm-proxy-<version>-linux-<arch>.tar.gz` с:
- бинарниками `proxy` и `cache-indexer`
- примерами конфигурации и systemd unit-файлами
- `install.sh` и `SHA256SUMS`

Версия берётся из `proxy/Cargo.toml` (например `0.5.0` → пакет `0.5.0`, `0.2.3-test` → `0.2.3test`).

## Docker

См. [docker.md](docker.md) — сборка образов, compose-стеки, troubleshooting.

## Kubernetes

См. [kubernetes.md](kubernetes.md) и [k8s-architecture.md](k8s-architecture.md) — Helm chart `charts/bsdm/`, probes, HA.

## GitHub Release (CI)

Workflow [release.yml](../.github/workflows/release.yml) публикует release при push тега `v*`.

### Порядок релиза

1. Убедиться, что версия в `proxy/Cargo.toml` и `cache-indexer/Cargo.toml` совпадает с тегом
2. Обновить `CHANGELOG.md` и `docs/releases/vX.Y.Z.md`
3. Merge PR с bump версии в `main`
4. Создать и push тег:

```bash
git checkout main && git pull
git tag -a v0.5.0 -m "BSDM-Proxy v0.5.0"
git push origin v0.5.0
```

5. GitHub Actions: **Validate** → **Build** (linux x86_64 + aarch64) → **Publish GitHub Release** с tar.gz

Текст release notes берётся из `docs/releases/vX.Y.Z.md` (fallback — секция в `CHANGELOG.md`):

```bash
./scripts/extract-release-notes.sh v0.5.0
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

Полный план: [roadmap.md](roadmap.md)

Создать GitHub milestones / blocker issues (archived — **do not re-run**):

```bash
# Historical only — see scripts/archive/README.md
ls scripts/archive/
```

Актуальный статус блокеров: [BLOCKERS.md](BLOCKERS.md).

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

Шаблон PR: [.github/pull_request_template.md](../.github/pull_request_template.md).

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

| Workflow | Триггер | Шаги |
|----------|---------|------|
| [rust.yml](../.github/workflows/rust.yml) | push/PR → main | fmt, clippy, build, test, cargo-audit |
| [e2e.yml](../.github/workflows/e2e.yml) | push/PR → main | smoke + e2e |
| [close-blockers.yml](../.github/workflows/close-blockers.yml) | PR merged / manual | auto-close B1–B25 issues |
| [pr-blocker-hint.yml](../.github/workflows/pr-blocker-hint.yml) | PR opened/edited | комментарий со ссылками на issue |
| [release.yml](../.github/workflows/release.yml) | push tag `v*` / manual | test, build packages, GitHub Release |

## Локальный запуск proxy

```bash
export HTTP_PORT=1488
export METRICS_PORT=9090
export MITM_ENABLED=true
export RUST_LOG=info,bsdm_proxy=debug   # см. docs/logging.md

# CA для MITM (обязательно)
mkdir -p certs
# ... сгенерировать ca.key / ca.crt (см. README)

cargo run -p bsdm-proxy --bin proxy
```

Подробнее о уровнях и модулях: [logging.md](logging.md).

Проверка:
```bash
curl http://127.0.0.1:9090/health
curl -x http://127.0.0.1:1488 https://httpbin.org/get
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

Подробнее: [hierarchical-caching.md](hierarchical-caching.md)
