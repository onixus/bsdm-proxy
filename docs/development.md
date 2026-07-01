# Разработка и тестирование

Руководство для разработчиков BSDM-Proxy.

## Требования

| Компонент | Версия |
|-----------|--------|
| Rust | **1.88+** (рекомендуется latest stable) |
| Cargo | stable |
| librdkafka | dev-пакет (`librdkafka-dev`) |
| OpenSSL | dev-пакет (`libssl-dev`) |

**Debian/Ubuntu:**
```bash
sudo apt-get install -y \
  libssl-dev pkg-config cmake librdkafka-dev libclang-dev
```

## Структура workspace

```
bsdm-proxy/
├── proxy/              # Основной прокси (bin: proxy)
│   └── src/
│       ├── main.rs     # ProxyService, HTTP server, cache, Kafka
│       ├── lib.rs      # acl, auth, categorization, hierarchy, icp, peers
│       ├── peer_fetch.rs, hierarchy_config.rs, cache_key.rs
│       └── tls.rs, metrics.rs, policy_config.rs
├── cache-indexer/      # Kafka → OpenSearch indexer
├── e2e/                # Smoke и E2E тесты
├── config/             # Примеры ACL-правил
├── packaging/          # Release-пакет (systemd, install.sh)
├── scripts/            # build-package, run-*-tests, pre-push-check
└── docs/               # Документация
```

## Сборка

```bash
# Debug
cargo build -p bsdm-proxy --bin proxy

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

Ожидаемый результат: **75 тестов** (proxy unit/integration, cache-indexer, e2e smoke + e2e).

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

E2E harness: `e2e/src/lib.rs` — `ProxyHarness`, mock upstream, test CA.

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

Версия берётся из `proxy/Cargo.toml` (например `0.2.3-test` → пакет `0.2.3test`).

## Docker

См. [docker.md](docker.md) — сборка образов, compose-стеки, troubleshooting.

## Kubernetes

См. [kubernetes.md](kubernetes.md) — манифесты, probes, managed Kafka/OpenSearch.

## Roadmap и milestones

Полный план: [roadmap.md](roadmap.md)

Создать GitHub milestones (требует admin scope):

```bash
./scripts/create-milestones.sh
```

Создать issues по архитектурным блокерам B1–B25:

```bash
./scripts/create-blocker-issues.sh
# ./scripts/create-blocker-issues.sh --dry-run
```

См. [architecture.md](architecture.md).

## CI

| Workflow | Триггер | Шаги |
|----------|---------|------|
| [rust.yml](../.github/workflows/rust.yml) | push/PR → main | fmt, clippy, build, test, cargo-audit |
| [e2e.yml](../.github/workflows/e2e.yml) | push/PR → main | smoke + e2e |

## Локальный запуск proxy

```bash
export HTTP_PORT=1488
export METRICS_PORT=9090
export MITM_ENABLED=true
export RUST_LOG=info,bsdm_proxy=debug

# CA для MITM (обязательно)
mkdir -p certs
# ... сгенерировать ca.key / ca.crt (см. README)

cargo run -p bsdm-proxy --bin proxy
```

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
