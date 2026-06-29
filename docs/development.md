# Разработка и тестирование

Руководство для разработчиков BSDM-Proxy.

## Требования

| Компонент | Версия |
|-----------|--------|
| Rust | 1.85+ |
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
├── cache-indexer/      # Kafka → OpenSearch indexer
├── e2e/                # Smoke и E2E тесты
├── config/             # Примеры ACL-правил
├── packaging/          # Release-пакет (systemd, install.sh)
├── scripts/            # build-package, run-*-tests
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

CI запускает `cargo fmt --check` — перед пушем обязательно `cargo fmt --all`.

## Тесты

### Workspace

```bash
cargo test --workspace
```

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

Версия берётся из `proxy/Cargo.toml` (например `0.2.2-b` → пакет `0.2.2b`).

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
UPSTREAM_CA_CERT=./certs/ca.crt   # для lab MITM с самоподписанным upstream
```
