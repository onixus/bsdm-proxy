# Структура репозитория

Актуально для workspace `0.9.1`.

## Cargo workspace

| Member | Путь | Назначение |
|---|---|---|
| `bsdm-proxy` | `proxy/` | Forward proxy, MITM, cache, policy, UI routing и control plane |
| `cache-indexer` | `cache-indexer/` | Kafka/HTTP → ClickHouse/SQLite |
| `alert-worker` | `alert-worker/` | ClickHouse rules → webhook |
| `ml-worker` | `ml-worker/` | Feature extraction и scoring |
| `dns-sinkhole` | `dns-sinkhole/` | Core UDP DNS, DoH/DoT и RPZ-lite |
| `bsdm-events` | `bsdm-events/` | Общая event schema |
| `bsdm-proxy-e2e` | `e2e/` | Test harness |
| `bsdm-wasm-sdk` | `bsdm-wasm-sdk/` | WASM guest ABI helpers |
| WASM example | `examples/wasm/rust_plugin/` | Example guest plugin |
| `agent-spike` | `examples/agent-spike/` | On-Device SWG Local Policy Agent Spike (Agent Contract v0.1) |

Корневой `Cargo.toml` — единственный источник состава workspace.

## Каталоги

```text
bsdm-proxy/
├── proxy/                  # Основной data/control plane
├── cache-indexer/          # Analytics ingest + Search API
├── alert-worker/           # Detection rules
├── ml-worker/              # Feature store и scoring
├── dns-sinkhole/           # Core DNS security sidecar (DoH/DoT/RPZ)
├── bsdm-events/            # Shared event schema
├── bsdm-wasm-sdk/          # WASM SDK
├── e2e/                    # Integration test harness
├── admin-console/          # Поддерживаемая operator SPA (`/admin/`)
├── trust-ui/               # Experimental/deprecated posture reference
├── charts/bsdm/            # Helm chart
├── packaging/              # systemd package и env examples
├── config/                 # ACL examples
├── scripts/                # Build, test, load test и docs automation
├── docs/                   # Каноническая документация
├── prometheus/             # Scrape config и rules
├── grafana/                # Dashboards и provisioning
├── alertmanager/           # Alertmanager template
├── bpf/                    # Experimental XDP program
├── examples/               # Agent, DNS и WASM examples
├── Dockerfile              # Multi-stage images
└── docker-compose*.yml     # Deployment examples
```

## Compose

| Файл | Назначение |
|---|---|
| `docker-compose.yml` | Analytics base + optional profiles |
| `docker-compose.lite.yml` | Proxy + SQLite |
| `docker-compose.test.yml` | Test stack |
| `docker-compose.redis-l2.yml` | Redis L2 example |
| `docker-compose.hierarchy.yml` | Cache hierarchy example |
| `docker-compose.ha.yml` | HA lab sketch |
| `docker-compose.awg.yml` | Experimental AWG sidecar |

Основной Compose включает `dns-sinkhole` в базовом стеке; профили опциональных
компонентов: `alerts`, `ml`, `icap`. Legacy Trust-UI запускается только явным
профилем `experimental-trust-ui`; поддерживаемая операторская UI — Admin Console.

## Конфигурация и данные

| Путь | Назначение |
|---|---|
| `packaging/config/*.env.example` | Native environment examples |
| `scripts/clickhouse/*.sql` | ClickHouse schema |
| `config/acl-rules*.json` | ACL examples |
| `grafana/dashboards/` | Dashboards |
| `prometheus/alerts/` | Prometheus rules |
| `examples/dns/` | RPZ-lite example |

## Документация

| Путь | Роль |
|---|---|
| `README.md` | Product overview |
| `docs/README.md` | Documentation index |
| `docs/project-status.md` | Feature maturity |
| `docs/getting-started/` | Deployment |
| `docs/architecture/` | Design и capacity |
| `docs/features/` | Proxy modules |
| `docs/analytics/` | Analytics/ML |
| `docs/ops-and-dev/` | Operations/development |
| `docs/releases/` | Historical release notes |

Wiki не является отдельным источником истины. Она генерируется командой:

```bash
python3 scripts/sync-wiki.py /path/to/bsdm-proxy.wiki
```

## CI

`.github/workflows/` содержит Rust, E2E, Docker, release, UI, load-test и docs
workflows. Перед PR:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
python3 scripts/check-doc-links.py
```
