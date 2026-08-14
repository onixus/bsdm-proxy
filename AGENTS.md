# AGENTS.md

Single source of truth for AI coding agents in this repository. `.cursorrules`
points here — keep guidance in this file rather than duplicating it elsewhere.

## Project overview

BSDM-Proxy is a single Rust/Cargo product: a caching HTTPS forward proxy (Secure
Web Gateway) with MITM TLS, auth, ACL, Prometheus metrics, and an optional
Kafka → cache-indexer → ClickHouse analytics pipeline (plus optional
`alert-worker` webhook alerts, `ml-worker` feature-store scoring, and
`dns-sinkhole` UDP RPZ-lite sidecar).

Standard build, lint, test, and run commands live in `README.md` and
`docs/ops-and-dev/development.md` — use those as the source of truth.

## Repository layout

Cargo workspace members (see `Cargo.toml`):

- `proxy/` — proxy core, bin `proxy` (HTTP/HTTPS parsing, ACL, auth, L1 cache).
- `cache-indexer/` — cache indexing, bin `cache-indexer` (Kafka integration).
- `alert-worker/` — security incident handling, dedup, webhooks; bin `alert-worker`.
- `ml-worker/` — UEBA / threat scoring against ClickHouse; bin `ml-worker`.
- `dns-sinkhole/` — UDP RPZ-lite sidecar, bin `dns-sinkhole`.
- `bsdm-events/` — shared event types.
- `e2e/` — test harness.
- `bsdm-wasm-sdk/`, `examples/wasm/rust_plugin/`, `examples/agent-spike/` — WASM
  plugin SDK and example crates.

Supporting directories:

- `admin-console/` — React + Tailwind SPA, the current administration UI.
- `trust-ui/` — React UI for trust/consent flows.
- `web-config/` — **legacy** zero-dependency static config generator. Kept as a
  fallback only; new UI work belongs in `admin-console/`.
- `deploy/compose/` — profile Compose files (lite, pilot, ha, hierarchy,
  redis-l2, test, awg). The default `docker-compose.yml` stays in the repo root.
- `charts/bsdm/` — Helm charts.
- `grafana/`, `prometheus/`, `alertmanager/` — monitoring configuration.
- `scripts/` — benchmarking (wrk), HTTP-archive generation, ClickHouse
  migrations, installer, CI helpers.
- `packaging/config/` — packaged `.env.example` files.

## Formatting and linting

- **ALWAYS** run `cargo fmt --all` before committing Rust changes. CI strictly
  enforces formatting and will fail if the code is not formatted.
- **ALWAYS** run `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  before committing logical changes.

## Rust guidelines

- Idiomatic Rust, edition 2021. Requires Rust 1.85+.
- Prefer `tokio` for async.
- Error handling via `Result` with `anyhow` or `thiserror` as appropriate. Never
  use `.unwrap()` / `.expect()` in production code — tests are fine.
- Cache code (`sharded_cache.rs`, `hierarchy.rs`) is concurrency-sensitive: mind
  `Arc`, `RwLock`, `Mutex`.
- Add Prometheus metrics for new features (`proxy/src/metrics.rs`).
- This is a proxy — optimize for low latency.

## Databases

- ClickHouse handles heavy analytics. When adding fields to ML models, provide
  matching SQL migrations in `scripts/clickhouse/migrations/`.
- Optimize SQL for a columnar store: avoid `SELECT *`, use partitioning.

## Infrastructure and CI/CD

- When changing configuration, update the corresponding `.env.example` in
  `packaging/config/`.
- When adding a service, update `charts/bsdm/` and `docker-compose.yml`.

## Testing

- Propose E2E tests in `e2e/` for new functionality.
- Use the existing benchmark scripts in `scripts/` (e.g. `run-proxy-benchmark.sh`)
  for performance checks.
- `cargo test --workspace` (plus the `smoke`/`e2e` suites) needs **no** Docker,
  Kafka, or ClickHouse — the e2e harness spawns `proxy` as a subprocess with an
  in-process mock upstream (`e2e/src/lib.rs`). The suites do require outbound
  localhost networking.

## Environment notes

The update script already runs `cargo fetch`; system packages and the Rust
toolchain are baked into the VM image.

- Requires Rust 1.85+. The image ships a newer stable toolchain
  (`rustup default stable`); the previously preinstalled 1.83 is too old and will
  fail to compile some deps.
- Native builds need `libssl-dev pkg-config cmake librdkafka-dev libclang-dev`
  (see `docs/ops-and-dev/development.md`). `rdkafka` links against `librdkafka-dev`.

## Running locally

- To run with `MITM_ENABLED=true` (the default), a CA keypair must exist at
  `./certs/ca.key` and `./certs/ca.crt`. These are git-ignored and NOT in the
  repo, so generate them first (`./scripts/gen-ca.sh`, or "Быстрый старт" in
  `README.md`), otherwise MITM startup fails. For plain forward-proxy testing set
  `MITM_ENABLED=false` and skip the certs.
- Lite node (proxy + SQLite indexer, no Kafka/CH):
  `./scripts/gen-ca.sh && docker compose -f deploy/compose/docker-compose.lite.yml up -d --build`
  (see `docs/getting-started/lite-mode.md`).
- Run natively: `HTTP_PORT=3128 METRICS_PORT=9090 cargo run -p bsdm-proxy --bin proxy`
  (or the built `./target/debug/proxy`). Verify with
  `curl http://127.0.0.1:9090/health` and
  `curl -x http://127.0.0.1:3128 http://httpbin.org/get`. HTTPS through MITM:
  `curl --cacert certs/ca.crt -x http://127.0.0.1:3128 https://httpbin.org/uuid`.
- The full Docker stack (`docker-compose.yml`: Kafka, ClickHouse, Prometheus,
  Grafana) is optional and only needed to exercise the analytics pipeline /
  dashboards end to end. Lite compose does not start that plane.
