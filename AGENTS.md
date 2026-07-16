# AGENTS.md

## Cursor Cloud specific instructions

BSDM-Proxy is a single Rust/Cargo product: a caching HTTPS forward proxy with MITM
TLS, auth, ACL, Prometheus metrics, and an optional Kafka → cache-indexer → ClickHouse
analytics pipeline (plus optional `alert-worker` webhook alerts and `ml-worker`
feature-store scoring). The Cargo workspace has six crates: `proxy/` (bin `proxy`),
`cache-indexer/` (bin `cache-indexer`), `alert-worker/` (bin `alert-worker`),
`ml-worker/` (bin `ml-worker`), `bsdm-events/` (shared event types), and
`e2e/` (test harness). Standard build,
lint, test, and run commands live in `README.md` and `docs/development.md` — use those
as the source of truth.

Environment notes (the update script already runs `cargo fetch`; system packages and the
Rust toolchain are baked into the VM image):

- Requires Rust 1.85+. The image ships a newer stable toolchain (`rustup default stable`);
  the previously preinstalled 1.83 is too old and will fail to compile some deps.
- Native build needs system packages `libssl-dev pkg-config cmake librdkafka-dev libclang-dev`
  (see `docs/development.md`). `rdkafka` (Kafka client) links against `librdkafka-dev`.

Running and testing:

- `cargo test --workspace` (plus the `smoke`/`e2e` suites) needs **no** Docker, Kafka, or
  ClickHouse — the e2e harness spawns `proxy` as a subprocess with an in-process mock
  upstream (`e2e/src/lib.rs`). The test suites do require outbound localhost networking.
- To run the proxy with `MITM_ENABLED=true` (the default), a CA keypair must exist at
  `./certs/ca.key` and `./certs/ca.crt`. These are git-ignored and NOT in the repo, so
  generate them first (`./scripts/gen-ca.sh` or "Быстрый старт" in `README.md`), otherwise MITM startup fails.
  For plain forward-proxy testing you can set `MITM_ENABLED=false` and skip the certs.
  Standalone caching node (no Kafka/CH): `./scripts/gen-ca.sh && docker compose -f docker-compose.lite.yml up -d --build` (see `docs/lite.md`).
- Run locally: `HTTP_PORT=1488 METRICS_PORT=9090 cargo run -p bsdm-proxy --bin proxy`
  (or the built `./target/debug/proxy`). Verify with `curl http://127.0.0.1:9090/health`
  and `curl -x http://127.0.0.1:1488 http://httpbin.org/get`. HTTPS through MITM:
  `curl --cacert certs/ca.crt -x http://127.0.0.1:1488 https://httpbin.org/uuid`.
- The full Docker stack (`docker-compose.yml`: Kafka, ClickHouse, Prometheus, Grafana) is
  optional and only needed to exercise the analytics pipeline / dashboards end to end.
  Lite compose does not start that plane.