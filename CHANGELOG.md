# Changelog

All notable changes to BSDM-Proxy are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-07-16

Milestone **M4 Threat analytics**: rule-based alerts, C&C / Shannon heuristics, Grafana Unified Alerting.

### Added

- **M4 Grafana Unified Alerting + Alertmanager** — provisioned rules (`grafana/alerting/`), Prometheus `m4_threat` alerts, compose `alertmanager` service; closes M4 roadmap
- **M4 Shannon / high-entropy domains** — `high_entropy_domain` uses Shannon entropy on the leftmost DNS label (`ALERT_SHANNON_MIN_BITS`, modes `shannon|legacy|either`); Grafana long-domain candidates panel
- **PhishTank API key** — `PHISHTANK_API_KEY` sent as `app_key`; category cache keeps feed source for `threat_sources`
- **M4 beacon heuristic (B18)** — `beacon_periodic` rule in `alert-worker` (regular client→domain gaps); Grafana “Beacon candidates” panel; docs
- **Lite SQLite indexer** — `INDEX_STORE=sqlite|memory`, `POST /api/events`, proxy `EVENT_SINK_URL`; Lite compose includes indexer ([docs/lite.md](docs/lite.md))
- **Lite compose (Phase 1)** — [`docker-compose.lite.yml`](docker-compose.lite.yml) standalone proxy (no Kafka/CH); [`scripts/gen-ca.sh`](scripts/gen-ca.sh); docs [`docs/lite.md`](docs/lite.md)
- **Alert worker (B19 / #50)** — `alert-worker` polls ClickHouse threat rules and POSTs SIEM JSON webhooks; compose profile `alerts`, Dockerfile target, Prometheus scrape, docs [`docs/alerting.md`](docs/alerting.md)
- **Strategic roadmap** — Lite / DX / Wasm / AI-traffic phases in [`docs/strategic-roadmap.md`](docs/strategic-roadmap.md); linked from README and [`docs/roadmap.md`](docs/roadmap.md)
- **Web config GUI** — restored General/Cache/Kafka/Auth tabs; Performance, import `.env`, export `acl-rules.json`; compose aligned with root `docker-compose.yml` (P2-5)
- **Categorization Prometheus metrics** + M4 threat panels / SQL ([#105](https://github.com/onixus/bsdm-proxy/issues/105))
- Soft `session_id` / redirect-chain correlation; k8s ClickHouse Operator analytics plane ([#135](https://github.com/onixus/bsdm-proxy/issues/135))

### Changed

- **ACL lock-free snapshot** — `AclEngineHandle` with `arc-swap`; hot path `check_access` without `tokio::RwLock` ([#40](https://github.com/onixus/bsdm-proxy/issues/40) / B9)
- **Docs cleanup** — roadmap/README/wiki synced (M3/M4 done); blockers aligned with ClickHouse path; archived GitHub bootstrap scripts under `scripts/archive/`
- **M4 roadmap** — threat analytics complete; next: M5 ML

Release package: `./scripts/build-package.sh` → `dist/bsdm-proxy-0.5.0-linux-<arch>.tar.gz`  
Notes: [docs/releases/v0.5.0.md](docs/releases/v0.5.0.md)

## [0.3.2] - 2026-07-02

Milestone **M2.5 perf P1**: hot-path optimizations and offline categorization.

### Added

- **Fast cache serve path** — `PERF_FAST_CACHE_HIT` serves L1/L2 hits (HIT, REVALIDATED, NEGATIVE_HIT, L2_HIT) before ACL/categorization ([#100](https://github.com/onixus/bsdm-proxy/issues/100))
- **Bounded Kafka queue** — `KafkaEventPipeline` with `KAFKA_QUEUE_CAPACITY` (default 8192), non-blocking `try_enqueue`, drop when full ([#106](https://github.com/onixus/bsdm-proxy/issues/106))
- **Offline categorization** — `categorize_local()` on hot path (UT1/custom DB + sync cache); URLhaus/PhishTank in background `tokio` task ([#104](https://github.com/onixus/bsdm-proxy/issues/104))
- **`x-cache-status` on MISS** — `MISS-STREAMING` / `MISS` on response headers before cache insert completes ([#111](https://github.com/onixus/bsdm-proxy/issues/111))
- Prometheus counter `bsdm_proxy_kafka_queue_dropped_total`

### Changed

- **ACL regex precompilation** — regex patterns compiled on rule load/update; no `Mutex` on hot-path regex lookup ([#109](https://github.com/onixus/bsdm-proxy/issues/109))
- Category cache uses `std::sync::RwLock` (no await on policy path)
- `docs/performance.md`, `docs/categorization.md` — hot path / bench warnings

Release package: `./scripts/build-package.sh` → `dist/bsdm-proxy-0.3.2-linux-<arch>.tar.gz`

## [0.3.1] - 2026-07-01

Milestone **M3 maintenance**: ClickHouse-only analytics, Search API, documentation and project structure cleanup.

### Added

- **`bsdm-events`** workspace crate — shared `CacheEvent` schema for Kafka pipeline
- **ClickHouse indexer** — `cache-indexer` writes to `bsdm.http_cache` (JSONEachRow INSERT)
- **Search API** — `GET /api/search` on cache-indexer admin port ([#130](https://github.com/onixus/bsdm-proxy/issues/130))
- **Grafana ClickHouse dashboard** — `grafana/dashboards/bsdm-http-traffic-ch.json`
- **Helm chart** — `charts/bsdm/` (proxy Deployment skeleton)
- **Documentation** — `docs/deployment.md`, `docs/docker.md`, `docs/kubernetes.md`, `docs/structure.md`, `docs/licensing.md`
- **NOTICE** — updated third-party registry (Rust deps, Docker images, AGPL notes)
- `license = "MIT"` in `proxy` and `e2e` Cargo.toml

### Removed

- **OpenSearch backend** — `cache-indexer` is ClickHouse-only; `opensearch` crate, dual-write, legacy compose ([#134](https://github.com/onixus/bsdm-proxy/issues/134))
- `opensearch-dashboards/`, `OPENSEARCH_UPGRADE.md`, `scripts/reconcile-os-ch-events.sh`
- OpenSearch index/ISM helpers from `bsdm-events`
- `docker-compose.clickhouse.yml`, `grafana/clickhouse/` duplicate, `README.md_old`, `SDBM/`, `.github/issue-bodies/ch-*.md`

### Changed

- **Default Docker stack** — `docker compose up` uses ClickHouse + Grafana CH dashboards + Search API ([#132](https://github.com/onixus/bsdm-proxy/issues/132))
- ADR 0002 status → Accepted
- **web-config** — ClickHouse instead of OpenSearch in compose generator
- **Dockerfile** — include `e2e`, `bsdm-events`; builder `rust:1-alpine`

### Migration

- OpenSearch users: migrate to ClickHouse — see [docs/releases/v0.3.1.md](docs/releases/v0.3.1.md) and [clickhouse-analytics.md](docs/clickhouse-analytics.md)
- `cache-indexer.env`: use `CLICKHOUSE_*`, remove `OPENSEARCH_*`

Release package: `./scripts/build-package.sh` → `dist/bsdm-proxy-0.3.1-linux-<arch>.tar.gz`

## [0.3.0] - 2026-06-30

Milestone **M2 — Squid parity**: hierarchy Phase 4, enterprise auth (NTLM/Kerberos), ACL API, negative caching.

### Added

- **Hierarchy Phase 4** — multicast peer discovery, Bloom-filter cache digests, optional HTCP sibling queries (`PEER_DISCOVERY_*`, `HIERARCHY_DIGEST_*`, `HIERARCHY_USE_HTCP`)
- **NTLM authentication** — multi-round `Proxy-Authenticate: NTLM` via `sspi`, optional Samba `ntlm_auth` helper (`auth-ntlm` feature, [#44](https://github.com/onixus/bsdm-proxy/issues/44))
- **Kerberos / SPNEGO** — multi-round `Negotiate` handshake with service keytab (`auth-kerberos` feature)
- **LDAP group enrichment** — resolve `memberOf` after NTLM/Kerberos via service bind (`LDAP_GROUP_ENRICHMENT`, requires `auth-ldap` + SSO features)
- **REST ACL API** — CRUD and reload on metrics port (`/api/acl/*`, `ACL_API_TOKEN`) ([#82](https://github.com/onixus/bsdm-proxy/pull/82))
- **Negative caching** — short TTL for upstream 403/404 (`NEGATIVE_CACHE_*`) ([#81](https://github.com/onixus/bsdm-proxy/pull/81))
- **Cache revalidation** — `Cache-Control`, ETag / `If-Modified-Since`, `304` → `REVALIDATED`
- Prometheus counter `bsdm_proxy_hierarchy_digest_skipped_icp_total`
- `.cargo/audit.toml` — documented ignore for transitive `rsa` via optional `sspi`

### Changed

- `AuthManager::handle_proxy_auth()` — multi-round SSO with per-client-IP session state
- Documentation and `bsdm-proxy.env.example` updated for M2 features

### Fixed

- Default build without `auth-ntlm`/`auth-kerberos` features (cfg guard for SSPI path)
- `NTLM_AUTH_HELPER` command-line parsing (program + arguments)
- First-round NTLM helper handshake (`YR` with empty token)
- `cargo fmt` / CI formatting for hierarchy modules

### Build

```bash
# Default (Basic auth only)
cargo build -p bsdm-proxy --release

# All auth backends
cargo build -p bsdm-proxy --release --features auth-all
```

Release package: `./scripts/build-package.sh` → `dist/bsdm-proxy-0.3.0-linux-<arch>.tar.gz`

See [docs/releases/v0.3.0.md](docs/releases/v0.3.0.md) for migration and configuration.

## [0.2.3-test] - 2026-06-29

Test pre-release — partial M2 (L2, HTTP/2, compression).

### Added

- Redis L2 cache (`REDIS_L2_ENABLED`)
- HTTP/2 upstream (`UPSTREAM_HTTP2_ENABLED`)
- At-rest cache compression Zstd/Brotli (`CACHE_COMPRESSION`)
- ACL TimeWindow and LDAP group Principal rules
- Rate limiting per IP/user
- `ProxyService` extracted to library

See [docs/releases/v0.2.3-test.md](docs/releases/v0.2.3-test.md).

## [0.2.2b] - 2026-06

Beta — hierarchical caching Phase 3, optional MITM CA.

[GitHub Releases](https://github.com/onixus/bsdm-proxy/releases/tag/v0.2.2b)

[0.5.0]: https://github.com/onixus/bsdm-proxy/compare/v0.3.2...v0.5.0
[0.3.2]: https://github.com/onixus/bsdm-proxy/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/onixus/bsdm-proxy/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/onixus/bsdm-proxy/compare/v0.2.3-test...v0.3.0
[0.2.3-test]: https://github.com/onixus/bsdm-proxy/releases/tag/v0.2.3-test
[0.2.2b]: https://github.com/onixus/bsdm-proxy/releases/tag/v0.2.2b
