# Changelog

All notable changes to BSDM-Proxy are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Agent policy push (#273)** — versioned policy hub; long-poll
  `GET /api/v1/agent/policy/watch`, SSE `GET /api/v1/agent/policy/stream`,
  operator `POST /api/v1/agent/policy/push`; auto-push on pinning reload;
  `agent-spike` watch loop (`AGENT_POLICY_PUSH`, default on).

## [0.9.4] - 2026-08-04

Patch release after **0.9.3**: optional agent control-plane **mTLS transport**
listener (client certificates required on a dedicated port).

### Added

- **Agent control mTLS transport** — optional HTTPS listener
  (`CONTROL_MTLS_ENABLED`, default bind `:9443`) requiring client certificates
  signed by the proxy CA; plain metrics/control port unchanged; optional
  `CONTROL_MTLS_REQUIRE_ENROLLED` fingerprint check against device registry;
  docs in control-plane-security + pilot-agent (#273).

## [0.9.3] - 2026-08-04

Patch release after **0.9.2**: Phase C agent control-plane telemetry and
identity — events batch, device enroll token, optional mTLS CSR client certs.

### Added

- **Agent mTLS CSR enroll (#273)** — optional `csr_pem` on
  `POST /api/v1/agent/enroll`; control plane signs ClientAuth cert with proxy
  CA (`CertCache`), binds CN/URI SAN to `device_id` + platform; returns
  `client_cert_pem` / `ca_cert_pem` / fingerprint; `agent-spike --mtls`.
- **Agent enroll lab path (#273)** — `POST /api/v1/agent/enroll` issues
  `device_token` (SHA-256 hashed on device registry); auth via
  `AGENT_ENROLL_TOKEN` or `CONTROL_API_TOKEN`; agent endpoints accept
  device Bearer or control token; revoke clears hash; `agent-spike --enroll`.
- **Agent events telemetry (#273)** — `POST /api/v1/agent/events` batch ingest
  (validate, `local-agent` metrics, optional Kafka/HTTP enqueue as `CacheEvent`),
  lab `GET /api/v1/agent/events/recent` ring buffer; `agent-spike` posts decisions
  after evaluate; smoke + contract docs.

## [0.9.2] - 2026-08-04

Patch release after **0.9.1**: pilot observability pack, Phase C agent lab path
(policy pull, durable device registry, refactor), and one-model ML pilot docs.

### Added

- **Agent Phase C lab path (#273)** — `agent-spike` policy pull + local evaluate
  + enriched heartbeat (`--once` / smoke); control plane
  `sni_rules` / `sni_deny_patterns` (`AGENT_SNI_DENY_PATTERNS`);
  **device registry persistence** via `AGENT_DEVICES_PATH` (compose volume
  `agent-devices`, `"persisted"` in responses);
  [pilot-agent.md](docs/getting-started/pilot-agent.md),
  `scripts/run-agent-pilot-smoke.sh`.
- **Pilot ML one-model path** — documented UEBA (`ueba_zscore_v0`) pilot:
  `config/pilot-ml.env.example`, [pilot-ml.md](docs/getting-started/pilot-ml.md),
  `scripts/run-ml-pilot-smoke.sh`, pilot compose defaults for ml-worker;
  proxy threat-score remains opt-in enrich-only.
- **Pilot observability pack** — Admin Console Dashboard `decision_source` mix,
  Logs server/client filter for Hybrid paths, pilot alert-worker rule subset
  (`config/pilot-alert.env.example`, [pilot-alerts.md](docs/getting-started/pilot-alerts.md)).

### Changed

- **Agent control-plane structure** — `DeviceRegistry` owns inventory +
  heartbeat/revoke/persist and policy document helpers; `control_api` thin
  HTTP adapters; `agent-spike` split into `policy` / `engine` / `main`.

## [0.9.1] - 2026-08-04

Patch release after **0.9.0**: complete Phase B pilot ops — backup/restore
drills, DLP kill-switch, Basic auth pilot path, DNS sinkhole day-1, and Admin
Console Hybrid honesty (frozen experimental deep-links).

### Added

- **Admin Console Hybrid honesty** — `routeScope` + frozen deep-link shell/banner
  for `/wasm` `/cluster` `/ai-cache` `/amneziawg`, header read-only vs token
  badges, Settings eBPF/Wasm marked frozen, Data Security pilot DLP note; core
  nav maturity raised to Основной in project-status.
- **Pilot DNS sinkhole day-1** — Base compose UDP `:5353`, DoH/DoT off by default,
  zone bind-mount, `badsite.test` in example RPZ, `scripts/run-dns-pilot-smoke.sh`,
  and [pilot-dns.md](docs/getting-started/pilot-dns.md).
- **Pilot Basic auth pilot path** — Users file (`BASIC_AUTH_USERS_FILE`),
  `scripts/gen-basic-auth-user.sh`, `scripts/run-auth-pilot-smoke.sh`, example
  users JSON, compose mount, and [pilot-auth.md](docs/getting-started/pilot-auth.md)
  (OIDC reverse-proxy documented as experimental, not day-1 forward SWG).
- **DLP_ENABLED kill-switch** — Native signature DLP is off by default
  (`DLP_ENABLED=false`/unset); `true` loads built-in patterns. Pilot compose sets
  false so no control-API pattern wipe is required after restart.
- **Backup & restore runbook** — ClickHouse Native dump/restore scripts,
  CA archive rollback path, and combined drill
  (`scripts/drill-backup-restore.sh`, [docs/ops-and-dev/backup-restore.md](docs/ops-and-dev/backup-restore.md)).

### Fixed

- **Cargo.lock for workspace 0.9.x** — lockfile package metadata kept in sync so
  Docker `cargo build --locked` / GHCR publish succeed after version bumps.

## [0.9.0] - 2026-08-04

Release **0.9.0**. Pilot-hardening cut on the Hybrid Policy path: production
control-plane auth defaults, SNI never-MITM invariant, Admin Console as the sole
operator UI, CA rotation tooling, decision-source observability, managed pinning
exceptions, Search API pagination, and reproducible 100-user load-test/pilot
compose profiles.

### Added

- **Control plane & metrics security defaults (#271)** — Production requires
  `CONTROL_API_TOKEN` (fail closed; lab override `CONTROL_API_ALLOW_INSECURE`),
  configurable `METRICS_BIND`, optional `METRICS_AUTH_TOKEN` /
  `METRICS_REQUIRE_AUTH` for scrape, Search API production token gate, pilot
  compose secret requirements, and
  [control-plane-security.md](docs/ops-and-dev/control-plane-security.md).
- **SNI policy invariant verification (#272)** — `POLICY_MODE=sni` hard-gates TLS
  termination (no MITM regardless of `MITM_ENABLED` / categories), with exhaustive
  unit coverage, e2e proof via `decision_source` metrics, and documentation in
  `docs/features/acl-policy.md`.
- **Hybrid pilot load-test profile (#269)** — Reproducible
  `scripts/run-hybrid-load-test.sh` with latency p50/p95/p99, error rate,
  `decision_source` deltas, markdown results under
  `docs/ops-and-dev/load-test-results/`, methodology in
  `docs/ops-and-dev/load-test-selective-mitm.md`, and a CI hybrid job in
  `.github/workflows/load-test.yml`.
- **Pilot readiness compose + acceptance (#270)** — `docker-compose.pilot.yml`
  Hybrid defaults (`POLICY_MODE=selective-mitm`, ACL on, experimental modules
  opt-in only) and rewritten acceptance checklist in
  `docs/getting-started/pilot-deployment.md`.
- **Policy decision-source observability** — Bounded Prometheus counters,
  structured decision logs, Grafana breakdowns, and Search API filtering for
  `dns`, `sni`, `mitm`, and `pinning-bypass`, including compatible SQLite and
  ClickHouse schema upgrades.
- **Managed Certificate Pinning exceptions** — Validated, hot-reloadable JSON
  registry, authenticated Control API reload, append-only JSONL audit trail,
  expiry support, and a safe operator procedure while retaining the legacy
  `PINNING_EXCEPTIONS` startup fallback.
- **Search API pagination and sorting** — REST Search API pagination/sorting and
  ClickHouse schema migration/compatibility checks.
- **Two-phase CA rotation tooling** — Key-permission validation, archived
  rollback material, automated offline rotation drill, and emergency guidance.

### Security

- Make Admin Console mutations fail closed without an in-memory API token, add
  an explicit read-only banner, and document the console exposure threat model.
- Reject `POLICY_MODE=full-mitm` in the default `production` deployment profile;
  local development/test use now requires an explicit `ALLOW_FULL_MITM=true` override.
- Update optional WASM runtime `wasmtime` to 46.0.2 to address
  RUSTSEC-2026-0222 and RUSTSEC-2026-0223.
- Align default documented proxy port examples with `HTTP_PORT=3128`.

### Changed

- Make Admin Console the only supported operator UI, redirect legacy `/trust`
  entry points to `/admin/`, and move standalone Trust-UI behind an explicit
  experimental Compose profile.

## [0.8.0] - 2026-07-27

Release **0.8.0**. Hybrid Policy Engine & Local Agent Contract, Global Session State & Real-time Threat Sync, Native UI Routing (Trust-UI & Admin Console), OIDC Security Validation, DoH & DoT Encrypted DNS Gateways, and Admin Console modules (RPZ, Wasm, ICAP, Mesh Cluster, eBPF/XDP, Vector AI Cache).


### Added

- **Hybrid Policy Engine & Agent Contract** — Implementation of hybrid policy resolution (`POLICY_MODE`: `selective-mitm`, `sni`, `full-mitm`), Local Policy Agent Contract v0.1 specification ([docs/architecture/agent-contract.md](docs/architecture/agent-contract.md)), ADR 0005 ([docs/adr/0005-local-policy-agent-vs-tunnel-first.md](docs/adr/0005-local-policy-agent-vs-tunnel-first.md)), `examples/agent-spike`, and load test harness `scripts/run-hybrid-load-test.sh` ([#262](https://github.com/onixus/bsdm-proxy/pull/262))
- **Security (OIDC) Verification & JWT Audit** — Strict CSRF state verification, JWT issuer, audience, and expiration claim validation ([#241](https://github.com/onixus/bsdm-proxy/pull/241))
- **ClickHouse DLP & CASB Schema Migration** — Added `dlp_violation` and `casb_alert` columns to `http_cache` schema and ingest pipeline ([#239](https://github.com/onixus/bsdm-proxy/pull/239))
- **Native Static UI Routing & Reverse Proxy** — Native routing for Trust-UI (`/trust/`) and Admin Console (`/admin/`) directly through proxy ([#238](https://github.com/onixus/bsdm-proxy/pull/238))
- **Trust-UI End-User Portal (Phases 1-5)** — Live policy streaming, client device posture, threat status UI, and container integration ([#234](https://github.com/onixus/bsdm-proxy/pull/234)-[#237](https://github.com/onixus/bsdm-proxy/pull/237))
- **DoH (RFC 8484) & DoT (RFC 7858) Encrypted DNS Gateways** — Inbound DoH (`/dns-query`) and DoT (TCP/853 TLS) listeners for `dns-sinkhole`, wireformat base64url decoding, 2-byte TCP framing, and `admin-console` encrypted DNS panel ([#204](https://github.com/onixus/bsdm-proxy/pull/204))
- **Admin Console RPZ Sinkhole Module (`/rpz`)** — RPZ list parsing, feed management, custom overrides, and DNS query simulator ([#108](https://github.com/onixus/bsdm-proxy/issues/108))
- **Admin Console Wasm Plugins Module (`/wasm`)** — Interactive Wasm Request Sandbox, WAT source viewer, plugin directory, and engine settings ([#188](https://github.com/onixus/bsdm-proxy/issues/188))
- **Admin Console ICAP Inspection & DLP Module (`/icap`)** — RFC 3507 ICAP scanning sandbox, Threat Log audit table, and service profile management ([#99](https://github.com/onixus/bsdm-proxy/issues/99))
- **Admin Console gRPC Control Plane Mesh Module (`/cluster`)** — Multi-node cluster topology grid, real-time gRPC policy push, and cluster-wide cache purge ([#187](https://github.com/onixus/bsdm-proxy/issues/187))
- **eBPF / XDP Kernel Packet Drop Bypass Module** — Zero-CPU packet drops at NIC driver layer (`EBPF_XDP_ENABLED`), reference `bpf/xdp_drop.c`, and `admin-console` eBPF Policies panel
- **Admin Console AI Semantic Cache & Vector DB Module (`/ai-cache`)** — Qdrant vector match simulator, cosine similarity tuning, token savings analytics ($285.00/24h) ([#189](https://github.com/onixus/bsdm-proxy/issues/189))

## [0.5.7+033] - 2026-07-17

Release **0.5.07.033** (Cargo/semver `0.5.7+033`). Post-M5: DX control plane, Wasm, AI traffic helpers, P3 ICAP + DNS sinkhole.

### Added

- **DNS sinkhole sidecar** — workspace crate `dns-sinkhole` (UDP RPZ-lite proxy); ADR 0004; compose profile `dns-sinkhole`; docs [dns-sinkhole.md](docs/features/dns-sinkhole.md) ([#108](https://github.com/onixus/bsdm-proxy/issues/108))
- **ICAP adapter PoC** — env `ICAP_ENABLED` / `ICAP_URL`; REQMOD before upstream + RESPMOD on buffered MISS; compose profile `icap` (c-icap/ClamAV); docs [icap.md](docs/features/icap-inspection.md) ([#99](https://github.com/onixus/bsdm-proxy/issues/99))
- **Wasm plugin host PoC** — Cargo feature `wasm` (Wasmtime); post-auth request hook with fuel limits; PoC `examples/wasm/deny_blocked_suffix.wat`; docs [wasm-plugins.md](docs/features/wasm-plugins.md) ([#188](https://github.com/onixus/bsdm-proxy/issues/188))
- **DX gRPC control plane** — optional Cargo feature `grpc`; proto `proxy/proto/control_plane.proto`; `CONTROL_GRPC_ENABLED` / `CONTROL_GRPC_BIND`; mirrors REST stats/purge/hierarchy/upstream TLS ([#187](https://github.com/onixus/bsdm-proxy/issues/187))
- **Hierarchy peer mTLS** — `HIERARCHY_PEER_MTLS_*` wraps peer HTTP fetch in TLS + client cert ([#103](https://github.com/onixus/bsdm-proxy/issues/103))
- **Semantic vector backend** — pluggable similarity index (`SEMANTIC_VECTOR_BACKEND=local|qdrant`) + optional HTTP embed provider; metric `bsdm_proxy_semantic_cache_vector_errors_total` ([#189](https://github.com/onixus/bsdm-proxy/issues/189))
- **AI semantic / LLM cache prep** — `SEMANTIC_CACHE_ENABLED` POST body-hash cache for chat/completions paths; optional local cosine near-hit; docs [semantic-cache.md](docs/features/semantic-cache.md)
- **AI API-key rate limiting** — token bucket per API key (`RATE_LIMIT_API_KEY_*`); key from `X-API-Key` or `Authorization: Bearer`; optional `RATE_LIMIT_API_KEY_REQUIRED` → 401; metric label `api_key` / `api_key_missing`
- **AI request coalescing** — singleflight for concurrent GET/HEAD cache MISSes (`MISS_COALESCE_ENABLED`); waiters serve `COALESCED-HIT`; metric `bsdm_proxy_cache_coalesced_total`
- **DX upstream TLS hot reload** — `GET /api/upstream/tls`, `POST /api/upstream/tls/reload`; rebuilds Hyper client pool from `UPSTREAM_CA_CERT` / `UPSTREAM_HTTP2_ENABLED` (`ArcSwap`)
- **DX hierarchy peer hot reload** — `GET /api/hierarchy/peers`, `POST /api/hierarchy/reload`; optional `CACHE_PEERS_PATH` / `HIERARCHY_PEERS_PATH` JSON; discovery siblings preserved
- **DX Cache-Tag purge** — L1 secondary index for `Cache-Tag` / `Surrogate-Key`; `POST /api/cache/purge` accepts `tag` / `tags` (+ L2 key delete)
- **DX Phase 2 control plane** — ACL CRUD (`PUT`/`DELETE`/`persist`), `GET /api/stats` Lite JSON, `POST /api/cache/purge`; admin-console Policies delete/persist; [docs/features/control-plane.md](docs/features/control-plane.md)
- **Lite B21 — optional Kafka feature** — `kafka` Cargo feature (default on) for `bsdm-proxy` and `cache-indexer`; Lite Docker build uses `--no-default-features` (no `rdkafka` link) ([#52](https://github.com/onixus/bsdm-proxy/issues/52))
- **M5.5 threat score write-back** — `ml-worker` publishes to `threat_score_cache` + `GET /api/threat-scores`; proxy optional async poll enriches `threat_sources` / block ([#169](https://github.com/onixus/bsdm-proxy/issues/169))
- **Admin console** — Threat scores page (M5.5 snapshot + XAI); dashboard uses live write-back API
- **M5.4 C&C beacon ML** — `cc_beacon_v0`: augments M4 `beacon_periodic` with behavioral signals (POST ratio, small payloads, off-hours); `beacon_pair_features` table; Grafana panel; `scripts/ml/eval_cc_beacon.py` ([#168](https://github.com/onixus/bsdm-proxy/issues/168))
- **M5.3 lexical phishing** — `phishing_lexical_v0`: domain lexical heuristics + weak labels from PhishTank / UT1 / `phishing` category; `domain_phishing_features` table; Grafana panel; `scripts/ml/eval_phishing_lexical.py` ([#167](https://github.com/onixus/bsdm-proxy/issues/167))
- **Admin console (UI/UX)** — React + Tailwind SPA in `admin-console/`: unified dashboard, logs with explainable ML (XAI), policies, settings; migrates `web-config` export logic
- **M5.2 UEBA z-score** — `ueba_zscore_v0` (default): population baseline from `entity_features` or `ML_BASELINE_PATH`; Grafana anomalous-entities panel; `scripts/ml/export_baseline.py` + `compare_stub_vs_ueba.py` ([#166](https://github.com/onixus/bsdm-proxy/issues/166))
- **M5.1 ML worker scaffold** — crate `ml-worker` extracts entity windows into ClickHouse `entity_features`, scores with `anomaly_stub_v0` into `ml_scores`, optional webhook; compose profile `ml`, packaging/systemd; ADR 0003 / [docs/analytics/ml-security.md](docs/analytics/ml-security.md) (B15 / #46)

### Documentation

- **Squid rock ↔ BSDM spill sizing** — [docs/architecture/capacity-planning.md](docs/architecture/capacity-planning.md) mapping + HA example ([#101](https://github.com/onixus/bsdm-proxy/issues/101))
- **Issue tracker hygiene** — [docs/project-status.md](docs/project-status.md); close completed epics #165/#125/#102/#112; backlog #187 gRPC, #188 Wasm, #189 vector DB; BLOCKERS wave 3 strikethrough
- **Project docs refresh** — README / architecture / development / structure / docker / deployment / wiki index / env.example aligned with M1–M5 done and DX/AI Unreleased (Lite = proxy+SQLite, control plane, event sink, hierarchy peers paths, threat-score vars)

Release package: `./scripts/build-package.sh` → `dist/bsdm-proxy-0.5.7.033-linux-<arch>.tar.gz`
Notes: [docs/releases/v0.5.7+033.md](docs/releases/v0.5.7+033.md)

## [0.5.0] - 2026-07-16

Milestone **M4 Threat analytics**: rule-based alerts, C&C / Shannon heuristics, Grafana Unified Alerting.

### Added

- **M4 Grafana Unified Alerting + Alertmanager** — provisioned rules (`grafana/alerting/`), Prometheus `m4_threat` alerts, compose `alertmanager` service; closes M4 roadmap
- **M4 Shannon / high-entropy domains** — `high_entropy_domain` uses Shannon entropy on the leftmost DNS label (`ALERT_SHANNON_MIN_BITS`, modes `shannon|legacy|either`); Grafana long-domain candidates panel
- **PhishTank API key** — `PHISHTANK_API_KEY` sent as `app_key`; category cache keeps feed source for `threat_sources`
- **M4 beacon heuristic (B18)** — `beacon_periodic` rule in `alert-worker` (regular client→domain gaps); Grafana “Beacon candidates” panel; docs
- **Lite SQLite indexer** — `INDEX_STORE=sqlite|memory`, `POST /api/events`, proxy `EVENT_SINK_URL`; Lite compose includes indexer ([docs/getting-started/lite-mode.md](docs/getting-started/lite-mode.md))
- **Lite compose (Phase 1)** — [`docker-compose.lite.yml`](docker-compose.lite.yml) standalone proxy (no Kafka/CH); [`scripts/gen-ca.sh`](scripts/gen-ca.sh); docs [`docs/getting-started/lite-mode.md`](docs/getting-started/lite-mode.md)
- **Alert worker (B19 / #50)** — `alert-worker` polls ClickHouse threat rules and POSTs SIEM JSON webhooks; compose profile `alerts`, Dockerfile target, Prometheus scrape, docs [`docs/analytics/alerting.md`](docs/analytics/alerting.md)
- **Strategic roadmap** — Lite / DX / Wasm / AI-traffic phases in [`docs/roadmap.md`](docs/roadmap.md)
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

- OpenSearch users: migrate to ClickHouse — see [docs/releases/v0.3.1.md](docs/releases/v0.3.1.md) and [clickhouse-analytics.md](docs/analytics/clickhouse-retrosearch.md)
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

[0.5.7+033]: https://github.com/onixus/bsdm-proxy/compare/v0.5.0...v0.5.7+033
[0.5.0]: https://github.com/onixus/bsdm-proxy/compare/v0.3.2...v0.5.0
[0.3.2]: https://github.com/onixus/bsdm-proxy/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/onixus/bsdm-proxy/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/onixus/bsdm-proxy/compare/v0.2.3-test...v0.3.0
[0.2.3-test]: https://github.com/onixus/bsdm-proxy/releases/tag/v0.2.3-test
[0.2.2b]: https://github.com/onixus/bsdm-proxy/releases/tag/v0.2.2b
