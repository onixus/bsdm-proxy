# Changelog

All notable changes to BSDM-Proxy are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.13] - 2026-08-21

Patch after **0.9.12**: Threat intelligence feed collector framework (`threat-intel`), proxy hot-path zero-allocation and lock-free optimizations, ACL category policies and domain fallbacks, redesigned interactive installer, and security/dependency updates.

### Added

- **Threat intelligence feed collector** (`threat-intel`, TASK-TI-001) — optional
  worker that ingests OpenPhish, PhishStats, Phishing.Database and URLhaus on a
  schedule through per-source plugins, with per-source retry/backoff, intra-batch
  deduplication, response-size and per-fetch caps, Prometheus metrics on
  `:8093/metrics`, JSONL snapshots plus `report.json`, and a `TI_RUN_ONCE`
  one-shot mode. Ships as a Compose profile (`--profile threat-intel`), a Helm
  toggle (`threatIntel.enabled`), a systemd unit and a packaged env example.
  Collection is metadata-only: the collector never requests a collected
  indicator. Storage, scoring and ACL/RPZ enforcement are not part of this
  change. See
  [docs/features/threat-intel-collector.md](docs/features/threat-intel-collector.md).
- **ACL category fallbacks & default policies** — added built-in dataset definitions
  for social networks (`acl-social-networks.txt`), cloud file hosting
  (`acl-cloud-file-hosting.txt`), and cloud CDN/API endpoints (`acl-cloud-cdn-apis.txt`)
  with deny policies for social networks and cloud file hosting.
- **Redesigned interactive installer** — streamlined `./install.sh` and
  `scripts/interactive-install.sh` with portable helper logic, root requirement
  deferral, and installer validation workflow.
- **Local Jenkins pipeline** — restored Docker-based pipeline in `Jenkinsfile.local`
  and tag publisher `Jenkinsfile.publish` with SAST (Semgrep) and Gitleaks gates.

### Changed

- **Request hot-path optimization** — reduced per-request allocations and lock
  contention across the proxy core. No configuration, wire format, or policy
  semantics change; the cache key stays SHA-256 hex so ICP/HTCP/cache-digest
  peers are unaffected.
  - `AclEngine::check_access` no longer deep-clones the whole rule set on every
    request; rules are matched in place on the `ArcSwap` snapshot, and regexes
    resolve by rule index instead of by hashing the pattern string.
  - `PolicyDecisionCache` is sharded (`RwLock` per shard) instead of one global
    `Mutex`, looks up through a thread-local key buffer instead of allocating a
    principal and domain `String` per request, and evicts from a bounded sample
    instead of scanning every entry under the lock.
  - Domain extraction slices the host out of plain ASCII URLs directly, falling
    back to `Url::parse` for IDNA/punycode, percent escapes and IPv6 literals;
    a differential test pins the fast path to the parser's output.
  - Category suffix matching (`UT1` / custom DB / RKN) walks borrowed slices of
    the host instead of building a `Vec<String>` of joined suffixes.
  - Cache-event construction is skipped entirely when no Kafka or HTTP sink is
    configured, and the ICAP request-header map is only built when an
    adaptation stage will read it.
  - MISS requests only clone their headers for a peer fetch when a cache
    hierarchy is actually configured, and the redundant second URL parse on the
    MISS path is gone.
  - Rate limiting short-circuits before touching headers when disabled (the
    default), matches the API-key header by hashed lookup instead of scanning
    every header, and reuses existing token buckets without re-allocating keys.
  - Prometheus labels for method, status code, and cache status come from a
    static vocabulary instead of a `String` per request.
  - L1 cache shard selection uses a fast mixer rather than SipHash over the
    64-byte digest key; per-request event/metric sampling uses an atomic counter
    rather than an RNG draw, which also makes the 1-in-N rate exact.
  - `client_ip` is shared per connection as `Arc<str>` instead of copied per
    request.
- **Compose profiles path** — consolidated deployment profile compose files under
  `deploy/compose/`.
- **Admin Console polish** — repaired mixed-language UI strings and polished layout.

### Fixed

- **Dependency security** — bumped `h2` to `0.4.16` for RUSTSEC-2026-0258.
- **Event sampling rate** — `KAFKA_SAMPLE_RATE` was consulted twice on the cache
  MISS and DLP-violation paths, so the effective emit rate was 1-in-N² rather
  than the configured 1-in-N. Sampling is now applied once, at dispatch.
- **Admin Console configuration and tokens** — fixed config persistence on Apply
  and API token bootstrapping.
- **Flaky compression config test** — `cache_compress` unit tests mutated the
  process-global `CACHE_COMPRESSION` without synchronizing, so the two env tests
  raced and either could observe the other's value. They now take the same
  `env_lock()` guard used by the `upstream` tests. Pre-existing on `main`;
  reproduced there in 3 of 8 runs.


## [0.9.12] - 2026-08-12

Patch after **0.9.11**: hardened RKN registry ACL enforcement and registry-source resilience.

### Added

- **RKN fallback source** — configurable `RKN_FALLBACK_URL` with a domain-only Re-filter fallback when the primary scoped registry feed fails validation or fetch.
- **Last-known-good RKN snapshot** — validated registry state persists to `RKN_SNAPSHOT_PATH` and is restored on startup.
- **RKN source provenance** — audit/log matches carry the selected registry source.

### Changed

- **Scoped RKN matching** — URL, domain, and literal-IP records retain their original scope; IPs attached to domain/URL rows are no longer promoted into broad IP blocks.
- **Readiness semantics** — when RKN sync is enabled, `/ready` fails closed until a validated live or persisted registry is available; `/health` remains liveness-only.
- **Registry refresh safety** — minimum entry validation, atomic registry replacement, cache invalidation on revision, and retention of the active/LKG registry on bad feeds.

### Fixed

- **Tokio startup safety** — RKN background sync scheduling no longer assumes an active runtime during engine construction.
- **Clippy compatibility** — use a concise char-pattern split accepted by the current Rust lint gate.


## [0.9.11] - 2026-08-06

Patch after **0.9.10**: Admin Console foundations, fixture-backed browser
smoke testing, control-plane/RPZ integration, and release pipeline hardening.

### Added

- **Fixture-backed Admin Console smoke test** — production build is driven by
  Chromium over all supported and frozen routes without Kafka, ClickHouse, the
  proxy data-plane, or the ML worker. CI rejects console errors, failed requests,
  demo-data fallback, missing fixture markers, and broken SPA navigation.
- **Same-origin Search proxy** — control plane proxies `GET /api/search*` and
  `POST /api/events` to `SEARCH_UPSTREAM_URL`.
- **RPZ management API** — file-backed `/api/dns/rpz/*`, sinkhole configuration,
  zone compilation, and live dns-sinkhole reload support.
- **Product agent binary** — `bsdm-agent` is the preferred product binary name.

### Changed

- **Admin Console foundations** — shared design tokens, reusable surfaces,
  command palette navigation, decomposed Dashboard, Logs, Analytics, and Settings,
  URL-synchronised tabs, consistent focus handling, and reduced-motion support.
- **Release validation** — manifest, lockfile, changelog, Rust, Admin Console,
  browser smoke, package checksum, SBOM, and provenance checks are release gates.

### Fixed

- **Settings Apply safety** — sends a delta against live configuration, does not
  persist masked secrets, and confirms sensitive path changes.
- **RPZ startup inside Tokio** — avoids blocking-lock use on the active runtime.
- **Mock static path boundary** — prevents sibling-prefix and `..` traversal.
- **Generated RPZ state** — runtime zone output is no longer tracked by Git.
- **Admin Console Docker build** — exposes the product version from the manifest.

## [0.9.10] - 2026-08-05

Patch after **0.9.9**: pilot polish + agent fleet packaging residual.

### Added

- **Agent fleet packaging (MDM/GPO residual)** — silent install flags on
  Linux/macOS/Windows installers; `packaging/agent/fleet/` with Intune Win32
  scripts, GPO ADMX/ADML + registry→env script, macOS `pkgbuild` + mobileconfig
  example, Linux silent wrapper, `scripts/build-agent-fleet-packages.sh`;
  guide [pilot-agent-fleet.md](docs/getting-started/pilot-agent-fleet.md).
  Packages remain **unsigned** (signing/notarization = customer pipeline).
- **Admin Console in proxy image** — multi-stage Docker build copies
  `admin-console/dist` to `/opt/bsdm/admin-console`; `ADMIN_CONSOLE_DIR` set by
  default. Day-1 pilot: `http://localhost:9090/admin/` without host mount.
- **Search API CORS (cache-indexer)** — reflect localhost / 127.0.0.1 Origin,
  `OPTIONS` preflight; Admin Console on `:9090` can call Search on `:8080`.

### Fixed

- **HTTP L1 cache HIT framing** — strip hop-by-hop / `transfer-encoding` /
  stale `content-encoding` when serving buffered cache bodies (avoids hyper
  `user sent unexpected header` on keep-alive reuse).
- **dns-sinkhole zone dir** — create `/etc/bsdm-proxy` as root with `+x` so
  non-root `bsdm` can load RPZ.
- **Admin Console defaults** — `HTTP_PORT` / OIDC redirect default **3128**
  (was 1488).

### Docs

- Pilot day-1: Admin Console baked-in, Search CORS, ACL/CONFIG writable paths,
  macOS DNS host port note (`:15353`).
- Fleet rollout guide and roadmap Phase C residual split (scaffolding vs signed store).

## [0.9.9] - 2026-08-05

Patch after **0.9.8**: CI stabilization — clippy fix for agent system-proxy
on Linux, CI workflow permissions for Code Scanning.

### Fixed

- **agent-spike clippy (`needless_return`)** — Linux CI failed on
  `system_proxy` cfg branches; platform `*_impl` helpers without trailing
  `return`.
- **CI workflow permissions** — explicit permissions on `ci.yml` (#295 /
  code scanning alert).

## [0.9.8] - 2026-08-05

Patch release after **0.9.7**: Phase C agent **productization slice** —
WebSocket policy push, TLS OCSP stapling, multi-node Redis registry/CRL,
multi-OS pilot installers + system proxy (#273).

### Added

- **Multi-OS agent install + system proxy (#273)** — `agent-spike` hooks
  `--set-system-proxy` / `--clear-system-proxy` / `--manage-system-proxy`
  (macOS `networksetup`, Linux gsettings + env snippet, Windows WinINET/netsh);
  pilot packages under `packaging/agent/` (Linux/macOS/Windows installers,
  systemd, LaunchDaemon, Scheduled Task); `scripts/build-agent-binaries.sh`.
- **Multi-node agent device registry + CRL (Redis)** — write-through HASH +
  token/fingerprint/serial indexes (`AGENT_DEVICES_REDIS_URL` or
  `REDIS_URL` + `AGENT_DEVICES_REDIS=true`; prefix `AGENT_REDIS_PREFIX`,
  default `bsdm:agent:`). Shared enroll/heartbeat/revoke/auth across proxy
  nodes; file path (`AGENT_DEVICES_PATH` / `AGENT_CRL_PATH`) remains optional
  local durability.
- **TLS OCSP stapling (data-plane MITM + control mTLS)** — CA-signed RFC 6960
  **good** staple attached via rustls `with_single_cert_with_ocsp`; default on
  (`TLS_OCSP_STAPLING=0` to disable); refresh `TLS_OCSP_STAPLE_REFRESH_SECS`
  (default 900s). Separate from agent client-cert OCSP API.
- **Agent policy WebSocket push (#273)** — `GET /api/v1/agent/policy/ws`
  (RFC 6455 upgrade); server sends full policy JSON text frames on publish;
  HTTP/1 upgrades enabled on metrics + mTLS control ports; `agent-spike`
  `AGENT_POLICY_WS=1` / `--policy-ws`.

## [0.9.7] - 2026-08-04

Patch release after **0.9.6**: agent **RFC 6960 DER OCSP** and **gRPC policy**
product path (Get/Push/Watch) (#273).

### Added

- **Agent OCSP DER responder (#273)** — RFC 6960
  `POST /api/v1/agent/ocsp` (`application/ocsp-request` →
  `application/ocsp-response`), CA-signed (ECDSA P-256 or RSA); optional
  `GET ?b64=`; public (no Bearer); JSON status API retained at `/ocsp/status`.
- **gRPC agent policy product path (`--features grpc`)** —
  `GetAgentPolicy`, `PushAgentPolicy`, server-stream `WatchAgentPolicy` on the
  existing control gRPC service (same policy hub as HTTP long-poll/SSE).

## [0.9.6] - 2026-08-04

Patch release after **0.9.5**: agent **CRL + lab OCSP**, control-plane
**agent_api** extract, and Admin Console **Devices** operator surface (#273).

### Changed

- **Agent API module extract** — Agent Contract HTTP handlers moved from
  monolithic `control_api` into `proxy/src/agent_api.rs` (`dispatch_agent`);
  same routes/auth (`/api/v1/agent/*`, `/api/v1/devices`).
- **Admin Console Agent Devices** — supported route `/devices` (nav + i18n):
  device registry list/revoke, policy snapshot + push, recent events, CRL
  summary via `admin-console/src/api/agent.ts`.

### Added

- **Agent OCSP status API (#273)** — lab JSON
  `GET /api/v1/agent/ocsp/status?fingerprint=|&serial=` (`good`/`revoked`/`unknown`)
  backed by enroll registry + CRL; enroll returns `ocsp_status_url`; not full
  RFC 6960 DER wire format (documented).
- **Agent cert CRL (#273)** — fingerprint + serial revocation store
  (`AGENT_CRL_PATH`); revoke adds cert to CRL; `GET /api/v1/agent/crl` (JSON)
  and `GET /api/v1/agent/crl.pem` (CA-signed X.509 when CA allows CrlSign);
  mTLS `CONTROL_MTLS_CHECK_CRL` (default on when mTLS enabled).

## [0.9.5] - 2026-08-04

Patch release after **0.9.4**: agent **policy push** (long-poll, SSE, operator
notify) so on-device agents pick up policy changes without waiting for the
heartbeat pull cycle.

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
- **Lite compose (Phase 1)** — [`docker-compose.lite.yml`](deploy/compose/docker-compose.lite.yml) standalone proxy (no Kafka/CH); [`scripts/gen-ca.sh`](scripts/gen-ca.sh); docs [`docs/getting-started/lite-mode.md`](docs/getting-started/lite-mode.md)
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

[Unreleased]: https://github.com/onixus/bsdm-proxy/compare/v0.9.13...HEAD
[0.9.13]: https://github.com/onixus/bsdm-proxy/compare/v0.9.12...v0.9.13
[0.9.12]: https://github.com/onixus/bsdm-proxy/compare/v0.9.11...v0.9.12
[0.9.11]: https://github.com/onixus/bsdm-proxy/compare/v0.9.10...v0.9.11
[0.9.10]: https://github.com/onixus/bsdm-proxy/compare/v0.9.9...v0.9.10
[0.9.9]: https://github.com/onixus/bsdm-proxy/compare/v0.9.8...v0.9.9
[0.9.8]: https://github.com/onixus/bsdm-proxy/compare/v0.9.7...v0.9.8
[0.9.7]: https://github.com/onixus/bsdm-proxy/compare/v0.9.6...v0.9.7
[0.9.6]: https://github.com/onixus/bsdm-proxy/compare/v0.9.5...v0.9.6
[0.9.5]: https://github.com/onixus/bsdm-proxy/compare/v0.9.4...v0.9.5
[0.9.4]: https://github.com/onixus/bsdm-proxy/compare/v0.9.3...v0.9.4
[0.9.3]: https://github.com/onixus/bsdm-proxy/compare/v0.9.2...v0.9.3
[0.9.2]: https://github.com/onixus/bsdm-proxy/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/onixus/bsdm-proxy/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/onixus/bsdm-proxy/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/onixus/bsdm-proxy/compare/v0.5.7+033...v0.8.0
[0.5.7+033]: https://github.com/onixus/bsdm-proxy/compare/v0.5.0...v0.5.7+033
[0.5.0]: https://github.com/onixus/bsdm-proxy/compare/v0.3.2...v0.5.0
[0.3.2]: https://github.com/onixus/bsdm-proxy/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/onixus/bsdm-proxy/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/onixus/bsdm-proxy/compare/v0.2.3-test...v0.3.0
[0.2.3-test]: https://github.com/onixus/bsdm-proxy/releases/tag/v0.2.3-test
[0.2.2b]: https://github.com/onixus/bsdm-proxy/releases/tag/v0.2.2b
