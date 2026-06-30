# Changelog

All notable changes to BSDM-Proxy are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.3.0]: https://github.com/onixus/bsdm-proxy/compare/v0.2.3-test...v0.3.0
[0.2.3-test]: https://github.com/onixus/bsdm-proxy/releases/tag/v0.2.3-test
[0.2.2b]: https://github.com/onixus/bsdm-proxy/releases/tag/v0.2.2b
