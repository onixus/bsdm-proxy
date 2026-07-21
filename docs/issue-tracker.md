# GitHub issue tracker status

Snapshot of open / recently completed work. Live list: [open issues](https://github.com/onixus/bsdm-proxy/issues?q=is%3Aissue+is%3Aopen).

> Cloud agent tokens can **create** issues but often cannot **close** them (GitHub App 403). Completed work is closed via PR `Closes #N` keywords or by a maintainer.

## Completed — close / auto-close

| Issue | Title | Resolution |
|-------|-------|------------|
| [#165](https://github.com/onixus/bsdm-proxy/issues/165) | M5 epic | Done — M5.1–M5.5 (#166–#169) |
| [#125](https://github.com/onixus/bsdm-proxy/issues/125) | OpenSearch → ClickHouse epic | Done — ADR 0002 cutover |
| [#102](https://github.com/onixus/bsdm-proxy/issues/102) | Event schema `acl_action` / `threat_sources` | Done in ClickHouse (B16); OS criteria obsolete |
| [#112](https://github.com/onixus/bsdm-proxy/issues/112) | Web config ACL UI | Superseded by `admin-console/` Policies |
| [#186](https://github.com/onixus/bsdm-proxy/issues/186) | Permission probe | Invalid — close |
| [#190](https://github.com/onixus/bsdm-proxy/issues/190) | Tracker hygiene meta | Close when the above are closed |
| [#99](https://github.com/onixus/bsdm-proxy/issues/99) | ICAP adapter & UI | Done — #195, #200 |
| [#108](https://github.com/onixus/bsdm-proxy/issues/108) | DNS sinkhole & UI | Done — #197, #200 |
| [#188](https://github.com/onixus/bsdm-proxy/issues/188) | Wasm plugins & UI | Done — #200 |
| [#187](https://github.com/onixus/bsdm-proxy/issues/187) | gRPC control plane & Mesh UI | Done — #201 |
| [#189](https://github.com/onixus/bsdm-proxy/issues/189) | Vector DB & AI Cache UI | Done — #202 |

Blockers B1–B26: all ✅ in [BLOCKERS.md](BLOCKERS.md) (GitHub #32–#56).

## Still valid open

| Issue | Title | Notes |
|-------|-------|-------|
| — | — | No open P3 backlog items |

## Next strategic backlog

| Issue | Phase |
|-------|-------|
| — | Optional polish (Wasm SDK, ICAP TLS, DoH) or new epic |

*(#99 ICAP / #108 DNS / #187 gRPC Mesh / #188 Wasm / #189 AI Cache closed via implementation PRs #200, #201, #202.)*


---

*Updated: 2026-07-21*
