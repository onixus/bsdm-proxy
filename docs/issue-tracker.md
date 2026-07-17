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
| [#99](https://github.com/onixus/bsdm-proxy/issues/99) | ICAP adapter | Done — #195 |
| [#108](https://github.com/onixus/bsdm-proxy/issues/108) | DNS sinkhole | Done — #197 (merge) |

Blockers B1–B26: all ✅ in [BLOCKERS.md](BLOCKERS.md) (GitHub #32–#56).

## Still valid open

| Issue | Title | Notes |
|-------|-------|-------|
| — | — | No open P3 backlog items |

## Next strategic backlog

| Issue | Phase |
|-------|-------|
| — | Optional polish (Wasm SDK, ICAP TLS, DoH) or new epic |

*(#99 ICAP / #108 DNS closed via implementation PRs; #101 / #103 / #189 / #187 / #188 closed earlier.)*


---

*Updated: 2026-07-17*
