# Architecture blockers B1–B25

Краткий реестр блокеров. Полное описание: [architecture.md](architecture.md)

| GitHub | Скрипт |
|--------|--------|
| Issues [#32–#56](https://github.com/onixus/bsdm-proxy/issues?q=is%3Aissue+in%3Atitle+B) | `./scripts/create-blocker-issues.sh` |

---

## Critical — M1

| ID | Issue | Блокер | Статус |
|----|-------|--------|--------|
| B1 | [#32](https://github.com/onixus/bsdm-proxy/issues/32) | Wire hierarchy modules into binary | ✅ |
| B2 | [#33](https://github.com/onixus/bsdm-proxy/issues/33) | Add `rand` dependency for WeightedStrategy | ✅ |
| B3 | [#34](https://github.com/onixus/bsdm-proxy/issues/34) | Implement HTTP fetch from hierarchy peer | ✅ |
| B4 | [#35](https://github.com/onixus/bsdm-proxy/issues/35) | Start ICP server in proxy runtime | ✅ |
| B5 | [#36](https://github.com/onixus/bsdm-proxy/issues/36) | Make `ca.key` optional when MITM disabled | ✅ |
| B6 | [#37](https://github.com/onixus/bsdm-proxy/issues/37) | Implement rate limiting per user/IP | ❌ |

## High — M2 / M3

| ID | Issue | Блокер | Статус |
|----|-------|--------|--------|
| B7 | [#38](https://github.com/onixus/bsdm-proxy/issues/38) | Refactor ProxyService out of `main.rs` | ✅ |
| B8 | [#39](https://github.com/onixus/bsdm-proxy/issues/39) | Move online categorization off hot path | ❌ |
| B9 | [#40](https://github.com/onixus/bsdm-proxy/issues/40) | Replace ACL global Mutex | ❌ |
| B10 | [#41](https://github.com/onixus/bsdm-proxy/issues/41) | Kafka reliable delivery (topic env, acks) | ❌ |
| B11 | [#42](https://github.com/onixus/bsdm-proxy/issues/42) | Indexer: add `categories` to CacheEvent | ❌ |
| B12 | [#43](https://github.com/onixus/bsdm-proxy/issues/43) | Shared `bsdm-events` crate | ❌ |
| B13 | [#44](https://github.com/onixus/bsdm-proxy/issues/44) | Implement NTLM or remove from docs | ❌ |
| B14 | [#45](https://github.com/onixus/bsdm-proxy/issues/45) | ACL TimeWindow + group rules | ❌ |

## Medium — M3 / M4 / M5

| ID | Issue | Блокер | Статус |
|----|-------|--------|--------|
| B15 | [#46](https://github.com/onixus/bsdm-proxy/issues/46) | Design analytics/ML worker service | ❌ |
| B16 | [#47](https://github.com/onixus/bsdm-proxy/issues/47) | Extend event schema for threat analytics | ❌ |
| B17 | [#48](https://github.com/onixus/bsdm-proxy/issues/48) | OpenSearch Dashboards in docker-compose | ❌ |
| B18 | [#49](https://github.com/onixus/bsdm-proxy/issues/49) | Behavioral threat signals (beyond blocklists) | ❌ |
| B19 | [#50](https://github.com/onixus/bsdm-proxy/issues/50) | Alerting pipeline to SIEM/webhook | ❌ |
| B20 | [#51](https://github.com/onixus/bsdm-proxy/issues/51) | Security analytics dashboards (historical) | ❌ |

## Structural

| ID | Issue | Блокер | Статус |
|----|-------|--------|--------|
| B21 | [#52](https://github.com/onixus/bsdm-proxy/issues/52) | Use Cargo feature flags in main | ❌ |
| B22 | [#53](https://github.com/onixus/bsdm-proxy/issues/53) | Cache refresh + negative caching | ❌ |
| B23 | [#54](https://github.com/onixus/bsdm-proxy/issues/54) | HTTP/2 upstream client | ❌ |
| B24 | [#55](https://github.com/onixus/bsdm-proxy/issues/55) | Fix healthcheck curl vs wget | ❌ |
| B25 | [#56](https://github.com/onixus/bsdm-proxy/issues/56) | Implement or remove REST ACL API | ❌ |

---

## Волны разблокировки

1. **Волна 1 (M1):** ~~B5~~ → ~~B1+B2~~ → ~~B3+B4~~ → **B6** → ~~**B7**~~
2. **Волна 2 (M3):** B12 → B11 → B10 → B17
3. **Волна 3 (M4/M5):** B16 → B15 → B8
