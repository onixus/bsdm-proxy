# ADR 0004: DNS sinkhole as sidecar (not in proxy)

**Status:** Accepted
**Date:** 2026-07-17
**Relates:** [#108](https://github.com/onixus/bsdm-proxy/issues/108), [dns-sinkhole.md](../features/dns-sinkhole.md), [swg-backlog-mapping.md](../project-status.md) P3-4

## Context

Enterprise SWGs often advertise a **DNS security** layer (Umbrella-style): resolve-time block/sinkhole before HTTP. BSDM-Proxy is an **explicit forward proxy** with MITM, cache, and ACL. Issue #108 asks for an optional DNS module and a **scope decision**.

## Decision

1. **Do not** embed a DNS server or RPZ engine inside `bsdm-proxy`. DNS is a different on-ramp; coupling it to CONNECT/MITM would confuse ops and fight the documented anti-pattern “DNS-first pipeline as Umbrella”.
2. Ship a **separate workspace binary** `dns-sinkhole`: UDP DNS proxy that applies an RPZ-lite / domain blocklist, then forwards remaining queries to an upstream resolver.
3. Deploy as an **optional Compose profile** (and Docker target), same pattern as `alert-worker` / `ml-worker` / `icap`.
4. Keep the PoC protocol surface small: UDP, single-question queries, A/AAAA answers, NXDOMAIN or fixed sinkhole IPs. Full BIND RPZ, DoH/DoT, and DNSSEC validation are follow-ups.

## Consequences

- New crate `dns-sinkhole`, docs, example zone, Dockerfile stage, compose profile.
- Proxy ACL/UT1 remain the HTTP policy plane; DNS is complementary.
- Closes #108 acceptance: design doc + basic RPZ/DNS proxy sketch (implemented PoC).

## Non-goals

- Replacing corporate Unbound/BIND
- Inline DNS from the proxy process
- Encrypted DNS (DoH/DoT) in v0
