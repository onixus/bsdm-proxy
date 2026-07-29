# ADR 0005: Local Policy Agent vs Tunnel-First Architecture

- **Status**: Accepted
- **Date**: 2026-07-29
- **Deciders**: BSDM Core Architecture Team
- **Issues**: #257

## Context and Problem Statement

Modern Secure Web Gateways (SWG) and ZTNA solutions historically relied on full-tunnel traffic redirection (sending all enterprise endpoint traffic through a centralized proxy cluster for TLS decryption and policy enforcement).

In 2026, full-tunnel MITM suffers from severe operational degradation:
- Certificate Pinning in desktop & mobile apps (e.g. Slack, Teams, Zoom, iOS/Android system services).
- Encrypted Client Hello (ECH) and QUIC/HTTP3 transport protocols.
- User privacy concerns and performance latency penalties.

We must decide the architectural direction for Phase C Agent development: **Local Policy Agent (On-Device enforcement)** vs **Tunnel-First (Centralized proxy redirection)**.

---

## Decision Driver Options

1. **Option A: Tunnel-First (Central Proxy Redirection)**
   - All endpoint traffic redirected via WireGuard / AmneziaWG / IPsec tunnel to centralized proxy.
   - Central proxy performs DNS, SNI, and MITM inspection.

2. **Option B: Local Policy Agent (On-Device Policy Engine)**
   - Endpoint runs a lightweight local agent with embedded policy engine.
   - DNS filtering and SNI inspection executed locally on device.
   - Central proxy or selective tunnel used ONLY for high-risk selective MITM traffic.

---

## Decision Outcome

**Chosen Option**: **Option B — Local Policy Agent**.

### Rationale
1. **Performance**: 90%+ of web policy decisions (DNS RPZ & SNI domain matching) execute locally without network roundtrips.
2. **Resilience**: Laptops/mobile endpoints remain protected off-network even during temporary cloud control-plane outage.
3. **Bypass Reduction**: Eliminates Certificate Pinning breakage for non-inspected apps by applying SNI filtering prior to any TLS handshake manipulation.
4. **Bandwidth Efficiency**: Saves up to 90% of backhaul bandwidth compared to full-tunneling.

### Consequences

#### Positive
- Native integration with OS proxy settings and local DNS resolvers.
- Unified policy engine shared between proxy daemon and agent.
- Scalable control plane (handles control/telemetry, not heavy data plane forwarding).

#### Negative
- Requires multi-platform agent binaries (Windows, macOS, Linux).
- Operating system level privileges required to bind DNS/proxy listeners.
