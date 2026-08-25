# ADR 0007: Safe Selective MITM & Circuit Breaker for Certificate Pinning

- **Status**: Accepted
- **Date**: 2026-08-24
- **Deciders**: BSDM Core Security & Architecture Team
- **Issues**: #322, #328
- **Operator procedure**: [certificate-pinning.md — MITM circuit breaker: detection and operator reset](../features/certificate-pinning.md#mitm-circuit-breaker-detection-and-operator-reset) · tuning: [configuration.md](../ops-and-dev/configuration.md#mitm-circuit-breaker)

## Context

Corporate TLS MITM inspection creates availability risks when upstream services or client applications employ Certificate Pinning (e.g. mobile apps, desktop clients like Slack/Teams, or native OS updaters). When TLS termination fails due to certificate generation errors or client handshake rejections (pinning violations):

1. Unhandled repeated failures can disrupt critical business applications.
2. Ad-hoc local exception files without mutation tokens or audit trails lead to configuration drift across cluster nodes and violate compliance/audit standards.

## Decision

1. **Automatic MITM Circuit Breaker**:
   - Implement a per-domain failure window (default: $\ge 5\%$ failures with minimum 5 samples over 60 seconds).
   - On exceeding threshold, the proxy automatically trips the breaker for that domain, immediately switching to blind `CONNECT` tunneling (`decision_source: "pinning-bypass"`, `bypass_reason: "circuit_breaker_tripped"`).
   - The tripped domain remains bypassed until manually reset by an operator or until cooldown expiry.

2. **Centralized Verified Pinning Exceptions & Mutation Token**:
   - Pinning exceptions and circuit breaker resets must be executed through authenticated Control API endpoints (`/api/mitm/circuit-breaker/reset`, `/api/pinning/exceptions`) requiring Bearer tokens.
   - All exception additions, removals, and breaker trip/reset events are written to an append-only audit trail (`PINNING_AUDIT_LOG_PATH`).

3. **Telemetry & Observability**:
   - Every bypass is tagged with `decision_source: "pinning-bypass"` in events and metrics (`bsdm_proxy_policy_decision_source_total`).
   - Circuit breaker status and tripped domain list are exposed at `GET /api/mitm/circuit-breaker`.

4. **Documented reset path**: recognising a trip, the pre-reset checks, the exact `POST /api/mitm/circuit-breaker/reset` payload (`domain`, `actor`, `reason`) and the choice between a reset and a pinning exception are documented for operators in [certificate-pinning.md](../features/certificate-pinning.md#mitm-circuit-breaker-detection-and-operator-reset). Tuning variables (`MITM_CIRCUIT_BREAKER_*`) are documented in [configuration.md](../ops-and-dev/configuration.md#mitm-circuit-breaker).

## Consequences

### Positive

- **Availability First**: Prevents mass outages of corporate services caused by unexpected pinning changes or certificate generation errors.
- **Auditable & Compliant**: Every trip and exception mutation is immutably logged with actor, timestamp, domain, and reason.
- **Fail-Closed Hardening**: Unauthenticated mutations are rejected.

### Negative

- Blind `CONNECT` tunnels lose payload inspection (DLP/content filtering) for the duration of the bypass. Availability is prioritized over inspection during incidents.
