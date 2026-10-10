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
   - *Amended in v1.0 (see «Revision 1» below)*: a trip additionally requires failures from at least `MITM_CIRCUIT_BREAKER_MIN_CLIENTS` (default 3) distinct client IPs, and the default cooldown is 900 s instead of «until manual reset».

2. **Centralized Verified Pinning Exceptions & Mutation Token**:
   - Pinning exceptions and circuit breaker resets must be executed through authenticated Control API endpoints (`/api/mitm/circuit-breaker/reset`, `/api/pinning/exceptions`) requiring Bearer tokens.
   - All exception additions, removals, and breaker trip/reset events are written to an append-only audit trail (`PINNING_AUDIT_LOG_PATH`).

3. **Telemetry & Observability**:
   - Every bypass is tagged with `decision_source: "pinning-bypass"` in events and metrics (`bsdm_proxy_policy_decision_source_total`).
   - Circuit breaker status and tripped domain list are exposed at `GET /api/mitm/circuit-breaker`.
   - Since v1.0 every trip increments `bsdm_proxy_mitm_circuit_breaker_trips_total`; production deployments alert on any increase.

4. **Documented reset path**: recognising a trip, the pre-reset checks, the exact `POST /api/mitm/circuit-breaker/reset` payload (`domain`, `actor`, `reason`) and the choice between a reset and a pinning exception are documented for operators in [certificate-pinning.md](../features/certificate-pinning.md#mitm-circuit-breaker-detection-and-operator-reset). Tuning variables (`MITM_CIRCUIT_BREAKER_*`) are documented in [configuration.md](../ops-and-dev/configuration.md#mitm-circuit-breaker).

## Consequences

### Positive

- **Availability First**: Prevents mass outages of corporate services caused by unexpected pinning changes or certificate generation errors.
- **Auditable & Compliant**: Every trip and exception mutation is immutably logged with actor, timestamp, domain, and reason.
- **Fail-Closed Hardening**: Unauthenticated mutations are rejected.

### Negative

- Blind `CONNECT` tunnels lose payload inspection (DLP/content filtering) for the duration of the bypass. Availability is prioritized over inspection during incidents.

## Revision 1 (v1.0, release review)

**Problem found.** The architecture review of v1.0-rc showed that the original
decision let *any single client* disable inspection: five `CONNECT`s to a domain
with one deliberately aborted handshake (5% of 5 samples) tripped the breaker,
and with the old default `MITM_CIRCUIT_BREAKER_COOLDOWN_SECS=0` the domain stayed
on blind `CONNECT` for every user until an operator noticed. A malware implant
could take its own C2 domain — in exactly the category MITM is enabled for — out
of inspection permanently.

**Decision (v1.0):**

1. A trip requires failures from at least `MITM_CIRCUIT_BREAKER_MIN_CLIENTS`
   distinct client IPs (default `3`) in addition to the rate and sample thresholds.
2. Default cooldown is `900` s: the domain returns to MITM automatically.
   `MITM_CIRCUIT_BREAKER_COOLDOWN_SECS=0` keeps the old «until manual reset» mode
   as an explicit choice.
3. Trips are counted in `bsdm_proxy_mitm_circuit_breaker_trips_total`; the
   production guide requires an alert on any increase and a SOC review of each trip
   ([runbook](../ops-and-dev/runbook.md#2-mitm-circuit-breaker-сработал)).

**Residual risk (known issue v1.0).** Three colluding clients (for example, three
infected hosts) can still move a domain to blind `CONNECT` for 15 minutes.

**Planned for 1.1** ([roadmap](../roadmap.md)): count only certificate-distrust
TLS alerts (`unknown_ca`, `bad_certificate`, `certificate_unknown`) rather than
any handshake error (RST/EOF), and fail-closed (block instead of bypass) for
`malware`/`phishing` categories in production.
