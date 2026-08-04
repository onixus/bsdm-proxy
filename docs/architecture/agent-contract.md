# Agent Contract v0.1

This document defines the specification and interaction contract between the BSDM Control Plane and Local Endpoint Agents (Phase C).

## Overview

The BSDM Agent architecture operates on a **Local Policy Agent** model: policy decision enforcement happens directly on-device using a local policy engine, while the central control plane manages enrollment, policy distribution, heartbeat, and telemetry ingestion.

All Agent Contract v0.1 HTTP endpoints use the canonical
`/api/v1/agent/*` namespace. The unversioned `/api/agent/*` namespace is
deprecated and retained only as a compatibility alias for the implemented
policy and heartbeat endpoints.

### Implementation status

- Implemented: `POST /api/v1/agent/enroll` (device Bearer + optional **CSR →
  client cert** signed by proxy CA), `GET /api/v1/agent/policy`,
  `POST /api/v1/agent/heartbeat`, `POST /api/v1/agent/events` (+ lab recent),
  `GET /api/v1/devices`, revoke.
- Spike client: enroll (`--mtls` for CSR), policy, evaluate, events, heartbeat
  ([pilot-agent.md](../getting-started/pilot-agent.md)).
- Optional transport: `CONTROL_MTLS_ENABLED` HTTPS port requiring client cert.
- Policy push: long-poll `/policy/watch`, SSE `/policy/stream`, operator
  `POST /policy/push` (+ pinning reload notify).
- Agent CRL: JSON + optional X.509 PEM (`/api/v1/agent/crl[.pem]`); mTLS checks CRL.
- Agent OCSP status (lab JSON): `GET /api/v1/agent/ocsp/status?fingerprint=|&serial=`.
- Admin Console: supported `/devices` (list, revoke, policy push, events, CRL).
- Handlers live in `proxy/src/agent_api.rs` (`dispatch_agent`).
- Reserved: RFC 6960 DER OCSP responder, WebSocket/gRPC push productization,
  multi-OS installers, multi-node registry.

---

## 1. Device Enrollment & Identity Binding

### 1.1 Enrollment (token + optional mTLS CSR)

1. Operator sets `AGENT_ENROLL_TOKEN` (or reuses `CONTROL_API_TOKEN` when enroll
   token is unset). Proxy CA is the MITM CA (`CertCache` / `./certs/ca.*`).
2. Agent calls `POST /api/v1/agent/enroll` with Bearer enroll token:
   ```json
   {
     "device_id": "laptop-001",
     "platform": "macos",
     "name": "Alice laptop",
     "user_identity": "alice@corp",
     "capabilities": ["local-proxy"],
     "device_type": "desktop",
     "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\\n...\\n-----END CERTIFICATE REQUEST-----",
     "cert_validity_days": 90
   }
   ```
3. Always returns a **one-time** `device_token` (`bsdmagent_…`); only SHA-256
   hash is stored (`AGENT_DEVICES_PATH`).
4. When `csr_pem` is present and CA is loaded: verifies CSR signature, signs a
   **ClientAuth** certificate bound to:
   - CN / URI SAN `urn:bsdm:device:{device_id}`
   - OU = platform
   - optional email SAN from `user_identity`
   - CSR subject is **not** trusted as identity
5. Response includes `client_cert_pem`, `ca_cert_pem`, `cert_fingerprint`
   (SHA-256 of cert DER), `cert_not_after` when mTLS issued.
6. Agent uses `Authorization: Bearer <device_token>` on HTTP agent APIs; with
   `CONTROL_MTLS_ENABLED`, also presents the client cert on the mTLS port.
7. Revoke clears device token hash and appends the cert to the agent CRL when a
   fingerprint/serial is known.

#### Transport mTLS (optional, separate port)

When `CONTROL_MTLS_ENABLED=true`, a dedicated HTTPS listener
(`CONTROL_MTLS_BIND`, default `:9443`) **requires** a client certificate signed
by the proxy/agent CA. Plain `METRICS_PORT` stays HTTP for scrapers/Admin.

- Paths: `/api/v1/agent/*`, `/api/v1/devices*`, `/health`
- Optional `CONTROL_MTLS_REQUIRE_ENROLLED=true` rejects certs whose fingerprint
  is not on a non-revoked enrolled device
- HTTP Bearer (`device_token` / control token) still applies for API auth

#### Certificate revocation (lab CRL + OCSP status)

- Revoke (`POST /api/v1/devices/{id}/revoke`) clears device token and appends
  `cert_fingerprint` (+ serial when known) to the agent CRL.
- `GET /api/v1/agent/crl` — JSON list for ops / mTLS fingerprint checks.
- `GET /api/v1/agent/crl.pem` — CA-signed X.509 CRL when issuer has `CrlSign`.
- `GET /api/v1/agent/ocsp/status?fingerprint=|&serial=` — lab JSON OCSP-like
  status: `good` | `revoked` | `unknown` (backed by enroll + CRL; not ASN.1).
- Durable store: `AGENT_CRL_PATH`. mTLS: `CONTROL_MTLS_CHECK_CRL` (default on).

#### Reserved

- Full RFC 6960 binary OCSP / stapling.
- Forcing mTLS on the primary metrics port (would break Prometheus scrape).

---

## 2. Policy Fetch & Synchronization

### 2.1 Policy Pull (`GET /api/v1/agent/policy`)
- **Headers**: `Authorization: Bearer <mTLS-token>` or client certificate.
- **Response Payload**:
  ```json
  {
    "policy_version": "v0.1.0",
    "policy_mode": "selective-mitm",
    "mitm_categories": ["malware", "phishing", "illegal-content"],
    "pinning_exceptions": [".slack.com", ".teams.microsoft.com", ".zoom.us"],
    "sni_deny_patterns": ["*.evil.com", "badsite.test"],
    "sni_rules": [
      { "pattern": "*.evil.com", "action": "deny" },
      { "pattern": "badsite.test", "action": "deny" }
    ]
  }
  ```

  **Current control-plane sources:** `policy_mode` / `mitm_categories` from
  proxy env; `pinning_exceptions` from the managed pinning registry; SNI deny
  from `AGENT_SNI_DENY_PATTERNS` (comma-separated) or pilot defaults.
  `dns_sinkhole` / RPZ version is reserved (not yet in this payload).

### 2.2 Policy Push (lab: long-poll + SSE)

- **`GET /api/v1/agent/policy/watch?since={version}&timeout_secs=30`** — long-poll
  until `policy_version` changes (or timeout; response includes `changed` bool).
- **`GET /api/v1/agent/policy/stream`** — SSE (`text/event-stream`); events
  `policy` with full JSON document; comment pings every ~15s.
- **`POST /api/v1/agent/policy/push`** — operator rebuild from env + pinning and
  notify subscribers (`reason`, `actor` optional). Also fired after pinning
  exception reload.
- `policy_version` is a content-derived `v` + hex prefix (advances on each push).

---

## 3. Telemetry & Heartbeat

### 3.1 Heartbeat (`POST /api/v1/agent/heartbeat`)
- Periodicity: Default 60s.
- Contains: `device_id`, `policy_version`, `agent_version`, `status` (`healthy`, `degraded`).
- May include inventory/posture fields used by Trust UI: `name`, `ip`,
  `device_type` (`desktop`, `phone`), `cert_subject`, `cert_fingerprint`,
  and `trust_score` (0–100).
- The proxy keeps the latest heartbeat for each device in its runtime registry.
  `GET /api/v1/devices` exposes only those observed devices; it does not create
  placeholder inventory.
- When `AGENT_DEVICES_PATH` is set, the registry is loaded at process start and
  rewritten after each successful heartbeat or revoke (atomic JSON file).
  Unset → memory-only (lost on restart). Heartbeat/revoke responses include
  `"persisted": true|false`.

### 3.2 Telemetry Ingestion (`POST /api/v1/agent/events`)
- Batched events from on-device evaluation, ingested by the control plane.
- Request body:
  ```json
  {
    "device_id": "laptop-001",
    "events": [
      {
        "domain": "badsite.test",
        "action": "deny",
        "decision_source": "local-agent",
        "timestamp": 1720000000,
        "reason": "SNI exact match",
        "policy_version": "v0.1.0"
      }
    ]
  }
  ```
- `action`: `allow` | `deny` | `bypass` | `inspect` (max 100 events/batch).
- Default `decision_source` is `local-agent` (also increments
  `bsdm_proxy_policy_decision_source_total{source="local-agent"}`).
- When Kafka / `EVENT_SINK_URL` is configured on the proxy, events are converted
  to `CacheEvent` and enqueued for the indexer → ClickHouse path.
- Lab helper: `GET /api/v1/agent/events/recent` returns the last ≤50 accepted
  events from the in-process ring (not durable; for smoke/debug only).

---

## 4. Capability Negotiation

Agents negotiate capabilities during enrollment:
- `local-proxy` — HTTP/HTTPS local proxy listener on 127.0.0.1
- `dns-sinkhole` — Local DNS daemon / RPZ resolver
- `tunnel` — Optional fallback tunnel transport (AmneziaWG / WireGuard)
