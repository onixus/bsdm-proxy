# Agent Contract v0.1

This document defines the specification and interaction contract between the BSDM Control Plane and Local Endpoint Agents (Phase C).

## Overview

The BSDM Agent architecture operates on a **Local Policy Agent** model: policy decision enforcement happens directly on-device using a local policy engine, while the central control plane manages enrollment, policy distribution, heartbeat, and telemetry ingestion.

All Agent Contract v0.1 HTTP endpoints use the canonical
`/api/v1/agent/*` namespace. The unversioned `/api/agent/*` namespace is
deprecated and retained only as a compatibility alias for the implemented
policy and heartbeat endpoints.

### Implementation status

- Implemented: `GET /api/v1/agent/policy` (mode, `mitm_categories`,
  `pinning_exceptions`, `sni_deny_patterns` / `sni_rules`),
  `POST /api/v1/agent/heartbeat`, `GET /api/v1/devices`, and
  `POST /api/v1/devices/{device_id}/revoke`.
- Spike client: `examples/agent-spike` (policy pull + local evaluate + heartbeat;
  pilot smoke in [pilot-agent.md](../getting-started/pilot-agent.md)).
- Reserved by this contract: `POST /api/v1/agent/enroll`,
  `POST /api/v1/agent/events`, and policy push.

---

## 1. Device Enrollment & Identity Binding

### 1.1 Mutual TLS (mTLS) Enrollment
1. **Enrollment Request**: The agent initiates bootstrap with a single-use deployment token or OIDC identity token:
   `POST /api/v1/agent/enroll`
2. **Key Generation**: Agent generates a local ECDSA/Ed25519 keypair and submits a Certificate Signing Request (CSR).
3. **Identity Certificate**: Control plane issues a client certificate bound to:
   - `Device-ID` (UUIDv4 generated during OS installation)
   - `User-Identity` (UPN / Subject Alt Name)
   - `Platform` (`windows`, `macos`, `linux`)

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

### 2.2 Policy Push (WebSocket / gRPC Stream)
- Control plane notifies agents when policy version changes.

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

### 3.2 Telemetry Ingestion (`POST /api/v1/agent/events`)
- Batched events logged locally and shipped back to ClickHouse event pipeline via Control Plane API.
- Logs include `decision_source` (`dns`, `sni`, `mitm`), `domain`, `action` (`allow`, `deny`, `bypass`), `timestamp`.

---

## 4. Capability Negotiation

Agents negotiate capabilities during enrollment:
- `local-proxy` — HTTP/HTTPS local proxy listener on 127.0.0.1
- `dns-sinkhole` — Local DNS daemon / RPZ resolver
- `tunnel` — Optional fallback tunnel transport (AmneziaWG / WireGuard)
