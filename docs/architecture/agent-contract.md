# Agent Contract v0.1

This document defines the specification and interaction contract between the BSDM Control Plane and Local Endpoint Agents (Phase C).

## Overview

The BSDM Agent architecture operates on a **Local Policy Agent** model: policy decision enforcement happens directly on-device using a local policy engine, while the central control plane manages enrollment, policy distribution, heartbeat, and telemetry ingestion.

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
    "policy_version": "2026-07-29T10:00:00Z",
    "policy_mode": "selective-mitm",
    "mitm_categories": ["malware", "phishing", "illegal-content"],
    "sni_rules": [
      { "pattern": "*.evil.com", "action": "deny" }
    ],
    "dns_sinkhole": {
      "enabled": true,
      "rpz_version": "v1.4.2"
    }
  }
  ```

### 2.2 Policy Push (WebSocket / gRPC Stream)
- Control plane notifies agents when policy version changes.

---

## 3. Telemetry & Heartbeat

### 3.1 Heartbeat (`POST /api/v1/agent/heartbeat`)
- Periodicity: Default 60s.
- Contains: `device_id`, `policy_version`, `agent_version`, `status` (`healthy`, `degraded`).

### 3.2 Telemetry Ingestion (`POST /api/v1/agent/events`)
- Batched events logged locally and shipped back to ClickHouse event pipeline via Control Plane API.
- Logs include `decision_source` (`dns`, `sni`, `mitm`), `domain`, `action` (`allow`, `deny`, `bypass`), `timestamp`.

---

## 4. Capability Negotiation

Agents negotiate capabilities during enrollment:
- `local-proxy` — HTTP/HTTPS local proxy listener on 127.0.0.1
- `dns-sinkhole` — Local DNS daemon / RPZ resolver
- `tunnel` — Optional fallback tunnel transport (AmneziaWG / WireGuard)
