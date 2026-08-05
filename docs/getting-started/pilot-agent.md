# Pilot agent spike (Phase C)

Day-1 **on-device** path for Hybrid SWG: pull a simplified policy from the
control plane, evaluate SNI deny / pinning / mode **locally**, and register the
device via heartbeat. This is a **spike** (`agent-spike` crate), not a
production multi-OS agent.

Related: [agent-contract.md](../architecture/agent-contract.md) ·
[ADR 0005](../adr/0005-local-policy-agent-vs-tunnel-first.md) ·
[control-plane-security.md](../ops-and-dev/control-plane-security.md) ·
[pilot-deployment.md](pilot-deployment.md).

Issue tracking: **#273** (agent implementation), **#258** (original spike).

---

## Day-1 scope

| Include | Exclude |
|---|---|
| `POST /api/v1/agent/enroll` → `device_token` | Control-plane TLS mutual-auth on primary `:9090` |
| Optional enroll CSR → client cert (proxy CA) | OCSP stapling on data-plane TLS |
| `GET /api/v1/agent/policy` pull + watch/SSE/**WebSocket** push | |
| gRPC policy (`Get/Push/WatchAgentPolicy`, feature `grpc`) | mTLS on metrics/admin port |
| Optional control mTLS port (`CONTROL_MTLS_*`, default `:9443`) | Multi-node shared registry |
| Agent cert CRL JSON/PEM + lab OCSP JSON + **RFC 6960 DER OCSP** | |
| `POST /api/v1/agent/heartbeat` + `GET /api/v1/devices` | Durable multi-node event store |
| `POST /api/v1/agent/events` telemetry batch | Multi-OS installers / system proxy |
| Device registry persistence (`AGENT_DEVICES_PATH`) | Full UT1 categorization on endpoint |
| Admin Console `/devices` (list/revoke/push/CRL) | Production IdP binding |
| Multi-node Redis devices + CRL (optional) | Full multi-cluster mesh productization |
| Local SNI deny + pinning bypass + mode | |
| `AGENT_ONCE` / `--once` / `--enroll` smoke | |

Pilot Hybrid path **does not require** an agent to pass acceptance. This guide
is for labs that want to exercise Phase C control-plane endpoints early.

---

## Prerequisites

1. Proxy healthy on control/metrics port (default `:9090`).
2. Production/pilot: set `CONTROL_API_TOKEN` (fail-closed). Lab-only may use
   `CONTROL_API_ALLOW_INSECURE=true`.
3. Optional: pin managed exceptions via `PINNING_EXCEPTIONS_PATH` so policy pull
   returns real domains (see `config/pinning-exceptions.example.json`).
4. Optional: `AGENT_SNI_DENY_PATTERNS=*.evil.com,badsite.test` on the **proxy**
   process (defaults match if unset).
5. Optional but **recommended for pilot**: `AGENT_DEVICES_PATH` so inventory
   survives proxy restart (compose default:
   `/var/lib/bsdm-proxy/agent-devices.json` on volume `agent-devices`).

---

## Device registry persistence

Without `AGENT_DEVICES_PATH` (and without Redis multi-node), devices live only
in memory and disappear on restart. With the path set:

1. Control plane **loads** JSON at start (`version: 1`, array of devices).
2. Each successful heartbeat / revoke **rewrites** the file atomically.
3. API responses include `"persisted": true|false`.

```bash
# Host / cargo:
export AGENT_DEVICES_PATH=./data/agent-devices.json

# Compose: already set + named volume agent-devices
docker compose up -d proxy
# After smoke heartbeat:
# docker compose exec proxy cat /var/lib/bsdm-proxy/agent-devices.json
```

### Multi-node (Redis)

Shared enroll / heartbeat / revoke / device-token auth across proxy nodes:

```bash
# Preferred dedicated URL:
export AGENT_DEVICES_REDIS_URL=redis://redis:6379/0

# Or reuse REDIS_URL:
export REDIS_URL=redis://redis:6379/0
export AGENT_DEVICES_REDIS=true

# Optional key prefix (default bsdm:agent:):
# export AGENT_REDIS_PREFIX=bsdm:agent:
```

Redis stores:

| Key | Type | Content |
|---|---|---|
| `{prefix}devices` | HASH | `device_id` → JSON device |
| `{prefix}tok:{sha256}` | STRING | → `device_id` |
| `{prefix}fp:{fingerprint}` | STRING | → `device_id` |
| `{prefix}ser:{serial}` | STRING | → `device_id` |
| `{prefix}crl` | HASH | fingerprint → JSON CRL entry |
| `{prefix}crl_number` | STRING | monotonic CRL number |

Local memory is a cache; writes go to Redis (and optional file). List/auth
paths pull/merge from Redis. Use the **same CA** and enroll token on all nodes.

File shape:

```json
{
  "version": 1,
  "devices": [
    {
      "id": "laptop-pilot-001",
      "name": "Pilot laptop",
      "ip": "",
      "device_type": "desktop",
      "agent_status": "healthy",
      "agent_version": "0.1.0",
      "policy_version": "v0.1.0",
      "trust_score": 90,
      "last_seen": 1720000000,
      "revoked": false
    }
  ]
}
```

Cap: 10 000 devices. Missing file → empty registry (created on first heartbeat).

---

## Enroll (lab device token)

```bash
export CONTROL_PLANE_URL=http://127.0.0.1:9090
# Preferred bootstrap secret (falls back to CONTROL_API_TOKEN if unset):
export AGENT_ENROLL_TOKEN=enroll-lab-secret
# Or: export CONTROL_API_TOKEN=replace-me

export DEVICE_ID=laptop-pilot-001
export DEVICE_NAME="Pilot laptop"
export DEVICE_PLATFORM=macos   # linux | macos | windows
export DEVICE_TYPE=desktop

# Prints DEVICE_TOKEN=bsdmagent_… once — store it for later runs
cargo run -p agent-spike -- --enroll --once

# mTLS: generate keypair + CSR, receive client_cert_pem + ca_cert_pem
cargo run -p agent-spike -- --enroll --mtls --once
# Also prints DEVICE_KEY_PEM_* / DEVICE_CERT_PEM_* / CA_CERT_PEM_* blocks
```

Re-use without re-enroll:

```bash
export DEVICE_TOKEN=bsdmagent_…
cargo run -p agent-spike -- --once
```

Revoke invalidates the token and adds the client cert to the **CRL**:

```bash
curl -sS -X POST -H "Authorization: Bearer ${CONTROL_API_TOKEN}" \
  http://127.0.0.1:9090/api/v1/devices/${DEVICE_ID}/revoke

# Fingerprint list (ops)
curl -sS -H "Authorization: Bearer ${CONTROL_API_TOKEN}" \
  http://127.0.0.1:9090/api/v1/agent/crl | jq .

# Optional X.509 CRL PEM (needs CA with CrlSign — in-memory CA / compatible files)
curl -sS -H "Authorization: Bearer ${CONTROL_API_TOKEN}" \
  http://127.0.0.1:9090/api/v1/agent/crl.pem
```

Persist CRL: `AGENT_CRL_PATH=./data/agent-crl.json`.

### OCSP status (lab JSON)

Per-cert status (not full RFC 6960 binary OCSP):

```bash
# After enroll --mtls (fingerprint from response):
curl -sS -H "Authorization: Bearer ${CONTROL_API_TOKEN}" \
  "http://127.0.0.1:9090/api/v1/agent/ocsp/status?fingerprint=${CERT_FP}" | jq .

# By serial:
curl -sS -H "Authorization: Bearer ${CONTROL_API_TOKEN}" \
  "http://127.0.0.1:9090/api/v1/agent/ocsp/status?serial=${CERT_SERIAL}" | jq .
# → status: good | revoked | unknown
```

Enroll response includes `ocsp_status_url` for convenience.

RFC 6960 DER (public, no Bearer) — body is a binary OCSP request, response is
CA-signed `application/ocsp-response` (ECDSA P-256 or RSA CA):

```bash
# After building an OCSP request DER (serial of the agent client cert):
curl -sS -X POST -H 'Content-Type: application/ocsp-request' \
  --data-binary @ocsp-req.der \
  http://127.0.0.1:9090/api/v1/agent/ocsp -o ocsp-resp.der
# or GET with base64: /api/v1/agent/ocsp?b64=...
```

### Optional: gRPC policy product path

Build with `--features grpc`, run with `CONTROL_GRPC_ENABLED=true`
(`CONTROL_GRPC_BIND`, default `127.0.0.1:50051`). RPCs:
`GetAgentPolicy`, `PushAgentPolicy`, server-stream `WatchAgentPolicy`
(same hub as HTTP long-poll/SSE). Bearer metadata: `authorization: Bearer …`.

### Optional: agent control mTLS port

Plain `:9090` stays HTTP (Prometheus / Admin). Agents can use HTTPS **with
required client certificate** on a second port:

```bash
# proxy
export CONTROL_MTLS_ENABLED=true
export CONTROL_MTLS_BIND=0.0.0.0:9443
export CONTROL_MTLS_CLIENT_CA_FILE=./certs/ca.crt
# optional: fingerprint must match enroll registry
# export CONTROL_MTLS_REQUIRE_ENROLLED=true
```

```bash
# After --enroll --mtls saved PEMs:
curl -fsS --cacert ca.crt --cert device.crt --key device.key \
  --resolve control.bsdm.local:9443:127.0.0.1 \
  https://control.bsdm.local:9443/health
curl -fsS --cacert ca.crt --cert device.crt --key device.key \
  --resolve control.bsdm.local:9443:127.0.0.1 \
  -H "Authorization: Bearer $DEVICE_TOKEN" \
  https://control.bsdm.local:9443/api/v1/agent/policy
```

Details: [control-plane-security.md](../ops-and-dev/control-plane-security.md).

### Policy push (long-poll)

Agents default to watching for policy updates (disable with
`AGENT_POLICY_PUSH=0` or `--no-policy-push`):

```bash
# Operator: rebuild + notify all watchers
curl -sS -X POST -H "Authorization: Bearer ${CONTROL_API_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data '{"reason":"pinning-update","actor":"ops"}' \
  http://127.0.0.1:9090/api/v1/agent/policy/push

# Agent long-poll (or rely on spike watch loop)
curl -sS -H "Authorization: Bearer ${DEVICE_TOKEN}" \
  "http://127.0.0.1:9090/api/v1/agent/policy/watch?since=vOLD&timeout_secs=30"

# SSE (curl -N)
curl -NsS -H "Authorization: Bearer ${DEVICE_TOKEN}" \
  http://127.0.0.1:9090/api/v1/agent/policy/stream

# WebSocket (agent-spike: AGENT_POLICY_WS=1 or --policy-ws)
# ws://127.0.0.1:9090/api/v1/agent/policy/ws  (Bearer on handshake)
```

Pinning reload (`POST /api/pinning/exceptions/reload`) also publishes a push.

## Run continuous spike

```bash
export CONTROL_PLANE_URL=http://127.0.0.1:9090
export CONTROL_API_TOKEN=replace-me   # or DEVICE_TOKEN after enroll
export DEVICE_ID=laptop-pilot-001
export DEVICE_NAME="Pilot laptop"
export DEVICE_TYPE=desktop            # desktop | phone
# optional: DEVICE_IP=10.0.0.42 HEARTBEAT_INTERVAL_SECS=30

cargo run -p agent-spike
```

On start the agent:

1. Enrolls when `DEVICE_TOKEN` is unset (or `--enroll` / `AGENT_ENROLL=1`).
2. Pulls `GET /api/v1/agent/policy` (falls back to offline defaults if down).
3. Evaluates sample domains + posts events (`decision_source=local-agent`).
4. Loops: policy pull + enriched heartbeat every `HEARTBEAT_INTERVAL_SECS`.

---

## Acceptance smoke

```bash
# Proxy must already be up with a reachable control plane.
CONTROL_PLANE_URL=http://127.0.0.1:9090 \
CONTROL_API_TOKEN="${CONTROL_API_TOKEN:-}" \
./scripts/run-agent-pilot-smoke.sh
```

What it checks:

1. `GET /health` on the control plane.
2. `GET /api/v1/agent/policy` returns `policy_mode` + `sni_rules` / patterns.
3. `agent-spike --once` pulls policy, evaluates domains, posts **events** + heartbeat.
4. `GET /api/v1/devices` lists the smoke `device_id`.
5. `GET /api/v1/agent/events/recent` contains at least one event for the device.

Manual once-mode:

```bash
AGENT_ONCE=1 \
DEVICE_ID=smoke-agent-001 \
CONTROL_PLANE_URL=http://127.0.0.1:9090 \
CONTROL_API_TOKEN=replace-me \
cargo run -p agent-spike -- --once
```

---

## Control-plane policy shape (v0.1 subset)

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

| Field | Source |
|---|---|
| `policy_mode` | `POLICY_MODE` on proxy |
| `mitm_categories` | `MITM_CATEGORIES` |
| `pinning_exceptions` | Pinning registry active domains |
| `sni_*` | `AGENT_SNI_DENY_PATTERNS` (comma-separated) or pilot defaults |

Not yet: full ACL tree, DNS RPZ version, enroll, events batch.

---

## Verify devices in Admin / API

```bash
curl -sS -H "Authorization: Bearer ${CONTROL_API_TOKEN}" \
  http://127.0.0.1:9090/api/v1/devices | jq .
```

Revoke (Trust UI / ops):

```bash
curl -sS -X POST -H "Authorization: Bearer ${CONTROL_API_TOKEN}" \
  http://127.0.0.1:9090/api/v1/devices/laptop-pilot-001/revoke
```

---

## Unit tests (offline)

```bash
cargo test -p agent-spike
```

Covers SNI deny, pinning suffix match, selective phishing heuristic, and remote
DTO mapping (`sni_rules` vs flat `sni_deny_patterns`).
