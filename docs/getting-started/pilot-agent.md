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
| `GET /api/v1/agent/policy` pull | mTLS enroll (`POST /api/v1/agent/enroll`) |
| `POST /api/v1/agent/heartbeat` + `GET /api/v1/devices` | Policy push / WebSocket |
| Device registry persistence (`AGENT_DEVICES_PATH`) | Multi-node shared registry |
| Local SNI deny + pinning bypass + mode | Full UT1 categorization on endpoint |
| `AGENT_ONCE` / `--once` smoke | Windows/macOS installers, system proxy |
| Bearer `CONTROL_API_TOKEN` | Device cert identity |

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

Without `AGENT_DEVICES_PATH`, devices live only in memory and disappear on
restart. With the path set:

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

## Run continuous spike

```bash
export CONTROL_PLANE_URL=http://127.0.0.1:9090
export CONTROL_API_TOKEN=replace-me   # required when production auth is on
export DEVICE_ID=laptop-pilot-001
export DEVICE_NAME="Pilot laptop"
export DEVICE_TYPE=desktop            # desktop | phone
# optional: DEVICE_IP=10.0.0.42 HEARTBEAT_INTERVAL_SECS=30

cargo run -p agent-spike
```

On start the agent:

1. Pulls `GET /api/v1/agent/policy` (falls back to offline defaults if down).
2. Evaluates sample domains with `decision_source=local-agent`.
3. Loops: policy pull + enriched heartbeat every `HEARTBEAT_INTERVAL_SECS`.

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
3. `agent-spike --once` pulls policy, evaluates domains, posts heartbeat.
4. `GET /api/v1/devices` lists the smoke `device_id`.

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
