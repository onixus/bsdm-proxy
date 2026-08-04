# BSDM Local Policy Agent Spike (Phase C, Issue #258 / #273)

Minimal on-device SWG Local Policy Agent per **Agent Contract v0.1**
(`docs/architecture/agent-contract.md`). Pilot guide:
[pilot-agent.md](../../docs/getting-started/pilot-agent.md).

## What it does

1. **Policy pull** — `GET /api/v1/agent/policy` (mode, MITM categories, pinning
   exceptions, SNI deny patterns / `sni_rules`). Offline defaults if pull fails.
2. **Local evaluation** — SNI deny, certificate-pinning bypass, selective MITM
   heuristic; logs `decision_source = "local-agent"`.
3. **Heartbeat** — `POST /api/v1/agent/heartbeat` with `device_id`, `name`,
   `device_type`, `policy_version`, `agent_version`, `trust_score`.

Not included: mTLS enroll, events batch, policy push, OS system-proxy install.

## Run

```bash
cargo run -p agent-spike
```

### Once-mode (smoke)

```bash
AGENT_ONCE=1 cargo run -p agent-spike -- --once
# or:
./scripts/run-agent-pilot-smoke.sh
```

### Environment

| Variable | Default | Purpose |
|---|---|---|
| `CONTROL_PLANE_URL` | `http://127.0.0.1:9090` | Metrics/control base URL |
| `CONTROL_API_TOKEN` | _(empty)_ | Bearer for production fail-closed control plane |
| `DEVICE_ID` | `dev-mac-001` | Stable device id |
| `DEVICE_NAME` | `agent-{DEVICE_ID}` | Display name in `/api/v1/devices` |
| `DEVICE_TYPE` | `desktop` | `desktop` \| `phone` |
| `DEVICE_IP` | _(unset)_ | Optional inventory IP |
| `HEARTBEAT_INTERVAL_SECS` | `30` | Loop interval (min 5) |
| `AGENT_ONCE` | `0` | `1`/`true` → pull + evaluate + one heartbeat, then exit |

Proxy-side (policy source): `AGENT_SNI_DENY_PATTERNS` (comma-separated),
`POLICY_MODE`, `MITM_CATEGORIES`, pinning registry.

## Tests

```bash
cargo test -p agent-spike
```
