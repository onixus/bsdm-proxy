# BSDM Local Policy Agent Spike (Phase C, Issue #258 / #273)

Minimal on-device SWG Local Policy Agent per **Agent Contract v0.1**
(`docs/architecture/agent-contract.md`). Pilot guide:
[pilot-agent.md](../../docs/getting-started/pilot-agent.md).

## What it does

1. **Enroll** — `POST /api/v1/agent/enroll` → `device_token`; optional `--mtls`
   CSR → client cert + CA PEM.
2. **Policy pull** — `GET /api/v1/agent/policy` (mode, MITM categories, pinning
   exceptions, SNI deny patterns / `sni_rules`). Offline defaults if pull fails.
3. **Local evaluation** — SNI deny, certificate-pinning bypass, selective MITM
   heuristic; logs `decision_source = "local-agent"`.
4. **Events** — `POST /api/v1/agent/events` batch of local decisions.
5. **Heartbeat** — `POST /api/v1/agent/heartbeat` with inventory fields.

Not included: mTLS CSR, policy push, OS system-proxy install.

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
| `CONTROL_API_TOKEN` | _(empty)_ | Operator Bearer / enroll fallback |
| `AGENT_ENROLL_TOKEN` | falls back to control token | Bootstrap secret for enroll only |
| `DEVICE_TOKEN` | _(empty)_ | Post-enroll agent Bearer (`bsdmagent_…`) |
| `DEVICE_PLATFORM` | host OS | `linux` \| `macos` \| `windows` |
| `AGENT_ENROLL` / `--enroll` | auto if no `DEVICE_TOKEN` | Force enroll |
| `AGENT_MTLS` / `--mtls` | off | Enroll with CSR (needs proxy CA) |
| `AGENT_POLICY_PUSH` | on | Long-poll policy watch (`0` to disable) |
| `AGENT_POLICY_WATCH_SECS` | `25` | Watch timeout between polls |
| `--no-policy-push` | | Disable watch loop |
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
