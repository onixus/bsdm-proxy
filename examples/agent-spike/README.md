# BSDM Local Policy Agent Spike (Phase C, Issue #258)

This directory contains a minimal spike of an On-Device SWG Local Policy Agent built according to **Agent Contract v0.1** (`docs/architecture/agent-contract.md`).

## Architectural Highlights

- **On-Device Enforcement**: Executes SNI deny rules, category checks, and certificate pinning bypasses locally without proxy roundtrips.
- **Heartbeat & Telemetry**: Periodically sends heartbeats to central Control Plane (`:9090`) and logs local decisions with `decision_source = "local-agent"`.

## Running the Spike

```bash
cargo run -p agent-spike
```

### Environment Overrides

```bash
DEVICE_ID="laptop-win-042" CONTROL_PLANE_URL="http://127.0.0.1:9090" cargo run -p agent-spike
```
