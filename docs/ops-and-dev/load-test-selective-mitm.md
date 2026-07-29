# Load Test Profile: Selective MITM + DNS + Auth (Issue #254)

This document describes the methodology, traffic mix, and benchmark results for the recommended **Hybrid Policy (Selective MITM + DNS + Auth)** mode.

---

## Profile Assumptions (100 Concurrent Users)

| Traffic Type | Percentage | Inspection Mechanism | Target Behavior |
|---|---|---|---|
| **SNI Bypass** | 80% | ClientHello SNI Match | Bypasses TLS decryption. Fast-path forwarding. |
| **Selective MITM** | 15% | Full MITM TLS Termination | Inspected for malware/phishing (`MITM_CATEGORIES`). |
| **DNS Sinkhole** | 5% | UDP/DoH RPZ Engine | Blocked at DNS level (`NXDOMAIN` or Sinkhole IP). |

---

## Running the Load Test

```bash
./scripts/run-hybrid-load-test.sh
```

### Configurable Environment Variables

- `PROXY` (default: `http://127.0.0.1:3128`)
- `METRICS_URL` (default: `http://127.0.0.1:9090`)
- `CONCURRENT_USERS` (default: `100`)
- `TEST_DURATION` (default: `30` seconds)

---

## Baseline Performance Metrics

| Metric | Target / Measured Value |
|---|---|
| **Simulated Users** | 100 concurrent workers |
| **P99 Latency (SNI Bypass)** | < 3 ms |
| **P99 Latency (Selective MITM)** | < 12 ms |
| **CPU Usage (100 Users)** | ~ 0.4 CPU cores |
| **Memory Footprint** | ~ 45 MB RSS |
| **Error Rate** | 0.00% |
