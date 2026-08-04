# Hybrid load-test run `20260804T132958Z`

| Field | Value |
|---|---|
| Timestamp (UTC) | 20260804T132958Z |
| Proxy | `http://127.0.0.1:3128` |
| Concurrent users | 20 |
| Duration (s) | 16.36 |
| Traffic mix target | SNI 80% / MITM 15% / DNS 5% |
| Auth | disabled |
| Client OK / ERR | 2559 / 133 |
| Error rate (%) | 4.94 |
| Proxy requests (Δ) | 2559 |
| Proxy RPS | 156.4 |
| Cache hits (Δ) | 4 |
| Latency p50 (ms) | 1.8 |
| Latency p95 (ms) | 3.1 |
| Latency p99 (ms) | 3.7 |
| decision_source sni (Δ) | 0 |
| decision_source mitm (Δ) | 0 |
| decision_source dns (Δ) | 0 |
| decision_source pin (Δ) | 0 |
| MITM share (metrics %) | n/a |
| Client mix sni/mitm/dns | 2133/426/133 |

## Assumptions

- Profile: [load-test-selective-mitm.md](../load-test-selective-mitm.md).
- Latency is client-observed wall time through the proxy (includes upstream RTT).
- DNS share needs sinkhole on `127.0.0.1:5353` and `dig`.

## Host / stack notes

```
Darwin MacBook-Pro-Onixus.local 25.5.0 Darwin Kernel Version 25.5.0: Tue Jun  9 22:28:34 PDT 2026; root:xnu-12377.121.10~1/RELEASE_ARM64_T6050 arm64
CONTAINER ID   NAME                            CPU %     MEM USAGE / LIMIT     MEM %     NET I/O           BLOCK I/O         PIDS
11c58d6abfe3   bsdm-proxy-cache-indexer-1      0.00%     6.516MiB / 11.67GiB   0.05%     2.81MB / 1.14MB   2.92MB / 102MB    17
14c6a4a79ee9   bsdm-proxy-mock-upstream-1      0.02%     13.74MiB / 11.67GiB   0.11%     2.55MB / 4.71MB   0B / 1.78MB       1
3732fe056bf7   bsdm-proxy-proxy-1              0.00%     5.805MiB / 11.67GiB   0.05%     2.55MB / 4.71MB   12.3kB / 0B       18
445bd8e5c80d   shapoclyack-dev-control-plane   17.41%    3.35GiB / 11.67GiB    28.71%    302MB / 40.2MB    50.9MB / 17.8GB   1169
```
