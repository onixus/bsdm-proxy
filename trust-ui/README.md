# Trust-UI

**Trust-UI** is the Zero-Trust Posture & Threat Analytics Control Plane dashboard for **BSDM-Proxy**.

## Features

- **Real-Time Trust Scoring**: Instant visualization of network security index (0–100) and risk posture.
- **mTLS & Upstream Validation**: Monitor peer authentication and client certificate validation metrics.
- **Inline CASB DLP Monitoring**: Live tracking of Aho-Corasick pattern matches blocking confidential data leaks.
- **ML-Worker & Anomaly Vector Metrics**: Real-time Kafka feature-store scoring feed integration.
- **RPZ-lite DNS Sinkhole Overview**: Tracking UDP RPZ-lite domain intercepts.
- **Live Threat Stream Log**: Searchable and filterable traffic decision stream (ALLOWED, BLOCKED, SINKHOLED, MITM_INSPECTED).

## Getting Started

### Development Mode

```bash
cd trust-ui
npm install
npm run dev
```

The application runs on `http://localhost:3001` by default and proxies backend management requests (`/api`) to the BSDM Proxy instance at `http://127.0.0.1:1488`.

### Production Build

```bash
npm run build
```

This compiles static assets into `dist/`.
