# Trust-UI

**Trust-UI** is the live Zero-Trust posture dashboard for **BSDM-Proxy**.

Trust-UI has no demo mode and never substitutes synthetic values when a backend
is unavailable. Failed, unsupported, and empty APIs are shown explicitly in the
interface.

## Features

- **Node health and runtime stats** from `/health` and `/api/stats`.
- **Security counters** parsed from the proxy `/metrics` endpoint.
- **Recent traffic decisions** polled from the cache-indexer `/api/search` endpoint.
- **Device identity posture** from `/api/v1/devices` when that API is implemented
  by the deployment. Current BSDM nodes return an explicit unsupported state.

## Getting Started

### Development Mode

```bash
cd trust-ui
npm install
npm run dev
```

The application runs on `http://localhost:3001` by default. The Vite development
server routes proxy health/stats/metrics and future device identity requests to
`127.0.0.1:9090`, and search requests to the cache-indexer on
`127.0.0.1:8080`.

Production deployments must expose the same paths through the origin serving
Trust-UI.

The repository's `trust-ui` Docker image includes an Nginx configuration that
routes health, stats, and metrics to the `proxy` compose service and search
requests to `cache-indexer`. `SEARCH_API_TOKEN` and `CONTROL_API_TOKEN` are
injected into the Nginx configuration at container startup and remain outside
the browser bundle.

### Production Build

```bash
npm run build
```

This compiles static assets into `dist/`.
