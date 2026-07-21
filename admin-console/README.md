# BSDM Admin Console

Unified **single pane of glass** for BSDM-Proxy: monitoring dashboard, traffic logs with explainable ML decisions, ACL policies, and configuration export.

Replaces the legacy static [`web-config/`](../web-config/) generator with a modern React SPA.

## Stack

| Layer | Choice |
|-------|--------|
| Framework | React 19 + TypeScript |
| Build | Vite 8 |
| Styling | Tailwind CSS 4 (`@theme inline` tokens, runtime dark/light switch) |
| Data fetching | TanStack Query (polling, retry, stale-while-revalidate) |
| Routing | React Router 7 (client-side, no full page reloads) |
| Charts | Hand-rolled SVG (line/sparkline/segment/bar-list) — no chart library |
| Icons | lucide-react |

## Routes

| Path | Purpose |
|------|---------|
| `/` | Dashboard — RED metrics from Prometheus `/metrics` + `/api/stats`, live charts, top upstreams, ML anomalies, hierarchy peers |
| `/logs` | Retro-search with server+client filters, live tail, pagination, CSV export, session timeline, XAI modal |
| `/analytics` | Aggregations over the search sample: traffic over time, status/cache/decision mix, top talkers, threat severity |
| `/threat-scores` | ML write-back snapshot with model filter and traffic drill-down |
| `/policies` | Runtime ACL rules viewer / reload |
| `/settings` | Live node state + config generator (cache, auth, filtering, threat/ML, hierarchy/TLS, rate-limit/eBPF/Wasm, events) |

## Data honesty

Every fetcher returns `Sourced<T>` — payload plus provenance (`live` or `demo`).
A failed request renders a real **error state**; sample data appears **only**
when the user enables demo mode (Settings → Console API), and is always marked
with a "Demo" badge. Pages whose backend endpoints don't exist yet (RPZ, Wasm,
Cluster Mesh, AI Cache, eBPF stats) carry an explicit "Preview — no backend
endpoint" banner.

## Quick start

```bash
cd admin-console
npm install
npm run dev
# → http://127.0.0.1:5173
```

### Production build

```bash
npm run build
npm run preview
# static output in dist/
```

Serve `dist/` behind nginx or embed in your deployment. Example:

```bash
docker run -d -p 8080:80 -v $(pwd)/admin-console/dist:/usr/share/nginx/html:ro nginx:alpine
```

## API integration

The UI talks to existing BSDM REST endpoints (no backend changes required):

| API | Default (dev proxy) | Used by |
|-----|---------------------|---------|
| `GET /api/search` | `:8080` | Logs |
| `GET/POST /api/acl/*` | `:9090` | Policies |
| `GET /metrics` | `:9090` | Dashboard |
| `GET /api/ml/scores` | `:8091` | Dashboard (future; mock fallback) |

Configure base URLs under **Settings → API**. Empty base URLs use Vite dev-server proxies defined in `vite.config.ts`.

Passwords and API tokens are **not** persisted to `localStorage` — they remain in memory for the current browser session only.

When APIs are unreachable, the console shows **demo data** so layouts and XAI components remain testable offline.

## UI/UX deliverables

- **UIUX-001** — Sidebar layout, widget grid dashboard, SPA router (Dashboard / Policies / Settings + Logs)
- **UIUX-002** — Tailwind design tokens, reusable `Button` / `Modal` / `Form` components; web-config logic in `src/lib/config/`
- **UIUX-003** — Mobile hamburger menu, 44px touch targets, responsive tables → card lists at `md` breakpoint
- **UIUX-004** — `ThreatIndicator` (0–100% gradient), `InsightPanel` (factor tags), log detail modal distinguishing ACL vs ML blocks

## Architecture

```
src/
  api/           # HTTP clients (separated from UI)
  components/    # Design system + layout + XAI
  lib/config/    # Env/compose/ACL export (from web-config)
  pages/         # Route-level views
  theme/         # Design tokens
```

## Legacy web-config

The original [`web-config/`](../web-config/) static generator remains for backward compatibility. New development should use this console.
