# BSDM Admin Console

Unified **single pane of glass** for BSDM-Proxy: monitoring dashboard, traffic logs with explainable ML decisions, ACL policies, and configuration export.

This is the only supported operator UI. The canonical embedded entry point is
`/admin/`; `/` and legacy `/trust` paths redirect there. See
[ADR 0006](../docs/adr/0006-single-operator-console.md).

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
| `/security` | Supported data-security controls |
| `/policies` | Runtime ACL rules viewer / reload / persist |
| `/rpz` | DNS policy management |
| `/users` | Basic-auth user management |
| `/settings` | Live node state + config generator (cache, auth, filtering, threat/ML, hierarchy/TLS, rate-limit/eBPF/Wasm, events) |

These pages replace the supported overlap with the former standalone Trust-UI:
Dashboard owns node/security posture, Logs owns the recent decision stream, and
Threat Scores owns ML posture. Endpoint inventory remains deferred with the
Agent and is not represented as a working operator feature.

The default sidebar only advertises the supported Hybrid operator paths above.
Frozen modules remain directly routable for development and compatibility, but
are intentionally hidden from primary navigation:

- `/wasm`
- `/cluster`
- `/ai-cache`
- `/amneziawg`

Their product status is defined in [`docs/project-status.md`](../docs/project-status.md).

## Data honesty

Every fetcher returns `Sourced<T>` — payload plus provenance (`live` or `demo`).
A failed request renders a real **error state**; sample data appears **only**
when the user enables demo mode (Settings → Console API), and is always marked
with a "Demo" badge. Developer-only frozen routes carry an explicit preview
banner when their backend endpoint is not available. Frozen eBPF content is not
shown on the core Policies workflow.

## Quick start

```bash
cd admin-console
npm install
npm run dev
# → http://127.0.0.1:5173/admin/
```

### Production build

```bash
npm run build
npm run preview
# static output in dist/
```

The production bundle uses `/admin/` as its asset and router base. Serve it on
that path with an SPA fallback to `/admin/index.html`, or let BSDM-Proxy serve
`dist/` through native UI routing.

## API integration

The UI talks to existing BSDM REST endpoints (no backend changes required):

| API | Default (dev proxy) | Used by |
|-----|---------------------|---------|
| `GET /api/search` | `:8080` | Logs |
| `GET/POST /api/acl/*` | `:9090` | Policies |
| `GET /metrics` | `:9090` | Dashboard |
| `GET /api/threat-scores` | `:8091` | Dashboard / Threat Scores |

Configure the connection under **Settings → Console API**:

- **Single endpoint** (default) — one Control Plane base URL and token. The
  deployment gateway must route `/api/search`, `/api/acl`, `/api/stats`,
  `/api/threat-scores`, and `/metrics` on the same origin.
- **Advanced split deployment** — independent Search, ACL, Control/Metrics, and
  ML worker base URLs with the existing Search, ACL, and Control tokens.

An empty single-endpoint URL uses same-origin paths; Vite maps those paths to
the local development services defined in `vite.config.ts`. Existing saved
multi-URL configurations are migrated to Advanced mode.

Use **Test connection** to run read-only health probes for every dependency.
Each service is reported as connected, unauthorized, or unreachable.

Passwords and API tokens are **not** persisted to `localStorage` — they remain
in memory for the current browser tab only. When APIs are unreachable, the
console shows an explicit service error unless the operator has deliberately
enabled demo mode.

Without an attached API token the console operates in **read-only safety
mode**. The shared HTTP client rejects every POST, PUT, PATCH, and DELETE before
the request reaches the network. The persistent shell banner links directly to
Settings → Console API, where an operator can attach a token for the current
tab.

## Identity and version

The shell identifies itself as a **local, unauthenticated console** until a real
authentication/session contract is implemented. It does not fabricate an AD
user or role. API tokens configured under Settings authorize individual backend
requests; they do not create a UI identity.

The displayed product version is injected at build time from
[`proxy/Cargo.toml`](../proxy/Cargo.toml), the same manifest used to build the
proxy binary.

The console exposure threat model and deployment requirements are documented
in [`docs/features/admin-console-security.md`](../docs/features/admin-console-security.md).

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
