# BSDM Admin Console

Unified **single pane of glass** for BSDM-Proxy: monitoring dashboard, traffic logs with explainable ML decisions, ACL policies, and configuration export.

Replaces the legacy static [`web-config/`](../web-config/) generator with a modern React SPA.

## Stack

| Layer | Choice |
|-------|--------|
| Framework | React 19 + TypeScript |
| Build | Vite 8 |
| Styling | Tailwind CSS 4 (`@theme` design tokens) |
| Routing | React Router 7 (client-side, no full page reloads) |
| Icons | lucide-react |

## Routes

| Path | Purpose |
|------|---------|
| `/` | Dashboard — metric widgets, ML anomaly summary |
| `/logs` | Retro-search logs + XAI modal on blocked requests |
| `/policies` | Runtime ACL rules viewer / reload |
| `/settings` | Config generator + API endpoint configuration |

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
