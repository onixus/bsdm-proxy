# Control plane & metrics security defaults (#271)

Safe defaults for the metrics/control listener (`METRICS_PORT`, default `9090`),
ACL REST API, Search API, and related scrape endpoints.

See also: [control-plane.md](../features/control-plane.md) ·
[admin-console-security.md](../features/admin-console-security.md) ·
[pilot-deployment.md](../getting-started/pilot-deployment.md).

---

## Threat model (short)

| Surface | Risk if open | Default posture (production) |
|---|---|---|
| Mutating control APIs (`POST /api/cache/purge`, config apply, TLS reload, …) | Cache wipe, config rewrite, CA/pinning abuse | **Bearer required** (`CONTROL_API_TOKEN`) |
| ACL REST (`/api/acl/*`) | Policy bypass | **Bearer required** (ACL or CONTROL token) |
| Search / ingest (`/api/search`, `POST /api/events`) | Traffic metadata leak / event injection | **Bearer required** (`SEARCH_API_TOKEN`) |
| `GET /metrics` | Internal counters / cardinality leak | Open unless `METRICS_AUTH_TOKEN` / `METRICS_REQUIRE_AUTH` |
| `GET /health`, `/ready` | Low | Always open (probes) |
| `GET /api/stats` | Cache hit ratios | Open (local monitoring) |

---

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `DEPLOYMENT_PROFILE` | `production` | Drives fail-closed behaviour |
| `CONTROL_API_TOKEN` | *unset* | Bearer for control plane (preferred) |
| `ACL_API_TOKEN` | falls back to CONTROL | Bearer for `/api/acl/*` |
| `CONTROL_API_ALLOW_INSECURE` | `false` | Lab only: allow production **without** token (open mutations) |
| `CONTROL_API_REQUIRE_TOKEN` | `false` | Force fail-closed in development/test |
| `METRICS_BIND` | `0.0.0.0` | Host for metrics/control listen address |
| `METRICS_AUTH_TOKEN` | *unset* | Bearer for `GET /metrics` |
| `METRICS_REQUIRE_AUTH` | `false` | If true, reuse `CONTROL_API_TOKEN` for scrape auth |
| `SEARCH_API_TOKEN` | *unset* | Bearer for Search API |
| `SEARCH_API_ALLOW_INSECURE` | *unset* (inherits CONTROL insecure) | Lab open search |

### Production rules

1. **Missing `CONTROL_API_TOKEN`** → process **refuses to start**, unless
   `CONTROL_API_ALLOW_INSECURE=true` (lab).
2. With a token configured → all non-public `/api/*` need
   `Authorization: Bearer …` (constant-time compare).
3. Without a token in open lab mode → mutations are allowed (legacy), with loud warnings.

### Cache-indexer

With `SEARCH_API_ENABLED=true` and production profile, **missing
`SEARCH_API_TOKEN`** refuses to start unless `SEARCH_API_ALLOW_INSECURE=true`.

---

## Network policy recommendations

### Bare metal / VM pilot

```bash
# Prefer loopback or management NIC for control plane
export METRICS_BIND=127.0.0.1
export CONTROL_API_TOKEN="$(openssl rand -hex 32)"
export ACL_API_TOKEN="$CONTROL_API_TOKEN"
export SEARCH_API_TOKEN="$(openssl rand -hex 32)"
# optional scrape auth for Prometheus on the same host
export METRICS_REQUIRE_AUTH=true
```

- Do **not** publish `9090` / `8080` to the public internet.
- Put Prometheus/Grafana on the same host or private VPC; use scrape Bearer if exposed.
- Admin Console: reverse-proxy with SSO/mTLS in front of `/admin/` when off-box.

### Docker / Compose

Containers must often bind `0.0.0.0` so published ports work. Compensating controls:

1. Set real `CONTROL_API_TOKEN` / `SEARCH_API_TOKEN`.
2. Set `CONTROL_API_ALLOW_INSECURE=false` (pilot override does this).
3. Restrict host firewall / security groups to management subnets only.
4. Prefer not publishing Search (`8080`) outside the compose network when possible.

Lab compose files set `CONTROL_API_ALLOW_INSECURE=true` **explicitly** so
`docker compose up` still works without secrets. Pilot compose **requires** tokens.

### Kubernetes

- ClusterIP only for control/metrics; scrape via in-cluster Prometheus.
- Secrets for tokens via External Secrets / sealed secrets.
- NetworkPolicy: deny ingress to metrics port from non-monitoring namespaces.

---

## Quick verification

```bash
# Should 401 without Bearer when token configured / production fail-closed
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST http://127.0.0.1:9090/api/cache/purge \
  -H 'Content-Type: application/json' -d '{}'

# Health stays open
curl -fsS http://127.0.0.1:9090/health

# Scrape with optional auth
curl -fsS -H "Authorization: Bearer $METRICS_AUTH_TOKEN" \
  http://127.0.0.1:9090/metrics | head
```

---

## Code map

| Piece | Location |
|---|---|
| Production token gate | `proxy/src/security_defaults.rs` |
| Control API auth | `proxy/src/control_api.rs` (`is_authorized_bearer`) |
| ACL API auth | `proxy/src/acl_api.rs` |
| Metrics bind + scrape auth | `proxy/src/server.rs` (`metrics_server`) |
| Search fail-closed | `cache-indexer/src/search_api.rs`, `main.rs` |
