# Control plane API (DX Phase 2)

REST endpoints on the proxy metrics port (`METRICS_PORT`, default `9090`). No Grafana required for Lite ops.

See also: [strategic-roadmap.md](strategic-roadmap.md) Phase 2 · [acl.md](acl.md).

## Auth

| Variable | Role |
|----------|------|
| `CONTROL_API_TOKEN` | Preferred Bearer token for mutating control APIs |
| `ACL_API_TOKEN` | Fallback token (also used for `/api/acl/*`) |

`GET /api/stats` is intentionally unauthenticated (local Lite monitoring).  
`POST /api/cache/purge` and all `/api/acl/*` require Bearer when a token is configured.

```bash
curl -H "Authorization: Bearer $CONTROL_API_TOKEN" ...
```

## Stats (Lite JSON)

```bash
curl http://127.0.0.1:9090/api/stats
```

```json
{
  "service": "bsdm-proxy",
  "uptime_secs": 3600,
  "requests_in_flight": 2,
  "cache": {
    "hits": 1000,
    "misses": 120,
    "bypasses": 10,
    "hit_ratio": 0.892,
    "entries": 842,
    "capacity": 10000,
    "shards": 16
  }
}
```

## Cache purge

```bash
# Exact URL (method defaults to GET)
curl -X POST http://127.0.0.1:9090/api/cache/purge \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com/asset.js"}'

# Entire L1 (+ Redis L2 prefix when enabled)
curl -X POST http://127.0.0.1:9090/api/cache/purge \
  -H 'Content-Type: application/json' \
  -d '{"all":true}'
```

## ACL CRUD

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/acl/rules` | List |
| `POST` | `/api/acl/rules` | Add (in-memory); invalidates policy cache |
| `PUT` | `/api/acl/rules/{id}` | Replace |
| `DELETE` | `/api/acl/rules/{id}` | Remove |
| `POST` | `/api/acl/reload` | File → memory (`ACL_RULES_PATH`) |
| `POST` | `/api/acl/persist` | Memory → file |

Requires `ACL_ENABLED=true`.

## Roadmap leftovers

- [ ] Upstream / hierarchy hot reload
- [ ] Cache-Tags based purge
- [ ] gRPC control plane
