# Control plane API (DX Phase 2)

REST endpoints on the proxy metrics port (`METRICS_PORT`, default `9090`). No Grafana required for Lite ops.

See also: [strategic-roadmap.md](strategic-roadmap.md) Phase 2 · [acl.md](acl.md).

## Auth

| Variable | Role |
|----------|------|
| `CONTROL_API_TOKEN` | Preferred Bearer token for mutating control APIs |
| `ACL_API_TOKEN` | Fallback token (also used for `/api/acl/*`) |

`GET /api/stats` and `GET /api/hierarchy/peers` are intentionally unauthenticated (local Lite monitoring).  
`POST /api/cache/purge`, `POST /api/hierarchy/reload`, and all `/api/acl/*` require Bearer when a token is configured.

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
    "shards": 16,
    "tags": 12
  }
}
```

## Cache purge

```bash
# Exact URL (method defaults to GET)
curl -X POST http://127.0.0.1:9090/api/cache/purge \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com/asset.js"}'

# By Cache-Tag / Surrogate-Key (indexed on L1 insert)
curl -X POST http://127.0.0.1:9090/api/cache/purge \
  -H 'Content-Type: application/json' \
  -d '{"tag":"product-42"}'

curl -X POST http://127.0.0.1:9090/api/cache/purge \
  -H 'Content-Type: application/json' \
  -d '{"tags":["catalog","homepage"]}'

# Entire L1 (+ Redis L2 prefix when enabled)
curl -X POST http://127.0.0.1:9090/api/cache/purge \
  -H 'Content-Type: application/json' \
  -d '{"all":true}'
```

Tags are parsed from upstream response headers `Cache-Tag` (comma-separated) and `Surrogate-Key` (space-separated) when objects are stored in L1. Tag purge also deletes matching keys from Redis L2 when enabled.

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

## Hierarchy peers (hot reload)

Requires `HIERARCHY_ENABLED=true`. Reloads **static** parents/siblings only; multicast discovery peers are preserved. Does **not** rebind ICP/HTCP listeners or reload TLS.

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/hierarchy/peers` | List peers (`is_static` distinguishes config vs discovery) |
| `POST` | `/api/hierarchy/reload` | Re-read peers file or env |

**Source (in order):**

1. JSON file at `CACHE_PEERS_PATH` or `HIERARCHY_PEERS_PATH`
2. Else `CACHE_PARENTS` / `CACHE_SIBLINGS` env (same format as startup)

```json
{"parents":["parent.example.com:1488:1.0"],"siblings":["sib.example.com:1488:1.0:3130"]}
```

```bash
curl http://127.0.0.1:9090/api/hierarchy/peers

curl -X POST http://127.0.0.1:9090/api/hierarchy/reload \
  -H "Authorization: Bearer $CONTROL_API_TOKEN"
```

```json
{"status":"reloaded","source":"file","added":2,"removed":1,"preserved_discovery":3}
```

## Roadmap leftovers

- [x] Cache-Tags / Surrogate-Key purge (`{"tag":"..."}`)
- [x] Hierarchy peer hot reload (`/api/hierarchy/*`)
- [ ] Upstream TLS hot reload
- [ ] gRPC control plane
