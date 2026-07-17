# Control plane API (DX Phase 2)

REST endpoints on the proxy metrics port (`METRICS_PORT`, default `9090`). No Grafana required for Lite ops.

See also: [strategic-roadmap.md](strategic-roadmap.md) Phase 2 · [acl.md](acl.md).

## Auth

| Variable | Role |
|----------|------|
| `CONTROL_API_TOKEN` | Preferred Bearer token for mutating control APIs |
| `ACL_API_TOKEN` | Fallback token (also used for `/api/acl/*`) |

`GET /api/stats`, `GET /api/hierarchy/peers`, and `GET /api/upstream/tls` are intentionally unauthenticated (local Lite monitoring).  
`POST /api/cache/purge`, `POST /api/hierarchy/reload`, `POST /api/upstream/tls/reload`, and all `/api/acl/*` require Bearer when a token is configured.

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

## Upstream TLS (hot reload)

Rebuilds the shared Hyper upstream client pool after re-reading env / CA file. In-flight requests keep the previous pool until idle drain.

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/upstream/tls` | Current snapshot (`http2_enabled`, `ca_cert_path`, `custom_ca`, `reloaded_at_unix`) |
| `POST` | `/api/upstream/tls/reload` | Re-read `UPSTREAM_CA_CERT` + `UPSTREAM_HTTP2_ENABLED` |

Typical flow: replace the PEM at `UPSTREAM_CA_CERT` (or flip `UPSTREAM_HTTP2_ENABLED` in the process env), then reload.

```bash
curl http://127.0.0.1:9090/api/upstream/tls

curl -X POST http://127.0.0.1:9090/api/upstream/tls/reload \
  -H "Authorization: Bearer $CONTROL_API_TOKEN"
```

```json
{
  "status": "reloaded",
  "tls": {
    "http2_enabled": false,
    "ca_cert_path": "/etc/bsdm-proxy/upstream-ca.crt",
    "custom_ca": true,
    "reloaded_at_unix": 1720000000
  }
}
```

On failure (missing/invalid CA file) the previous client is kept and the API returns `400`.

## gRPC control plane (optional)

Feature-flagged (`--features grpc`), **off by default**. REST stays the Lite / admin-console path.

```bash
# Build
cargo build -p bsdm-proxy --features grpc --bin proxy

# Run
CONTROL_GRPC_ENABLED=true \
CONTROL_GRPC_BIND=127.0.0.1:50051 \
CONTROL_API_TOKEN=secret \
cargo run -p bsdm-proxy --features grpc --bin proxy
```

| Variable | Default | Role |
|----------|---------|------|
| `CONTROL_GRPC_ENABLED` | `false` | Start gRPC server (requires build with `grpc` feature) |
| `CONTROL_GRPC_BIND` | `127.0.0.1:50051` | Listen address |

Auth matches REST: mutating RPCs need `authorization: Bearer <CONTROL_API_TOKEN>` when the token is set. Public: `GetStats`, `ListHierarchyPeers`, `GetUpstreamTls`.

Proto: [`proxy/proto/control_plane.proto`](../proxy/proto/control_plane.proto).

```bash
# Example (grpcurl)
grpcurl -plaintext localhost:50051 list
grpcurl -plaintext localhost:50051 bsdm.control.v1.ControlPlane/GetStats
grpcurl -plaintext -H 'authorization: Bearer secret' \
  -d '{"all":true}' localhost:50051 bsdm.control.v1.ControlPlane/PurgeCache
```

ACL CRUD remains REST-only (`/api/acl/*`).

## Roadmap leftovers

- [x] Cache-Tags / Surrogate-Key purge (`{"tag":"..."}`)
- [x] Hierarchy peer hot reload (`/api/hierarchy/*`)
- [x] Upstream TLS hot reload (`/api/upstream/tls*`)
- [x] gRPC control plane (`--features grpc`, [#187](https://github.com/onixus/bsdm-proxy/issues/187))
