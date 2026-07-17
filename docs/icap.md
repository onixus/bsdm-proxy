# ICAP adapter (P3)

Optional **ICAP** (RFC 3507) client for enterprise AV / URL filtering sidecars — Squid `adaptation_access` equivalent. Async sidecar pattern; not inline DLP.

Issue: [#99](https://github.com/onixus/bsdm-proxy/issues/99) · Mapping: [swg-backlog-mapping.md](swg-backlog-mapping.md) P3-1.

## Status (PoC)

| Item | Status |
|------|--------|
| Feature flag `ICAP_ENABLED` | ✅ |
| REQMOD (request + body, before upstream) | ✅ |
| RESPMOD (buffered MISS response) | ✅ |
| Streaming MISS RESPMOD | ❌ skipped (document only) |
| CONNECT raw tunnel | ❌ N/A (no HTTP body); MITM HTTPS re-enters HTTP path |
| Compose example (open-source ICAP) | ✅ profile `icap` |
| TLS to ICAP server | ❌ PoC uses plain TCP |

## Pipeline hook points

```
authenticate → rate_limit → [Wasm] → ACL → cache lookup
  → (MISS) collect request body
  → **ICAP REQMOD**          ← may return encapsulated HTTP (e.g. 403) to client
  → peer / upstream fetch
  → (buffered) collect response body
  → **ICAP RESPMOD**         ← may rewrite status/headers/body
  → cache store + client response
```

| Mode | When | Behavior |
|------|------|----------|
| **REQMOD** | After request body collect, before peer/upstream | `204` → continue; encapsulated HTTP response → return to client (block/rewrite) |
| **RESPMOD** | After buffered upstream body collect | `204` → continue; encapsulated HTTP response → serve adapted response (and cache under adapted status) |

Streaming MISS (`STREAMING_MISS_ENABLED`) does **not** call RESPMOD — enable buffering for full response scanning.

## Configuration

| Env | Default | Role |
|-----|---------|------|
| `ICAP_ENABLED` | `false` | Enable client at startup |
| `ICAP_URL` | `icap://127.0.0.1:1344/echo` | Service URI (`icap://host:port/path`) |
| `ICAP_TIMEOUT_MS` | `5000` | Connect + exchange timeout |
| `ICAP_FAIL_OPEN` | `true` | On error/timeout: allow (`false` → 502) |
| `ICAP_REQMOD` | `true` | Call REQMOD |
| `ICAP_RESPMOD` | `true` | Call RESPMOD (buffered only) |
| `ICAP_MAX_BODY_BYTES` | `1048576` | Cap body sent to ICAP (`0` = headers / null-body only) |

Example:

```bash
ICAP_ENABLED=true \
ICAP_URL=icap://127.0.0.1:1344/echo \
ICAP_FAIL_OPEN=true \
ICAP_REQMOD=true \
ICAP_RESPMOD=true \
cargo run -p bsdm-proxy --bin proxy
```

## Compose (open-source ICAP server)

Profile **`icap`** starts [c-icap](https://sourceforge.net/projects/c-icap/) via the community image `toolarium/toolarium-icap-clamav-docker` (c-icap + ClamAV on port **1344**):

```bash
# From repo root — sidecar only, or with full stack
docker compose --profile icap up -d icap

# Point the proxy at it (same Docker network: host `icap`)
# ICAP_ENABLED=true ICAP_URL=icap://icap:1344/srv_clamav
```

See `docker-compose.yml` service `icap`. Service path depends on the image (`/echo`, `/srv_clamav`, …) — check the image docs / `OPTIONS` to the ICAP URI.

## Limits / non-goals

- Not a substitute for cloud SWG inline AV; intended for on-prem ClamAV / commercial ICAP appliances.
- No request rewrite (modified `req-hdr`) in PoC — only allow vs encapsulated HTTP response.
- No ICAP-over-TLS in PoC.
- Fail-open by default so a downed scanner does not brick browsing.

## Tests

```bash
cargo test -p bsdm-proxy icap
```

In-process mock ICAP server covers allow (`204`) and block (encapsulated `403`).
