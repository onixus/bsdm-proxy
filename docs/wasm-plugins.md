# Wasm plugins (Strategic Phase 3)

Optional **Wasmtime** request hooks so policy/transform logic can ship as `.wasm` / `.wat` modules without rebuilding the proxy.

Issue: [#188](https://github.com/onixus/bsdm-proxy/issues/188) · Roadmap: [strategic-roadmap.md](strategic-roadmap.md) Phase 3.

## Status (PoC)

| Item | Status |
|------|--------|
| Feature flag `wasm` (default off) | ✅ |
| Hook point: after auth + rate-limit, before ACL | ✅ HTTP + CONNECT |
| Host ABI (`bsdm` imports) | ✅ |
| Fuel / memory limits | ✅ |
| PoC deny-suffix plugin | ✅ `examples/wasm/deny_blocked_suffix.wat` |
| Rust/AS SDK | sketch via ABI docs (full SDK later) |
| WASI FS/net | **not** granted |

## Build & run

```bash
# Needs a Rust toolchain that can link wasmtime (same as proxy)
cargo build -p bsdm-proxy --features wasm --bin proxy

WASM_ENABLED=true \
WASM_MODULE_PATH=examples/wasm/deny_blocked_suffix.wat \
WASM_FUEL=50000 \
WASM_FAIL_OPEN=true \
cargo run -p bsdm-proxy --features wasm --bin proxy
```

Lite builds stay without wasmtime: `--no-default-features --features auth-basic` (do **not** enable `wasm`).

| Env | Default | Role |
|-----|---------|------|
| `WASM_ENABLED` | `false` | Load module at startup |
| `WASM_MODULE_PATH` | — | Path to `.wasm` or `.wat` |
| `WASM_FUEL` | `50000` | Wasmtime fuel units per request |
| `WASM_FAIL_OPEN` | `true` | On trap/fuel: allow request (`false` → 502) |

## Hook placement

```
authenticate → rate_limit → [Wasm on_request] → ACL/policy → cache → upstream
```

- **Deny** → `403` with `X-Wasm-Hook: deny`
- **Allow** → optional request header rewrites from the guest, then ACL

## Guest ABI

Module must export `memory` and `on_request` (no params).

Imports from module `bsdm`:

| Import | Signature | Behavior |
|--------|-----------|----------|
| `url_contains` | `(ptr,len) -> i32` | 1 if request URL contains UTF-8 needle |
| `method_eq` | `(ptr,len) -> i32` | 1 if method equals needle (ASCII case-insensitive) |
| `set_request_header` | `(nptr,nlen,vptr,vlen)` | Queue header to set on allow |
| `deny` | `(rptr,rlen)` | Deny with reason string |

PoC guest (`examples/wasm/deny_blocked_suffix.wat`): deny if URL contains `.blocked.test`; else set `x-wasm-hook: allow`.

## Security constraints

- No WASI filesystem or network in the PoC host linker
- Fuel + store memory/instance limits
- Treat untrusted modules carefully; prefer fail-closed (`WASM_FAIL_OPEN=false`) in production when plugins are mandatory
- Not a multi-tenant SaaS isolation boundary yet

## Next steps

- Richer context (headers map, user groups) via host getters
- `pre-upstream` / `post-response` hooks
- Rust/AssemblyScript SDK crate compiling to the ABI
- Hot-reload module path via control plane
