# ADR 0001: Tiered and sharded L1 HTTP cache

## Status

Accepted (2026-06)

## Context

HTTP Archive Top 1k sites bench (70 random sites, 12 parallel connections, 20 warm repeats) showed BSDM at ~500 Mbit/s warm goodput vs Squid ~657 Mbit/s, despite ~95% L1 HIT rate. Single-URL wrk HIT benchmarks remain much faster; the bottleneck is serving ~2.6 MB bodies from L1 under multi-worker load, not cache lookup.

Prior L1 design stored full response bodies inline in `quick_cache` (`Bytes` in heap). With `WORKER_COUNT=4` and a shared `Arc<Cache>`, all workers contended on one cache lock. Large bodies increased allocator pressure and memcpy on serve.

## Decision

1. **Tiered body storage (`CachedBody`)** — bodies below `CACHE_SPILL_THRESHOLD_BYTES` (default 256 KB) stay inline; larger bodies are written to temp spill files and served via `Bytes::from_owner` over a read-only mmap (Squid rock-like, userspace).

2. **Sharded L1 (`HttpL1Cache`)** — replace single `quick_cache` with N shards (default 16, power-of-2). Keys are hashed to a shard; each shard has its own `quick_cache` instance to reduce lock contention under `SO_REUSEPORT` multi-worker accept.

3. **Configuration** — new env vars: `CACHE_SPILL_THRESHOLD_BYTES`, `CACHE_SPILL_DIR`, `CACHE_SHARDS`.

## Consequences

### Positive

- Large HIT responses avoid holding full body in heap; mmap + `Bytes::from_owner` enables zero-copy serve.
- Sharded L1 scales better with `WORKER_COUNT > 1` on warm, large-object workloads.
- Spill files are removed when the cache entry is evicted or the `Bytes` owner is dropped.

### Negative / trade-offs

- Spill adds disk I/O on MISS/store for large objects (acceptable for objects that dominate RAM).
- L2 wire format still materializes body bytes (unchanged); tiering applies to L1 only.
- `CACHE_SHARDS` increases total capacity slightly (`per_shard = capacity / shards`, minimum 1 per shard).

## Alternatives considered

- **Streaming MISS only** — helps cold path, not warm HIT goodput; deferred (P1).
- **Single larger `quick_cache` + P0 TCP tuning** — improved cold path but warm goodput unchanged.
- **Per-worker L1** — higher MISS rate across workers; rejected.

## References

- `proxy/src/cache_body.rs`, `proxy/src/sharded_cache.rs`, `proxy/src/cache.rs`
- `docs/ops-and-dev/benchmarks.md`, `docs/architecture/performance.md`
