# Semantic / LLM cache (Phase 4)

Content-addressable caching for LLM-style `POST` APIs, plus optional near-hit via a pluggable similarity index (local memory or **Qdrant**).

See [roadmap.md](../roadmap.md) (AI Traffic Phase) · issue [#189](https://github.com/onixus/bsdm-proxy/issues/189).

## Enable

```bash
SEMANTIC_CACHE_ENABLED=true
# Optional:
# SEMANTIC_CACHE_PATH_PREFIXES=/v1/chat/completions,/v1/completions,/chat/completions
# SEMANTIC_CACHE_TTL_SECONDS=3600
# SEMANTIC_CACHE_SIMILARITY=1.0          # <1.0 enables near-hit
# SEMANTIC_CACHE_EMBED_DIMS=64
# SEMANTIC_CACHE_MAX_INDEX=10000         # local index only
```

## Behavior

1. **Exact hit** — SHA-256 of `method + URL + normalized JSON body` (`model` + `messages` / `prompt`).
   Header: `X-Cache-Status: LLM-HIT` · `bsdm_proxy_semantic_cache_exact_hits_total`
2. **Near hit** (only if `SEMANTIC_CACHE_SIMILARITY < 1.0`) — embed + cosine / vector search.
   Header: `X-Cache-Status: SEMANTIC-HIT` · `bsdm_proxy_semantic_cache_similar_hits_total`
3. **Miss** — upstream fetch; on `200` store in L1 with configured TTL.
   Header: `X-Cache-Status: LLM-MISS` · index updated for future near-hits

Applies only to `POST` URLs whose path matches a configured prefix.

## Embeddings

| `SEMANTIC_EMBED_PROVIDER` | Behavior |
|---------------------------|----------|
| `local` (default) | Feature-hash embedding (`hash_embed`) — near-duplicate prompts, not paraphrases |
| `http` | `POST SEMANTIC_EMBED_URL` with `{"text","dims"}` → `{"embedding":[float…]}` |

## Vector backends

| `SEMANTIC_VECTOR_BACKEND` | When to use |
|--------------------------|-------------|
| `local` (default) | Single node, small index (`SEMANTIC_CACHE_MAX_INDEX`) |
| `qdrant` | Cross-node / larger indexes; requires `SEMANTIC_VECTOR_URL` |

```bash
# Qdrant (optional)
SEMANTIC_VECTOR_BACKEND=qdrant
SEMANTIC_VECTOR_URL=http://qdrant:6333
# SEMANTIC_VECTOR_COLLECTION=bsdm_semantic
# SEMANTIC_VECTOR_API_KEY=
SEMANTIC_CACHE_SIMILARITY=0.92
```

Collection is created on first upsert (`vectors.size = SEMANTIC_CACHE_EMBED_DIMS`, Cosine). Point payload stores `cache_key` for L1 lookup.

**Capacity:** keep local index for edge / Lite; use Qdrant when multiple proxy replicas must share near-hit state or the index exceeds tens of thousands of prompts. Exact `LLM-HIT` still uses per-node L1 (and optional Redis L2) — vector DB is only for near-hit keys.

## Metrics

| Metric | Meaning |
|--------|---------|
| `bsdm_proxy_semantic_cache_exact_hits_total` | Exact body-hash hits |
| `bsdm_proxy_semantic_cache_similar_hits_total` | Near-hit served from L1 |
| `bsdm_proxy_semantic_cache_vector_errors_total` | Embed or vector backend errors |

## Limits

- Local hash embeddings are **not** true semantic embeddings unless you point `SEMANTIC_EMBED_PROVIDER=http` at a real model.
- Exact-match path is unchanged and does not depend on the vector backend.
