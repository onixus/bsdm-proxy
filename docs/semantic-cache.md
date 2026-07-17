# Semantic / LLM cache (Phase 4 prep)

Content-addressable caching for LLM-style `POST` APIs, plus an optional local similarity index as a stand-in for a future vector DB.

See [strategic-roadmap.md](strategic-roadmap.md) Phase 4.

## Enable

```bash
SEMANTIC_CACHE_ENABLED=true
# Optional:
# SEMANTIC_CACHE_PATH_PREFIXES=/v1/chat/completions,/v1/completions,/chat/completions
# SEMANTIC_CACHE_TTL_SECONDS=3600
# SEMANTIC_CACHE_SIMILARITY=1.0          # <1.0 enables near-hit (cosine on local hash embed)
# SEMANTIC_CACHE_EMBED_DIMS=64
# SEMANTIC_CACHE_MAX_INDEX=10000
```

## Behavior

1. **Exact hit** — SHA-256 of `method + URL + normalized JSON body` (`model` + `messages` / `prompt`; other fields like `temperature` ignored).  
   Header: `X-Cache-Status: LLM-HIT` · metric `bsdm_proxy_semantic_cache_exact_hits_total`
2. **Near hit** (only if `SEMANTIC_CACHE_SIMILARITY < 1.0`) — local feature-hash embedding + cosine vs in-memory index.  
   Header: `X-Cache-Status: SEMANTIC-HIT` · metric `bsdm_proxy_semantic_cache_similar_hits_total`
3. **Miss** — upstream fetch; on `200` store in L1 with configured TTL (ignores provider `Cache-Control: no-store` / `private`).  
   Header: `X-Cache-Status: LLM-MISS` · index updated for future near-hits

Applies only to `POST` URLs whose path matches a configured prefix.

## Limits / next steps

- Local hashing embeddings are **not** true semantic embeddings — useful for near-duplicate prompts, not paraphrase matching.
- Next: plug in an external embedding API / vector store behind the same `SemanticIndex` shape.
