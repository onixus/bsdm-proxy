# BSDM-Proxy — Module & Flow Context Map

> Карта модулей и потоков данных. Таблицу крейтов и feature flags
> см. в корневом `AGENTS.md`.

## proxy/ — Hot Paths

```
main.rs
  └─ server.rs               bind listeners, handle_connection, TLS accept
       └─ proxy_service/
            ├─ mod.rs         ProxyService struct + new() + accessors
            ├─ request.rs     handle_request → HTTP / CONNECT dispatch
            ├─ policy.rs      check_acl, check_policy, tls_policy_decision
            ├─ cache_ops.rs   L1/L2 hit/miss, stale revalidation, streaming miss
            ├─ icap_wasm.rs   ICAP reqmod/respmod, WASM plugin hooks
            ├─ helpers.rs     extract_domain, user_fields, metrics helpers
            └─ types.rs       ProxyPolicy, TlsPolicyDecision, MissCompletionHandle
```

## Auth Flow

```
proxy_service/request.rs  → authenticate_proxy()
  └─ auth/mod.rs             AuthManager::handle_proxy_auth()
       ├─ auth/cache.rs      ConnAuthCache (per-TCP keep-alive session)
       ├─ auth/ldap.rs       LDAP/AD backend        [cfg(feature = "auth-ldap")]
       └─ auth/basic.rs      SSPI / NTLM / Kerberos [cfg(feature = "auth-ntlm|auth-kerberos")]
```

## Device / Agent Path

```
control_api/users.rs         enroll / heartbeat / revoke endpoints
  └─ device_registry/
       ├─ mod.rs             DeviceRegistry struct + all operations
       ├─ types.rs           RegisteredDevice, EnrollRequest, errors
       └─ storage.rs         File + Redis backends, hash_device_token
```

## Cache Event Pipeline

```
proxy_service/cache_ops.rs   send_cache_event()
  └─ pipeline.rs             dispatch_cache_event()
       ├─ HttpEventPipeline  HTTP webhook sink
       └─ KafkaEventPipeline [cfg(feature = "kafka")]
            └─ cache-indexer/ consumes → SQLite / ClickHouse
                 └─ ml-worker/   reads features → scoring → writeback
                 └─ alert-worker/ reads alerts → dedupe → webhook
```

## Control API Module Map

```
control_api/
  ├─ mod.rs        ControlApiState struct, handle_request, dispatch, auth
  ├─ types.rs      DTOs: StatsResponse, PurgeRequest, PeersListResponse …
  ├─ casb_dlp.rs   CASB & DLP management endpoints
  ├─ network.rs    AmneziaWG, upstream TLS, threat-sync, cluster session
  ├─ cache_mgmt.rs Cache purge, stats, WASM reload, static UI serving
  ├─ users.rs      Basic users CRUD, agent device enroll/heartbeat/revoke
  └─ hierarchy.rs  Hierarchy peers, reload, pinning, config get/apply
```

## Cache Subsystem

```
cache.rs             CacheEntry, CacheIndex — L1 in-memory cache
sharded_cache.rs     ShardedCache — lock-free sharded wrapper
cache_key.rs         cache key derivation
cache_body.rs        body storage (memory / mmap)
cache_compress.rs    zstd / brotli compression
cache_freshness.rs   HTTP freshness calculation (max-age, s-maxage, heuristic)
cache_digest.rs      cache digest (Bloom filter) for hierarchy
l2_cache.rs          Redis L2 cache backend
streaming_miss.rs    streaming cache miss with concurrent readers
miss_coalesce.rs     request coalescing for identical cache misses
semantic_cache.rs    semantic / AI-cache (embedding-based dedup)
```

## Hierarchy & Peers

```
hierarchy.rs         parent/sibling proxy hierarchy
hierarchy_config.rs  hierarchy configuration & parsing
peers.rs             peer proxy management
peer_discovery.rs    auto-discovery (multicast/DNS)
peer_fetch.rs        fetching from peer proxies
icp.rs               ICP (Internet Cache Protocol)
htcp.rs              HTCP (Hyper Text Caching Protocol)
selection.rs         peer selection algorithm
```

## Security & Policy

```
acl.rs               ACL rules engine
acl_api.rs           ACL management REST API
acl_config.rs        ACL configuration parsing
policy_config.rs     policy configuration
policy_cache.rs      policy decision cache
pinning.rs           TLS certificate pinning
categorization.rs    URL categorization engine
casb.rs              CASB (Cloud Access Security Broker)
dlp.rs               DLP (Data Loss Prevention) patterns
security_defaults.rs default security policies
security_util.rs     security utility functions
rate_limit.rs        per-user / per-IP rate limiting
rpz_api.rs           RPZ (Response Policy Zone) API
```

## Agent & mTLS

```
agent_api.rs         agent device API
agent_crl.rs         CRL (Certificate Revocation List) management
agent_events.rs      agent event types
agent_ocsp.rs        OCSP responder (RFC 6960)
agent_policy_hub.rs  centralized policy distribution
control_mtls.rs      mTLS control plane
```

## Frontend Projects

| Directory | Stack | Purpose |
|---|---|---|
| `admin-console/` | React 19 + TypeScript + Vite + Tailwind | Единая веб-консоль администрирования оператора |

## Files NOT to Load into LLM Context

- `Cargo.lock` (131 KB — dependency lock, никогда не редактируется вручную)
- `target/` (build artefacts)
- `proxy-native.log` (runtime log)
- `*.tmp`, `tmp/` (temporary files)
- `node_modules/` (npm dependencies)
- `admin-console/dist/` (build output)
- `*.tar.gz`, `*.deb`, `*.rpm` (package artefacts)
