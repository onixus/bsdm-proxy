# Hierarchical Caching Design

## Overview

Implementation of hierarchical caching similar to Squid proxy, allowing multiple BSDM-Proxy instances to form a cache hierarchy for improved hit rates and reduced upstream traffic.

## Architecture

```
                    ┌─────────────┐
                    │   Client    │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Child Cache│  (BSDM-Proxy instance)
                    │  (Level 1)  │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐ ┌──▼─────┐ ┌───▼──────┐
       │Parent Cache │ │Parent  │ │ Parent   │
       │   (Level 2) │ │Cache 2 │ │ Cache 3  │
       └──────┬──────┘ └────┬───┘ └────┬─────┘
              │             │           │
              └─────────────┼───────────┘
                            │
                     ┌──────▼──────┐
                     │   Origin    │
                     │   Servers   │
                     └─────────────┘
```

## Key Features

### 1. Cache Peer Types

#### Parent Cache
- Higher-level cache in hierarchy
- Queried before going to origin
- Can have multiple parents (load balancing)
- Selection strategies: round-robin, weighted, closest, hash-based

#### Sibling Cache
- Same-level cache (peer)
- Only queried for HITs (not MISS)
- Uses ICP/HTCP for cache queries
- Reduces load on parents and origin

### 2. Inter-Cache Communication Protocols

#### ICP (Internet Cache Protocol)
- UDP-based protocol (port 3130)
- Quick cache presence checks
- Responses: ICP_HIT, ICP_MISS, ICP_DENIED
- Low latency (~1-5ms typical)

#### HTCP (Hypertext Caching Protocol)
- Enhanced version of ICP
- Supports cache headers and metadata
- Authentication support
- More flexible but slightly higher overhead

#### HTTP Cache-Digest
- Bitmap-based cache summary
- Periodic exchange of cached URLs
- Reduces query overhead
- Bloom filter implementation

### 3. Cache Selection Algorithm

```rust
Enum CacheSelectionStrategy {
    RoundRobin,      // Simple rotation
    Weighted,        // Based on peer weight/capacity
    Closest,         // Lowest RTT
    HashBased,       // Consistent hashing by URL
    LeastLoaded,     // Based on active connections
}
```

### 4. Request Flow

```
1. Client Request → Child Cache
   ↓
2. Check Local Cache
   ├─ HIT → Return immediately
   └─ MISS → Continue
   ↓
3. Query Siblings (ICP)
   ├─ ICP_HIT → Fetch from sibling
   └─ ICP_MISS → Continue
   ↓
4. Query Parents (HTTP)
   ├─ Parent HIT → Return from parent
   └─ Parent MISS → Continue
   ↓
5. Fetch from Origin
   ↓
6. Store in Local Cache
   ↓
7. Return to Client
```

## Configuration

### Environment Variables (implemented)

```bash
# Enable hierarchical caching (default: false)
HIERARCHY_ENABLED=true

# Parent caches (comma-separated: host:port[:weight])
CACHE_PARENTS=parent1.example.com:1488:1.0,parent2.example.com:1488:0.5

# Sibling caches (host:port[:weight][:icp_port])
CACHE_SIBLINGS=sibling1.example.com:1488,sibling2.example.com:1488:1.0:3130

# Optional peers JSON file (overrides CACHE_PARENTS / CACHE_SIBLINGS when set)
# CACHE_PEERS_PATH=/etc/bsdm/peers.json
# HIERARCHY_PEERS_PATH=/etc/bsdm/peers.json   # alias
# {"parents":["parent:1488:1.0"],"siblings":["sib:1488:1.0:3130"]}
# Hot reload: POST /api/hierarchy/reload  (see control-plane.md)

# ICP server bind (UDP, default 0.0.0.0:3130)
ICP_BIND=0.0.0.0:3130

# ICP client bind (default 0.0.0.0:0)
ICP_CLIENT_BIND=0.0.0.0:0

# Default ICP port for siblings without explicit icp_port
ICP_PEER_PORT=3130

ICP_TIMEOUT_MS=100
ICP_SERVER_ENABLED=true          # set false to disable local ICP listener
PARENT_TIMEOUT_SECONDS=5
ICP_MAX_SIBLING_QUERIES=10

# Selection strategy: round-robin, weighted, closest, hash
CACHE_SELECTION_STRATEGY=weighted

# Phase 4: HTCP instead of ICP for sibling queries (default: false)
HIERARCHY_USE_HTCP=false
HTCP_BIND=0.0.0.0:4827
HTCP_CLIENT_BIND=0.0.0.0:0
HTCP_PEER_PORT=4827
HTCP_SERVER_ENABLED=true

# Phase 4: cache digest (Bloom filter) — skip sibling queries when peer unlikely to have URL
HIERARCHY_DIGEST_ENABLED=true
HIERARCHY_DIGEST_BITS=65536
HIERARCHY_DIGEST_HASHES=4
HIERARCHY_DIGEST_REMOTE_TTL_SECONDS=300

# Phase 4: multicast peer discovery (optional)
PEER_DISCOVERY_ENABLED=false
PEER_DISCOVERY_MULTICAST=239.255.255.1:3131
PEER_DISCOVERY_INTERVAL_SECONDS=30
PEER_DISCOVERY_HOST=10.0.0.5
PEER_DISCOVERY_NODE_ID=edge-1
PEER_DISCOVERY_WEIGHT=1.0
PEER_DISCOVERY_DIGEST_EVERY=5
```

### Planned (not yet implemented)

```bash
HIERARCHY_DIRECT_DOMAINS=localhost,127.0.0.1
```

### Peers JSON file

When `CACHE_PEERS_PATH` (or `HIERARCHY_PEERS_PATH`) is set, static peers load from that file instead of `CACHE_PARENTS` / `CACHE_SIBLINGS`. Call `POST /api/hierarchy/reload` on the metrics port after editing the file (discovery siblings are preserved). See [control-plane.md](control-plane.md).

### Configuration File (TOML)

Full TOML config is still planned. Env vars + optional peers JSON cover runtime hierarchy peer changes.

## Implementation Status

### Phase 1: Core Infrastructure ✅

1. **Peer Management** (`proxy/src/peers.rs`) — done
2. **ICP Protocol** (`proxy/src/icp.rs`) — done
3. **Selection Strategy** (`proxy/src/selection.rs`) — done

### Phase 2: Request Routing ✅

4. **Hierarchy Manager** (`proxy/src/hierarchy.rs`) — done
5. **Cache Fetcher** (`proxy/src/peer_fetch.rs`) — done (HTTP/1 forward proxy)

### Phase 3: Integration ✅ (v0.2.3-test dev)

6. **Configuration** (`proxy/src/hierarchy_config.rs`) — env vars
7. **Runtime wiring** (`proxy/src/main.rs`) — request path + ICP server spawn
8. **Cache key** (`proxy/src/cache_key.rs`) — shared L1 + ICP lookup
9. **Docker-compose** (`docker-compose.hierarchy.yml`) — 3-tier demo
10. **Hierarchy Prometheus metrics** (`bsdm_proxy_hierarchy_*`)

### Phase 4: Discovery & Optimization ✅ (v0.3.x)

11. **Peer Discovery** (`proxy/src/peer_discovery.rs`) — multicast JSON beacons
12. **Cache Digest** (`proxy/src/cache_digest.rs`) — Bloom filter + remote registry
13. **HTCP** (`proxy/src/htcp.rs`) — optional sibling query protocol (UDP :4827)
14. **Digest metric** — `bsdm_proxy_hierarchy_digest_skipped_icp_total`

## Data Structures

### Peer Configuration

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachePeer {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub peer_type: PeerType,
    pub weight: f64,
    pub icp_port: Option<u16>,
    pub max_connections: usize,
    pub healthy: AtomicBool,
    pub rtt_ms: AtomicU64,
    pub stats: PeerStats,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PeerType {
    Parent,
    Sibling,
}

#[derive(Clone, Debug, Default)]
pub struct PeerStats {
    pub requests: AtomicU64,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub errors: AtomicU64,
    pub bytes_received: AtomicU64,
}
```

### ICP Message

```rust
#[derive(Debug, Clone)]
pub struct IcpMessage {
    pub opcode: IcpOpcode,
    pub version: u8,
    pub request_number: u32,
    pub url: String,
    pub requester_host: String,
}

#[derive(Debug, Clone, Copy)]
pub enum IcpOpcode {
    Query = 1,
    Hit = 2,
    Miss = 3,
    Error = 4,
    Denied = 22,
}
```

## Performance Considerations

### Latency Optimization
- **Parallel ICP queries**: Query all siblings simultaneously
- **Timeout budget**: 100ms for ICP, fail fast
- **Connection reuse**: Keep-alive to parents/siblings
- **Early termination**: Stop on first ICP_HIT

### Bandwidth Optimization
- **Cache Digest**: Avoid unnecessary ICP queries
- **Conditional requests**: Use If-Modified-Since with parents
- **Compression**: Gzip/Brotli between peers

### Availability
- **Health checks**: Passive (error counting) + Active (periodic probes)
- **Automatic failover**: Remove unhealthy peers from rotation
- **Circuit breaker**: Temporary disable failing peers
- **Graceful degradation**: Fall back to origin if all peers fail

## Metrics

Prometheus metrics (v0.2.x / M2):

```
bsdm_proxy_hierarchy_resolutions_total{result}   # sibling_hit, parent_hit, origin_required
bsdm_proxy_hierarchy_peer_requests_total{peer_type, outcome}  # parent|sibling × hit|miss|error
bsdm_proxy_hierarchy_icp_queries_total{outcome}  # hit, miss, timeout, error
bsdm_proxy_hierarchy_lookup_duration_seconds
```

Example queries:

```promql
rate(bsdm_proxy_hierarchy_resolutions_total[5m])
rate(bsdm_proxy_hierarchy_peer_requests_total{outcome="hit"}[5m])
  / rate(bsdm_proxy_hierarchy_peer_requests_total[5m])
```

## Testing Strategy

### Unit Tests
- ICP message encoding/decoding
- Selection algorithms
- Peer health tracking

### Integration Tests
- Multi-instance setup (docker-compose)
- Parent-child communication
- Sibling ICP exchange
- Failover scenarios

### Performance Tests
- Latency impact (<10ms overhead target)
- Throughput with hierarchy
- Cache hit rate improvement
- Peer discovery scalability

## Migration Path

### Backward Compatibility
- Hierarchy is **opt-in** (disabled by default)
- Existing single-instance deployments unchanged
- Graceful degradation if peers unavailable

### Deployment Scenarios

#### Scenario 1: Edge + Central
```
Edge Locations (child caches)
    ↓
Central Datacenter (parent cache)
    ↓
Origin Servers
```

#### Scenario 2: Geo-distributed
```
Regional Caches (siblings to each other)
    ↓
Global Parent Cache
    ↓
Origin Servers
```

#### Scenario 3: Multi-tier CDN
```
POP Caches (Level 1)
    ↓
Regional Caches (Level 2)
    ↓
Core Cache (Level 3)
    ↓
Origin Servers
```

## Security Considerations

- **Peer Authentication**: Shared secret or mTLS
- **ICP filtering**: Accept queries only from known peers
- **Cache poisoning prevention**: Verify parent responses
- **Access control**: Restrict which URLs can be fetched from peers

## Future Enhancements

- HTTPS between peers (TLS)
- HTCP protocol support
- Dynamic peer weights based on performance
- Geographic peer selection (GeoIP)
- Cache warming from digest
- Negative caching coordination
- Partial content caching (byte ranges)

## References

- [Squid Cache Hierarchy](http://www.squid-cache.org/Doc/config/cache_peer/)
- [RFC 2186: Internet Cache Protocol (ICP)](https://datatracker.ietf.org/doc/html/rfc2186)
- [RFC 2756: Hyper Text Caching Protocol (HTCP)](https://datatracker.ietf.org/doc/html/rfc2756)
- [Cache Digests (RFC 3040)](https://datatracker.ietf.org/doc/html/rfc3040)
