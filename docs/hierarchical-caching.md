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

### Environment Variables

```bash
# Enable hierarchical caching
HIERARCHY_ENABLED=true

# Parent caches (comma-separated)
CACHE_PARENTS=parent1.example.com:1488:1.0,parent2.example.com:1488:0.5
# Format: host:port:weight

# Sibling caches
CACHE_SIBLINGS=sibling1.example.com:1488,sibling2.example.com:1488

# ICP settings
ICP_PORT=3130
ICP_TIMEOUT_MS=100
ICP_ENABLED=true

# Selection strategy
CACHE_SELECTION_STRATEGY=weighted  # round-robin, weighted, closest, hash

# Peer discovery
PEER_DISCOVERY_ENABLED=true
PEER_DISCOVERY_MULTICAST=239.255.255.1:3131
PEER_DISCOVERY_INTERVAL_SEC=60

# Cache hierarchy rules
HIERARCHY_DIRECT_DOMAINS=localhost,127.0.0.1  # Bypass hierarchy
HIERARCHY_NEVER_DIRECT=false  # Always use hierarchy
```

### Configuration File (TOML)

```toml
[hierarchy]
enabled = true
selection_strategy = "weighted"
never_direct = false

[[hierarchy.parents]]
host = "parent1.example.com"
port = 1488
weight = 1.0
max_connections = 100
icp_port = 3130

[[hierarchy.parents]]
host = "parent2.example.com"
port = 1488
weight = 0.5
max_connections = 50
icp_port = 3130

[[hierarchy.siblings]]
host = "sibling1.example.com"
port = 1488
icp_port = 3130

[hierarchy.icp]
enabled = true
port = 3130
timeout_ms = 100
max_retries = 2

[hierarchy.discovery]
enabled = true
multicast_address = "239.255.255.1:3131"
announce_interval_sec = 60
ttl = 3

[hierarchy.rules]
# Domains to fetch directly (bypass hierarchy)
direct_domains = ["localhost", "127.0.0.1"]

# Domains to never cache
no_cache_domains = ["accounts.google.com"]

# Force parent for specific domains
[[hierarchy.rules.domain_routing]]
pattern = "*.cdn.example.com"
parent = "cdn-parent.example.com:1488"
```

## Implementation Plan

### Phase 1: Core Infrastructure

1. **Peer Management Module** (`proxy/src/peers.rs`)
   - Peer registry
   - Health checking (active/passive)
   - Connection pooling per peer
   - RTT tracking

2. **ICP Protocol** (`proxy/src/icp.rs`)
   - UDP server/client
   - ICP message encoding/decoding
   - Query/response handling
   - Timeout management

3. **Selection Strategy** (`proxy/src/selection.rs`)
   - Strategy trait
   - Implementations (round-robin, weighted, etc.)
   - Peer scoring

### Phase 2: Request Routing

4. **Hierarchy Manager** (`proxy/src/hierarchy.rs`)
   - Request flow coordination
   - Sibling queries (parallel ICP)
   - Parent fallback
   - Origin fallback

5. **Cache Fetcher** (`proxy/src/fetcher.rs`)
   - HTTP client for peer communication
   - Streaming responses
   - Error handling and retries

### Phase 3: Discovery & Optimization

6. **Peer Discovery** (`proxy/src/discovery.rs`)
   - Multicast announcements
   - Peer registration
   - Auto-configuration

7. **Cache Digest** (`proxy/src/digest.rs`)
   - Bloom filter for cached URLs
   - Periodic digest exchange
   - Digest-based pre-filtering

8. **Metrics** (extend `proxy/src/metrics.rs`)
   - Hierarchy metrics
   - Peer performance stats
   - ICP query stats

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

New Prometheus metrics:

```
bsdm_proxy_hierarchy_requests_total{peer, result}
bsdm_proxy_hierarchy_icp_queries_total{peer, result}
bsdm_proxy_hierarchy_peer_health{peer, type}
bsdm_proxy_hierarchy_peer_rtt_ms{peer}
bsdm_proxy_hierarchy_selection_duration_seconds
bsdm_proxy_hierarchy_fetch_duration_seconds{peer, cache_status}
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
