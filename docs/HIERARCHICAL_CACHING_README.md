# Hierarchical Caching for BSDM-Proxy

> См. также: [полная документация](hierarchical-caching.md) · [оглавление](README.md) · [architecture.md](architecture.md)

## Статус: Phase 4 интегрирована (v0.3.x)

Иерархический кеш **включён в runtime** и активируется через `HIERARCHY_ENABLED=true` (по умолчанию выключен).

Phase 4 добавляет: **peer discovery** (multicast), **cache digest** (Bloom filter), **HTCP** (опционально вместо ICP).

## Архитектура

### Уровни кеша

```
Level 1: Edge (локальный L1 quick_cache)
  ↓ ICP/HTCP query siblings (UDP :3130 / :4827)
  ↓ cache digest filter (optional)
  ↓ HTTP fetch parent on MISS
Level 2: Parent caches
  ↓
Origin Servers
```

### Реализованные модули

| Модуль | Файл | Статус |
|--------|------|--------|
| Peer registry | `peers.rs` | ✅ |
| ICP v2 UDP | `icp.rs` | ✅ client + server |
| HTCP UDP | `htcp.rs` | ✅ client + server |
| Cache digest | `cache_digest.rs` | ✅ Bloom + registry |
| Peer discovery | `peer_discovery.rs` | ✅ multicast beacons |
| Selection | `selection.rs` | ✅ round-robin, weighted, closest, hash |
| Hierarchy manager | `hierarchy.rs` | ✅ `resolve_source()` + digest filter |
| Env config | `hierarchy_config.rs` | ✅ |
| Peer HTTP fetch | `peer_fetch.rs` | ✅ `fetch_via_peer()` |
| Cache key | `cache_key.rs` | ✅ shared proxy + ICP/HTCP |
| Runtime wiring | `main.rs` | ✅ ICP/HTCP server + discovery |

## Поток запроса

```
1. Client → proxy
2. L1 cache lookup
   ├─ HIT → return
   └─ MISS → continue
3. [HIERARCHY_ENABLED] resolve_source(url)
   ├─ filter siblings by cache digest (optional)
   ├─ ICP/HTCP query siblings (parallel)
   ├─ select parent (strategy)
   └─ fetch_via_peer() on hit
4. origin fallback (http_client)
5. cache insert → digest update → response
```

## Конфигурация

### Переменные окружения

```bash
HIERARCHY_ENABLED=true

# Parents: host:port[:weight]
CACHE_PARENTS=parent1.example.com:1488:1.0,parent2.example.com:1488:0.5

# Siblings: host:port[:weight][:icp_port]
CACHE_SIBLINGS=sibling1.example.com:1488,sibling2.example.com:1488:1.0:3130

CACHE_SELECTION_STRATEGY=round-robin   # weighted, closest, hash

ICP_BIND=0.0.0.0:3130                  # локальный ICP server (UDP)
ICP_CLIENT_BIND=0.0.0.0:0              # ICP client bind
ICP_PEER_PORT=3130                     # default ICP port для siblings
ICP_TIMEOUT_MS=100
ICP_SERVER_ENABLED=true                # false — не слушать ICP
PARENT_TIMEOUT_SECONDS=5               # HTTP timeout к peer
ICP_MAX_SIBLING_QUERIES=10

# Phase 4: HTCP (вместо ICP для sibling queries)
HIERARCHY_USE_HTCP=false
HTCP_BIND=0.0.0.0:4827
HTCP_PEER_PORT=4827

# Phase 4: cache digest
HIERARCHY_DIGEST_ENABLED=true

# Phase 4: multicast discovery
PEER_DISCOVERY_ENABLED=false
PEER_DISCOVERY_MULTICAST=239.255.255.1:3131
```

Пример в пакете: [packaging/config/bsdm-proxy.env.example](../packaging/config/bsdm-proxy.env.example)

## Быстрый старт (два инстанса)

```bash
# Terminal 1: parent (с ICP)
HIERARCHY_ENABLED=true \
MITM_ENABLED=false \
HTTP_PORT=1488 \
ICP_BIND=127.0.0.1:3130 \
./target/release/proxy

# Terminal 2: child (parent = localhost:1488)
HIERARCHY_ENABLED=true \
MITM_ENABLED=false \
HTTP_PORT=1489 \
CACHE_PARENTS=127.0.0.1:1488:1.0 \
ICP_BIND=127.0.0.1:3131 \
./target/release/proxy

# Запрос через child
curl -x http://127.0.0.1:1489 http://httpbin.org/get
```

3-tier demo: `docker compose -f docker-compose.hierarchy.yml up -d --build`

## Тесты

```bash
cargo test -p bsdm-proxy --lib peers
cargo test -p bsdm-proxy --lib icp
cargo test -p bsdm-proxy --lib htcp
cargo test -p bsdm-proxy --lib cache_digest
cargo test -p bsdm-proxy --lib peer_discovery
cargo test -p bsdm-proxy --lib hierarchy
cargo test -p bsdm-proxy --lib peer_fetch
cargo test -p bsdm-proxy --lib hierarchy_config
```

## Roadmap (оставшееся)

- [ ] mTLS между peers
- [ ] `HIERARCHY_DIRECT_DOMAINS` — bypass parent для локальных доменов

## Ссылки

- [Squid Cache Hierarchy](http://www.squid-cache.org/Doc/config/cache_peer/)
- [RFC 2186: ICP v2](https://datatracker.ietf.org/doc/html/rfc2186)
- [RFC 2756: HTCP](https://datatracker.ietf.org/doc/html/rfc2756)
- [roadmap.md](roadmap.md)
