# DNS sinkhole / DNS security (P3)

Optional **DNS-layer** filtering (Cisco Umbrella–style first hop). Separate on-ramp from the explicit forward proxy.

Issue: [#108](https://github.com/onixus/bsdm-proxy/issues/108) · Roadmap: [roadmap.md](roadmap.md) · ADR: [adr/0004-dns-sinkhole-sidecar.md](adr/0004-dns-sinkhole-sidecar.md)

## Scope decision

| Option | Verdict |
|--------|---------|
| Inline in `bsdm-proxy` hot path | **Rejected** — different on-ramp; pollutes cache/MITM path |
| Full recursive resolver / BIND RPZ | **Out of scope** for PoC — ops already have Unbound/BIND |
| **Sidecar UDP DNS proxy** (`dns-sinkhole` crate) | **Accepted** — blocklist/RPZ-lite → sinkhole or NXDOMAIN; else forward to upstream |

Clients point DHCP/DoH stub / container `dns:` at this service. The HTTPS proxy keeps ACL/UT1; DNS is an optional first hop.

## Status (PoC)

| Item | Status |
|------|--------|
| Design / ADR | ✅ |
| Crate `dns-sinkhole` (UDP :53) | ✅ |
| RPZ-lite zone file + plain domain list | ✅ |
| Sinkhole A/AAAA or NXDOMAIN | ✅ |
| Forward to upstream resolver | ✅ |
| Compose profile `dns-sinkhole` | ✅ |
| DoH / DoT / DNSSEC validation | ❌ later |
| Full RFC RPZ (client-IP triggers, NSDNAME, …) | ❌ sketch only |

## Run

```bash
# Blocklist example (RPZ-lite + plain names)
DNS_SINKHOLE_ENABLED=true \
DNS_SINKHOLE_BIND=0.0.0.0:5353 \
DNS_SINKHOLE_UPSTREAM=1.1.1.1:53 \
DNS_SINKHOLE_ZONE_PATH=examples/dns/blocklist.rpz \
DNS_SINKHOLE_ACTION=sinkhole \
DNS_SINKHOLE_A=127.0.0.1 \
cargo run -p dns-sinkhole

# Query
dig @127.0.0.1 -p 5353 blocked.test A +short
# → 127.0.0.1
```

| Env | Default | Role |
|-----|---------|------|
| `DNS_SINKHOLE_BIND` | `0.0.0.0:53` | UDP listen |
| `DNS_SINKHOLE_UPSTREAM` | `1.1.1.1:53` | Forward resolver |
| `DNS_SINKHOLE_ZONE_PATH` | — | Required path to zone/list file |
| `DNS_SINKHOLE_ACTION` | `sinkhole` | `sinkhole` \| `nxdomain` |
| `DNS_SINKHOLE_A` | `127.0.0.1` | Sinkhole IPv4 |
| `DNS_SINKHOLE_AAAA` | `::1` | Sinkhole IPv6 |
| `DNS_SINKHOLE_TTL` | `300` | Answer TTL |
| `METRICS_PORT` | `8092` | `/health` + `/metrics` |
| `DNS_SINKHOLE_ENABLED` | `true` | Set `false` to no-op exit (compose convenience) |

## Zone file (RPZ-lite sketch)

```text
; comment
$TTL 300
blocked.test.          CNAME .
*.evil.example.        CNAME .
phishing.test.         A     127.0.0.1

# plain list (suffix match if leading '.')
malware.example
.blocked.suffix
```

- `CNAME .` → treat as policy block (same as action)
- Explicit `A` / `AAAA` in zone override sinkhole defaults for that name
- Leading `.` on a bare name → suffix match

## Compose

```bash
docker compose --profile dns-sinkhole up -d --build dns-sinkhole
# Clients / other containers: dns: ["dns-sinkhole"]  or publish 53/udp
```

## Relation to proxy

| Plane | Mechanism |
|-------|-----------|
| DNS first hop | This sidecar |
| Explicit HTTP(S) proxy | ACL + categorization + Wasm + ICAP |

No shared runtime. Optional future: feed sinkhole hits into ClickHouse via a small logger (not in PoC).

## Tests

```bash
cargo test -p dns-sinkhole
```
