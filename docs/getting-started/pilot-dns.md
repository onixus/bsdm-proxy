# Pilot DNS sinkhole (Hybrid first hop)

Day-1 DNS path for Selective MITM pilot: **UDP RPZ-lite sidecar** before the
HTTP(S) proxy. Clients (or lab dig) query the sinkhole; blocked names never open
TLS to the origin.

Related: [dns-sinkhole.md](../features/dns-sinkhole.md) ·
[pilot-deployment.md](pilot-deployment.md) ·
[load-test-selective-mitm.md](../ops-and-dev/load-test-selective-mitm.md) ·
ADR [0004](../adr/0004-dns-sinkhole-sidecar.md).

---

## Day-1 scope

| Include | Exclude |
|---|---|
| UDP DNS on host **5353** → container 53 | Full recursive/BIND |
| Zone from `examples/dns/blocklist.rpz` (bind-mountable) | DNSSEC validation |
| Health `:8092` | Mandatory DoH/DoT (optional with TLS certs) |
| dig smoke + hybrid load-test DNS share | Shared runtime with proxy MITM |

Proxy ACL/categorization remain independent — DNS is a **first hop**, not a
replacement for SNI/MITM policy.

---

## Start

```bash
# Full stack (dns-sinkhole is a base service, not a profile):
docker compose -f docker-compose.yml -f docker-compose.pilot.yml up -d --build dns-sinkhole

# Or entire pilot stack:
docker compose -f docker-compose.yml -f docker-compose.pilot.yml up -d --build
```

Defaults:

| Env | Day-1 value |
|---|---|
| `DNS_SINKHOLE_ENABLED` | `true` |
| Host UDP | `5353` |
| `DNS_SINKHOLE_ACTION` | `sinkhole` → `127.0.0.1` |
| DoH / DoT | **off** (set `DNS_SINKHOLE_DOH_ENABLED=true` + TLS cert/key later) |
| Zone | `./examples/dns/blocklist.rpz` → `/etc/bsdm-proxy/blocklist.rpz` |

Custom zone:

```bash
export DNS_ZONE_HOST=./config/my-pilot.rpz
docker compose -f docker-compose.yml -f docker-compose.pilot.yml up -d dns-sinkhole
```

---

## Acceptance smoke

```bash
./scripts/run-dns-pilot-smoke.sh
```

| Check | Expected |
|---|---|
| `GET :8092/health` | ok |
| `dig @127.0.0.1 -p 5353 blocked.test A +short` | `127.0.0.1` (or NXDOMAIN if action=nxdomain) |
| `dig @127.0.0.1 -p 5353 badsite.test` | blocked (load-test default qname) |
| `dig @127.0.0.1 -p 5353 example.com A +short` | real A (forward) |

---

## Load-test integration

```bash
DNS_HOST=127.0.0.1 DNS_PORT=5353 DNS_QNAME=badsite.test \
CONCURRENT_USERS=20 TEST_DURATION=30 \
  ./scripts/run-hybrid-load-test.sh
```

The hybrid script’s ~5% DNS share uses `dig` against this resolver. Without
`dig` or a running sinkhole, that share falls back / counts errors — run the DNS
smoke first.

---

## Client pointing (lab)

- Host tools: `dig @127.0.0.1 -p 5353 …`
- Optional: set OS/container DNS to host:5353 only in isolated lab networks
- Do **not** publish 5353 to the public internet without access control

---

## DoH / DoT (optional, not day-1)

```bash
export DNS_SINKHOLE_DOH_ENABLED=true
export DNS_SINKHOLE_DOT_ENABLED=true
export DNS_SINKHOLE_TLS_CERT=/certs/ca.crt   # use a proper server cert in real deploys
export DNS_SINKHOLE_TLS_KEY=/certs/ca.key
# map 8443/853 in compose if needed
```

Prefer dedicated TLS material; CA key reuse is for lab only.

---

## Checklist (pilot DNS)

- [ ] `dns-sinkhole` healthy on `:8092`
- [ ] `./scripts/run-dns-pilot-smoke.sh` green
- [ ] Zone lists at least `blocked.test` + `badsite.test` (or custom qnames)
- [ ] Hybrid load-test run with `DNS_HOST`/`DNS_PORT` set
- [ ] Document who points resolvers at the sinkhole (lab vs corporate DHCP)
