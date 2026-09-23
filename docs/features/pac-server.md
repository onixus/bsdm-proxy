# Built-in PAC / WPAD server

Issue: [#386](https://github.com/onixus/bsdm-proxy/issues/386)

`proxy` can publish one generated proxy auto-configuration file on a listener
separate from the authenticated control plane. This replaces the temporary
Python `bsdm-pac` service while keeping PAC delivery outside the proxy request
path.

The server is disabled by default and starts when `PAC_PROXY` is set.

## Endpoints

| Path | Purpose |
|------|---------|
| `GET /proxy.pac` | Canonical PAC file |
| `GET /wpad.dat` | WPAD-compatible alias |
| `GET /health` | Listener health (`ok`) |

`HEAD` is supported for all three paths. PAC responses use
`application/x-ns-proxy-autoconfig`, disable caching, and expose no control or
mutation API.

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `PAC_PROXY` | — | Enables PAC; proxy authority returned as `PROXY host:port` |
| `PAC_PORT` | `9091` | Listener port when `PAC_BIND` is not set |
| `PAC_BIND` | `0.0.0.0:${PAC_PORT}` | Listener IP and port |
| `PAC_BYPASS_FILE` | — | Optional domain list reloaded without restart |
| `PAC_RELOAD_INTERVAL_SECONDS` | `5` | Bypass-file polling interval |

Example for a native install:

```env
PAC_PROXY=proxy.corp.example:3128
PAC_BIND=0.0.0.0:9091
PAC_BYPASS_FILE=/etc/bsdm-proxy/pac-bypass.txt
PAC_RELOAD_INTERVAL_SECONDS=5
```

Then point clients at either URL:

```text
http://proxy.corp.example:9091/proxy.pac
http://proxy.corp.example:9091/wpad.dat
```

`PAC_PROXY` must be a bare authority with a numeric port. URL schemes,
credentials, paths and fallback directives are rejected. The generated result
ends with `PROXY host:port` and deliberately does **not** append `; DIRECT`, so a
proxy outage cannot silently bypass policy.

## Bypass file

The native package installs `/etc/bsdm-proxy/pac-bypass.txt`. Each non-comment
line is one domain:

```text
# Exact domain and every subdomain are DIRECT.
ozon.ru
vseinstrumenti.ru

# Internationalized domains must be written in ASCII/punycode.
xn--e1afmkfd.xn--p1ai
```

Rules:

- matching is case-insensitive;
- `example.com` matches both `example.com` and `*.example.com`;
- leading `.` / `*.` and a trailing dot are normalized;
- blank lines and lines beginning with `#` or `;` are ignored;
- raw Unicode, URL syntax, ports, underscores and JavaScript fragments are
  rejected;
- if any non-comment line is invalid, the complete reload is rejected and the
  last-known-good PAC remains active.

The file is read asynchronously. A successful change is visible after at most
`PAC_RELOAD_INTERVAL_SECONDS`; no process restart or systemd reload is needed.

## Always-direct destinations

The generated PAC returns `DIRECT` before consulting the bypass file for:

- plain hostnames, `localhost`, `*.localhost` and `*.local`;
- IPv4 loopback, RFC1918, link-local and carrier-grade NAT ranges;
- IPv6 loopback, unique-local and link-local literals.

Everything else uses `PAC_PROXY`.

## Operations

Expose the PAC listener only to client networks. It is intentionally
unauthenticated because clients must download it before they know the proxy
route. Restrict port `9091` with the host firewall or load balancer rather than
placing it on the public Internet.

Prometheus metrics are exported by the normal metrics endpoint:

- `bsdm_proxy_pac_requests_total{route,status}`;
- `bsdm_proxy_pac_reloads_total{result}`;
- `bsdm_proxy_pac_bypass_domains`.

Useful checks:

```bash
curl -fsS http://127.0.0.1:9091/health
curl -fsS http://127.0.0.1:9091/proxy.pac

# Edit the file; the process stays running.
echo 'ozon.ru' | sudo tee -a /etc/bsdm-proxy/pac-bypass.txt
```

## Tests

```bash
cargo test -p bsdm-proxy pac::tests
cargo clippy -p bsdm-proxy --all-targets -- -D warnings
```
