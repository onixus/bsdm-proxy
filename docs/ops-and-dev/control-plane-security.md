# Control plane & metrics security defaults (#271)

Safe defaults for the metrics/control listener (`METRICS_PORT`, default `9090`),
ACL REST API, Search API, and related scrape endpoints.

See also: [control-plane.md](../features/control-plane.md) ·
[admin-console-security.md](../features/admin-console-security.md) ·
[pilot-deployment.md](../getting-started/pilot-deployment.md).

---

## Чек-лист безопасности Control Plane для пилота (Pilot Security Checklist)

Перед допуском реальных пользователей оператор обязан подтвердить выполнение всех пунктов:

- [ ] **1. Fail-Closed для мутирующих API:** Все `POST`/`PUT`/`DELETE` запросы (`/api/config/apply`, `/api/cache/purge`, `/api/pinning/exceptions`, `/api/mitm/circuit-breaker/reset`, `/api/auth/*`, `/api/security/*`) требуют валидный Bearer token. При отсутствии токена запрос отклоняется с кодом `401 Unauthorized`.
- [ ] **2. Admin Console:** Действия мутации в консоли управления требуют ввода токена в `Settings → Console API`. Без токена мутации блокируются на клиенте и сервере (исключен silent success).
- [ ] **3. Сетевая изоляция портов:** Порт `:9090` (Control API / Metrics) и `:8080` (Search API) привязаны к внутренней management-сети либо `127.0.0.1` (`METRICS_BIND=127.0.0.1`). Доступ из публичного интернета закрыт фаерволом хоста (iptables / nftables / security group).
- [ ] **4. Защита приватного ключа CA:** Файл ключа `./certs/ca.key` (или `/etc/bsdm-proxy/ca.key`) имеет права `0600` (`chmod 600`) и доступен исключительно системному пользователю демона прокси (`bsdm`).
- [ ] **5. Конфигурация Compose:** В production/pilot overlay отключен `CONTROL_API_ALLOW_INSECURE` (`CONTROL_API_ALLOW_INSECURE=false`), заданы непустые `CONTROL_API_TOKEN`, `ACL_API_TOKEN` и `SEARCH_API_TOKEN`.
- [ ] **6. Threat Model:** Модель угроз и сценарии компрометации задокументированы (см. таблицу ниже).

---

## Threat model (short)

| Surface | Risk if open | Default posture (production) |
|---|---|---|
| Mutating control APIs (`POST /api/cache/purge`, config apply, TLS reload, breaker reset, exceptions) | Cache wipe, config rewrite, CA/pinning abuse | **Bearer required** (`CONTROL_API_TOKEN`) |
| ACL REST (`/api/acl/*`) | Policy bypass | **Bearer required** (ACL or CONTROL token) |
| Search / ingest (`/api/search`, `POST /api/events`) | Traffic metadata leak / event injection | **Bearer required** (`SEARCH_API_TOKEN`) |
| `GET /metrics` | Internal counters / cardinality leak | Open unless `METRICS_AUTH_TOKEN` / `METRICS_REQUIRE_AUTH` |
| `GET /health`, `/ready` | Low | Always open (probes) |
| `GET /api/stats` | Cache hit ratios | Open (local monitoring) |
| `GET /api/mitm/circuit-breaker` | Visibility of tripped domains | **Bearer required** |

Операторская процедура сброса брейкера (как понять, что он сработал, что
проверить до сброса, тело запроса и аудит) —
[certificate-pinning.md](../features/certificate-pinning.md#mitm-circuit-breaker-detection-and-operator-reset).
Настройки порогов — [configuration.md](configuration.md#mitm-circuit-breaker).

---

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `DEPLOYMENT_PROFILE` | `production` | Drives fail-closed behaviour |
| `CONTROL_API_TOKEN` | *unset* | Bearer for control plane (preferred) |
| `ACL_API_TOKEN` | falls back to CONTROL | Bearer for `/api/acl/*` |
| `CONTROL_API_ALLOW_INSECURE` | `false` | Lab only: allow production **without** token (open mutations) |
| `CONTROL_API_REQUIRE_TOKEN` | `false` | Force fail-closed in development/test |
| `METRICS_BIND` | `0.0.0.0` | Host for metrics/control listen address |
| `METRICS_AUTH_TOKEN` | *unset* | Bearer for `GET /metrics` |
| `METRICS_REQUIRE_AUTH` | `false` | If true, reuse `CONTROL_API_TOKEN` for scrape auth |
| `SEARCH_API_TOKEN` | *unset* | Bearer for Search API |
| `SEARCH_API_ALLOW_INSECURE` | *unset* (inherits CONTROL insecure) | Lab open search |
| `CONTROL_MTLS_ENABLED` | `false` | HTTPS agent API with **required** client cert |
| `CONTROL_MTLS_BIND` | `0.0.0.0:9443` | Agent mTLS listen address |
| `CONTROL_MTLS_CERT_FILE` / `KEY_FILE` | *auto* | Server leaf; unset → CA-signed `CONTROL_MTLS_SERVER_NAME` |
| `CONTROL_MTLS_CLIENT_CA_FILE` | `./certs/ca.crt` or CertCache CA | Trust store for client certs |
| `CONTROL_MTLS_SERVER_NAME` | `control.bsdm.local` | SAN/CN for auto server cert |
| `CONTROL_MTLS_REQUIRE_ENROLLED` | `false` | Peer cert fingerprint must match enrolled device |
| `CONTROL_MTLS_CHECK_CRL` | *on if mTLS enabled* | Reject peer certs listed in agent CRL |
| `AGENT_CRL_PATH` | *memory-only* | Durable JSON CRL (`fingerprint` + optional `serial`) |

OCSP:

- Lab JSON: `GET /api/v1/agent/ocsp/status?fingerprint=…` or `?serial=…`
  (`good` / `revoked` / `unknown`, Bearer/agent auth).
- **RFC 6960 DER**: `POST /api/v1/agent/ocsp` with body
  `application/ocsp-request` → `application/ocsp-response` (public, CA-signed).
  Optional `GET /api/v1/agent/ocsp?b64=…`.
- **TLS stapling** (data-plane MITM + control mTLS server leaves): CA-signed
  **good** staple in the TLS handshake (`TLS_OCSP_STAPLING`, default on;
  refresh `TLS_OCSP_STAPLE_REFRESH_SECS`). Not the agent client-cert status API.

### Agent control mTLS (optional)

Plain `METRICS_PORT` stays HTTP for Prometheus and Admin Console. Agents that
enrolled with CSR (`client_cert_pem` + private key) can use a **separate**
HTTPS port that **requires** a client certificate signed by the proxy CA:

```bash
export CONTROL_MTLS_ENABLED=true
export CONTROL_MTLS_BIND=0.0.0.0:9443
# optional: pin server leaf files; otherwise auto-issued from MITM CA
# export CONTROL_MTLS_CERT_FILE=./certs/control.crt
# export CONTROL_MTLS_KEY_FILE=./certs/control.key
export CONTROL_MTLS_CLIENT_CA_FILE=./certs/ca.crt
# optional: only accept certs whose fingerprint was stored at enroll
export CONTROL_MTLS_REQUIRE_ENROLLED=true
```

```bash
# After --enroll --mtls produced DEVICE_CERT / DEVICE_KEY / CA:
curl -fsS --cacert ca.crt --cert device.crt --key device.key \
  https://control.bsdm.local:9443/api/v1/agent/policy \
  -H "Authorization: Bearer $DEVICE_TOKEN" \
  --resolve control.bsdm.local:9443:127.0.0.1
```

Paths on the mTLS port: `/api/v1/agent/*`, `/api/v1/devices*`, `/health`.
Other control APIs remain on plain `METRICS_PORT` with Bearer auth.

### Production rules

1. **Missing `CONTROL_API_TOKEN`** → process **refuses to start**, unless
   `CONTROL_API_ALLOW_INSECURE=true` (lab).
2. With a token configured → all non-public `/api/*` need
   `Authorization: Bearer …` (constant-time compare).
3. Without a token in open lab mode → mutations are allowed (legacy), with loud warnings.

### Cache-indexer

With `SEARCH_API_ENABLED=true` and production profile, **missing
`SEARCH_API_TOKEN`** refuses to start unless `SEARCH_API_ALLOW_INSECURE=true`.

---

## Network policy recommendations

### Bare metal / VM pilot

```bash
# Prefer loopback or management NIC for control plane
export METRICS_BIND=127.0.0.1
export CONTROL_API_TOKEN="$(openssl rand -hex 32)"
export ACL_API_TOKEN="$CONTROL_API_TOKEN"
export SEARCH_API_TOKEN="$(openssl rand -hex 32)"
# optional scrape auth for Prometheus on the same host
export METRICS_REQUIRE_AUTH=true
```

- Do **not** publish `9090` / `8080` to the public internet.
- Put Prometheus/Grafana on the same host or private VPC; use scrape Bearer if exposed.
- Admin Console: reverse-proxy with SSO/mTLS in front of `/admin/` when off-box.

### Docker / Compose

Containers must often bind `0.0.0.0` so published ports work. Compensating controls:

1. Set real `CONTROL_API_TOKEN` / `SEARCH_API_TOKEN`.
2. Set `CONTROL_API_ALLOW_INSECURE=false` (pilot override does this).
3. Restrict host firewall / security groups to management subnets only.
4. Prefer not publishing Search (`8080`) outside the compose network when possible.

Lab compose files set `CONTROL_API_ALLOW_INSECURE=true` **explicitly** so
`docker compose up` still works without secrets. Pilot compose **requires** tokens.

### Kubernetes

- ClusterIP only for control/metrics; scrape via in-cluster Prometheus.
- Secrets for tokens via External Secrets / sealed secrets.
- NetworkPolicy: deny ingress to metrics port from non-monitoring namespaces.

---

## Quick verification

```bash
# Should 401 without Bearer when token configured / production fail-closed
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST http://127.0.0.1:9090/api/cache/purge \
  -H 'Content-Type: application/json' -d '{}'

# Health stays open
curl -fsS http://127.0.0.1:9090/health

# Scrape with optional auth
curl -fsS -H "Authorization: Bearer $METRICS_AUTH_TOKEN" \
  http://127.0.0.1:9090/metrics | head
```

---

## Code map

| Piece | Location |
|---|---|
| Production token gate | `proxy/src/security_defaults.rs` |
| Control API auth | `proxy/src/control_api.rs` (`is_authorized_bearer`) |
| ACL API auth | `proxy/src/acl_api.rs` |
| Metrics bind + scrape auth | `proxy/src/server.rs` (`metrics_server`) |
| Search fail-closed | `cache-indexer/src/search_api.rs`, `main.rs` |
