# Pilot authentication (Basic lab + OIDC notes)

Day-1 pilot path for **forward proxy** authentication. Goal: someone else can
enable auth without tribal knowledge and verify it with a smoke script.

Related: [authentication.md](../features/authentication.md) ·
[pilot-deployment.md](pilot-deployment.md) ·
[control-plane-security.md](../ops-and-dev/control-plane-security.md).

---

## Recommendation matrix

| Scenario | Backend | Status for pilot |
|---|---|---|
| Lab / 100-user functional pilot | **Basic** + `BASIC_AUTH_USERS_FILE` | **Recommended day-1** |
| Corporate AD password | LDAP (`auth-ldap`) | Pilot optional (needs DC + service bind) |
| Domain-joined SSO | NTLM / Kerberos | Beta; separate stand |
| Browser reverse-proxy login | OIDC (reverse proxy module) | **Experimental / frozen** — not forward-SWG day-1 |

Forward proxy auth uses `Proxy-Authorization`. Admin Console control API uses
`CONTROL_API_TOKEN` Bearer (separate secret).

---

## Path A — Basic (pilot default when auth is on)

### 1. Create users file

Password hash = **SHA-256 hex of the raw password** (see `AuthManager::hash_password_stable`).

```bash
# Generate one user entry
./scripts/gen-basic-auth-user.sh pilot 'your-strong-password' users

# Example file (password for both users is pilot-secret — change before production):
cp config/basic-auth-users.example.json /etc/bsdm-proxy/basic-auth-users.json
# or edit and set real hashes
```

Example shape:

```json
[
  {
    "username": "pilot",
    "password_hash": "<sha256-hex>",
    "role": "users"
  }
]
```

`role` is exposed as a single group for ACL (`groups` contains the role string).

### 2. Enable on the proxy

```bash
export AUTH_ENABLED=true
export AUTH_BACKEND=basic
export AUTH_REALM="BSDM Pilot"
export BASIC_AUTH_USERS_FILE=/etc/bsdm-proxy/basic-auth-users.json
```

**Pilot compose** (optional day-1):

```bash
export AUTH_ENABLED=true
export BASIC_AUTH_USERS_FILE=./config/basic-auth-users.example.json
# mount is already declared in docker-compose.pilot.yml when AUTH is on
docker compose -f docker-compose.yml -f docker-compose.pilot.yml up -d proxy
```

Without `BASIC_AUTH_USERS_FILE` (and empty in-memory DB), Basic accepts **any**
username/password — fine for e2e, **unsafe for pilot**. Always set a users file
for pilot/production.

### 3. Client usage

```bash
# curl
curl -x http://127.0.0.1:3128 -U 'pilot:your-strong-password' \
  http://httpbin.org/get

# HTTPS MITM
curl --cacert certs/ca.crt -x http://127.0.0.1:3128 \
  -U 'pilot:your-strong-password' https://httpbin.org/uuid
```

Browser / OS proxy settings: configure proxy user/password for HTTP proxy.

### 4. Acceptance smoke

```bash
PROXY=http://127.0.0.1:3128 \
AUTH_USER=pilot AUTH_PASS=your-strong-password \
  ./scripts/run-auth-pilot-smoke.sh
```

Checks:

| Step | Expected |
|---|---|
| No credentials | HTTP **407** (or 401) |
| Valid user/pass | HTTP **200** (or redirect) |
| Wrong password | HTTP **407** / **401** |

### 5. Load-test with auth

```bash
BASIC_AUTH='pilot:your-strong-password' \
CONCURRENT_USERS=20 TEST_DURATION=30 \
  ./scripts/run-hybrid-load-test.sh
```

---

## Path B — OIDC (not day-1 forward proxy)

The OIDC integration under `OIDC_*` env vars is part of the **experimental
reverse proxy / IAP** module (`reverse_proxy.rs`), not `AUTH_BACKEND` for CONNECT
forward proxy.

| | |
|---|---|
| Scope | Browser apps behind reverse proxy |
| Status | **Experimental (Frozen)** per project-status |
| Pilot day-1 | **Out of scope** |

If a future pilot needs IdP for operators, prefer:

1. Authenticated gateway in front of Admin Console (`/admin/`) + `CONTROL_API_TOKEN`, or
2. LDAP/OIDC for **proxy** users via LDAP backend / future dedicated proxy-OIDC design.

Do not enable reverse-proxy OIDC as a substitute for `Proxy-Authorization` on the data plane.

---

## Path C — LDAP (enterprise pilot extension)

When AD is available:

```bash
export AUTH_ENABLED=true
export AUTH_BACKEND=ldap
export LDAP_SERVERS=ldaps://dc.example.com:636
export LDAP_BASE_DN=dc=example,dc=com
export LDAP_USER_FILTER='(sAMAccountName={username})'
# optional service bind for group enrichment
export LDAP_BIND_DN='cn=bsdm-proxy,ou=services,dc=example,dc=com'
export LDAP_BIND_PASSWORD='…'
```

Build feature: `auth-ldap` (or full image). Acceptance: same smoke with AD
user/password; ACL rule using LDAP groups if enrichment is configured.

---

## Security checklist (auth pilot)

- [ ] `AUTH_ENABLED=true` only with real `BASIC_AUTH_USERS_FILE` (or LDAP)
- [ ] Users file mode `0600`, not in git
- [ ] Control plane tokens still set (`CONTROL_API_TOKEN`) — independent of proxy auth
- [ ] `run-auth-pilot-smoke.sh` green
- [ ] Optional: hybrid load-test with `BASIC_AUTH` recorded under load-test-results
- [ ] OIDC reverse proxy **not** required for pass

---

## Troubleshooting

| Symptom | Check |
|---|---|
| Always 407 with correct password | Hash algorithm (SHA-256 hex of password only); file path mounted; JSON parse errors in logs |
| 200 without password | `AUTH_ENABLED` false or users DB empty without file |
| ACL deny after auth | Rule match on username/groups (`role` → group) |
| CONNECT fails auth | Client must send Proxy-Authorization on CONNECT as well |
