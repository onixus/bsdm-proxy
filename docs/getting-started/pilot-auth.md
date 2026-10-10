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

Password hash = **Argon2id PHC string**. The algorithm lives only in the proxy
binary; `gen-basic-auth-user.sh` calls `proxy hash-password` rather than
reimplementing it, so the two can never drift apart.

Older files holding unsalted SHA-256 hex digests keep working: they are
recognised by the missing leading `$` and rewritten to Argon2id after the first
successful login, provided the users file and its directory are writable.

```bash
# Needs a built proxy binary; native install: set BSDM_PROXY_BIN=/opt/bsdm-proxy/bin/proxy
# Interactive prompt; the password is not placed in argv or shell history.
umask 077
./scripts/gen-basic-auth-user.sh --role users pilot \
  | python3 -c 'import json,sys; json.dump([json.load(sys.stdin)],sys.stdout,indent=2)' \
  > config/basic-auth-users.json
chmod 600 config/basic-auth-users.json
# Native install: copy this file to /etc/bsdm-proxy/basic-auth-users.json
# with ownership/read permissions for the service user.
# config/basic-auth-users.example.json contains PUBLIC demonstration credentials.
```

Example shape:

```json
[
  {
    "username": "pilot",
    "password_hash": "$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>",
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

**Pilot compose** (auth включена по умолчанию):

```bash
export AUTH_ENABLED=true
export BASIC_AUTH_USERS_HOST=./config/basic-auth-users.json
export BASIC_AUTH_USERS_FILE=/etc/bsdm-proxy/basic-auth-users.json
# HOST selects the source file; FILE is the path inside the container.
# Linux Docker: give the mounted 0600 file to the image UID/GID (1000:1000).
# Use the actual mapped identity if Docker user namespaces are enabled.
sudo chown 1000:1000 config/basic-auth-users.json
# Complete the CA/token/Grafana setup from pilot-deployment.md first.
docker compose -f docker-compose.yml -f deploy/compose/docker-compose.pilot.yml up -d proxy
```

In production, Basic auth without a users file fails startup. Development/test
may accept any credentials with an empty in-memory DB; always configure a real
users file for pilot/production. File/directory permissions must allow the proxy
service to read it (and to write it if login rehash is required).

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
| Always 407 with correct password | Hash format (Argon2id PHC string, or legacy SHA-256 hex); file path mounted; JSON parse errors in logs |
| 200 without password | `AUTH_ENABLED` false or users DB empty without file |
| ACL deny after auth | Rule match on username/groups (`role` → group) |
| CONNECT fails auth | Client must send Proxy-Authorization on CONNECT as well |
