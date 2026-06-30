# Authentication

> См. также: [оглавление документации](README.md) · [конфигурация в README](../README.md#конфигурация)

BSDM-Proxy supports proxy authentication backends for access control.

## Supported Backends

| Backend | Status | Build feature | Header |
|---------|--------|---------------|--------|
| **Basic** | ✅ | `auth-basic` (default) | `Proxy-Authorization: Basic` |
| **LDAP** | ✅ | `auth-ldap` | `Basic` (username/password) |
| **NTLM** | ✅ | `auth-ntlm` | `NTLM` (multi-round) |
| **Kerberos** | ✅ | `auth-kerberos` | `Negotiate` / SPNEGO (multi-round) |

Build with SSO backends:

```bash
cargo build -p bsdm-proxy --features auth-ntlm,auth-kerberos
# or all auth backends:
cargo build -p bsdm-proxy --features auth-all
```

### 1. Basic Authentication

Simple username extraction without external validation.

```bash
export AUTH_ENABLED=true
export AUTH_BACKEND=basic
export AUTH_REALM="BSDM-Proxy"
```

### 2. LDAP / Active Directory

Authenticate against LDAP or Active Directory servers (username/password).

```bash
export AUTH_ENABLED=true
export AUTH_BACKEND=ldap
export AUTH_REALM="Corporate Network"

export LDAP_SERVERS="ldap://dc1.example.com:389,ldap://dc2.example.com:389"
export LDAP_BASE_DN="dc=example,dc=com"
export LDAP_BIND_DN="cn=proxy-service,ou=services,dc=example,dc=com"
export LDAP_BIND_PASSWORD="service_password"
export LDAP_USER_FILTER="(sAMAccountName={username})"
export LDAP_GROUP_FILTER="(member={user_dn})"
export LDAP_USE_TLS=true
export LDAP_TIMEOUT=5
```

### 3. NTLM (Windows Integrated)

Multi-round NTLM handshake via `sspi`. For Active Directory validation use Samba **`ntlm_auth`** helper (recommended).

```bash
export AUTH_ENABLED=true
export AUTH_BACKEND=ntlm
export NTLM_DOMAIN="CORPORATE"
export NTLM_WORKSTATION="PROXY01"

# Recommended for AD: Squid-style helper (Samba winbind)
export NTLM_AUTH_HELPER="/usr/bin/ntlm_auth --helper-protocol=squid-2.5-ntlmssp"

# Optional lab/testing without AD: user:password file
# export NTLM_USERS_FILE=/etc/bsdm-proxy/ntlm-users.txt
```

Flow: client receives `407 Proxy-Authenticate: NTLM`, then exchanges Type 1/2/3 messages until authenticated.

### 4. Kerberos (SPNEGO)

Service accepts Kerberos tickets using a **keytab** (standard `HTTP/proxy@REALM` SPN).

```bash
export AUTH_ENABLED=true
export AUTH_BACKEND=kerberos   # alias: negotiate

export KRB5_KEYTAB=/etc/krb5.keytab
export KRB5_SERVICE_PRINCIPAL="HTTP/proxy.corp.example.com@CORP.EXAMPLE.COM"
export KRB5_HOSTNAME=proxy.corp.example.com
export KRB5_KDC_URL=tcp://dc.corp.example.com:88   # optional
export KRB5_MAX_TIME_SKEW_SECONDS=300
```

Clients must obtain a TGT (e.g. `kinit`) and send `Proxy-Authorization: Negotiate <token>`.

## Features

### User Caching

Successful authentications are cached to reduce load on authentication servers:

```bash
export AUTH_CACHE_TTL=300  # seconds (default: 5 minutes)
```

NTLM/Kerberos sessions are also keyed by client IP for the handshake duration.

### Group Membership (LDAP)

LDAP password backend (`AUTH_BACKEND=ldap`) loads `memberOf` during bind.

For **NTLM** and **Kerberos**, set the same `LDAP_*` variables plus a **service account** (`LDAP_BIND_DN`, `LDAP_BIND_PASSWORD`). After SSO handshake the proxy resolves groups via LDAP (no user password required):

```bash
export AUTH_BACKEND=ntlm   # or kerberos
export LDAP_GROUP_ENRICHMENT=true   # default when LDAP_SERVERS is set
export LDAP_SERVERS=ldaps://dc.corp.local:636
export LDAP_BASE_DN=dc=corp,dc=local
export LDAP_BIND_DN=cn=proxy-ldap,ou=services,dc=corp,dc=local
export LDAP_BIND_PASSWORD=service_secret
export LDAP_USER_FILTER="(sAMAccountName={username})"
```

Build with `auth-ldap` plus your SSO feature (or `auth-all`). Principal `user@REALM` is mapped to `sAMAccountName=user`; UPN lookup is tried as fallback.

Enrichment failures are logged; authentication still succeeds with empty groups.

### Security

- Passwords are never stored in plaintext (Basic/LDAP cache uses SHA-256)
- LDAP connections support TLS/SSL (`ldaps://` in `LDAP_SERVERS`)
- Kerberos uses keytab (no password on disk for service)
- Failed auth attempts are logged

## Configuration Examples

### Active Directory — LDAP (password)

```yaml
services:
  proxy:
    environment:
      - AUTH_ENABLED=true
      - AUTH_BACKEND=ldap
      - LDAP_SERVERS=ldaps://dc.corp.local:636
      - LDAP_BASE_DN=dc=corp,dc=local
      - LDAP_USER_FILTER=(sAMAccountName={username})
```

### Active Directory — Kerberos (domain-joined clients)

```yaml
services:
  proxy:
    environment:
      - AUTH_ENABLED=true
      - AUTH_BACKEND=kerberos
      - KRB5_KEYTAB=/etc/krb5.keytab
      - KRB5_SERVICE_PRINCIPAL=HTTP/proxy.corp.local@CORP.LOCAL
      - KRB5_HOSTNAME=proxy.corp.local
```

### Active Directory — NTLM with LDAP groups

```yaml
services:
  proxy:
    environment:
      - AUTH_ENABLED=true
      - AUTH_BACKEND=ntlm
      - NTLM_DOMAIN=CORP
      - NTLM_AUTH_HELPER=/usr/bin/ntlm_auth --helper-protocol=squid-2.5-ntlmssp
      - LDAP_SERVERS=ldaps://dc.corp.local:636
      - LDAP_BASE_DN=dc=corp,dc=local
      - LDAP_BIND_DN=cn=proxy-ldap,ou=services,dc=corp,dc=local
      - LDAP_BIND_PASSWORD=${LDAP_SERVICE_PASSWORD}
      - LDAP_USER_FILTER=(sAMAccountName={username})
```

Build with `--features auth-all` (or `auth-ntlm,auth-ldap`).

## Roadmap

- [x] NTLM auth — [#44](https://github.com/onixus/bsdm-proxy/issues/44)
- [x] Kerberos / SPNEGO with keytab
- [x] LDAP group lookup after NTLM/Kerberos principal resolution
- [ ] Auth Prometheus metrics (`bsdm_proxy_auth_*`)
