# Authentication

> См. также: [оглавление документации](../README.md) · [конфигурация в README](../README.md#конфигурация)

BSDM-Proxy supports proxy authentication backends for access control.

## Supported Backends

| Backend | Status | Build feature | Header |
|---------|--------|---------------|--------|
| **Basic** | ✅ Pilot day-1 | `auth-basic` (default) | `Proxy-Authorization: Basic` |
| **LDAP** | ✅ | `auth-ldap` | `Basic` (username/password) |
| **NTLM** | ✅ Beta | `auth-ntlm` | `NTLM` (multi-round) |
| **Kerberos** | ✅ Beta | `auth-kerberos` | `Negotiate` / SPNEGO (multi-round) |
| **OIDC** | ⚠ Experimental reverse-proxy only | default image | Browser OIDC for IAP (Google, Apple, any discovery-capable issuer) — **not** forward-proxy `AUTH_BACKEND` |

Pilot runbook (users file, smoke, load-test): [pilot-auth.md](../getting-started/pilot-auth.md).

Build with SSO backends:

```bash
cargo build -p bsdm-proxy --features auth-ntlm,auth-kerberos
# or all auth backends:
cargo build -p bsdm-proxy --features auth-all
```

### 1. Basic Authentication

Local username/password via `Proxy-Authorization: Basic`.

```bash
export AUTH_ENABLED=true
export AUTH_BACKEND=basic
export AUTH_REALM="BSDM-Proxy"
# Required for pilot/production — without this file any credentials are accepted:
export BASIC_AUTH_USERS_FILE=/etc/bsdm-proxy/basic-auth-users.json
```

Users file is JSON array of `{ "username", "password_hash", "role" }` where
`password_hash` is an **Argon2id PHC string** (`$argon2id$v=19$...`). Generate
entries with
`./scripts/gen-basic-auth-user.sh`. Example: `config/basic-auth-users.example.json`
(password `pilot-secret` — change before production).

Smoke: `./scripts/run-auth-pilot-smoke.sh`.

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
# Per-TCP-connection auth cache for HTTP keep-alive (0 = disabled)
export AUTH_CONN_CACHE_TTL_SECONDS=300
```

On keep-alive connections, a successful `Proxy-Authorization` is reused for subsequent requests on the same TCP socket without re-running LDAP/crypto. Set `AUTH_CONN_CACHE_TTL_SECONDS=0` to disable.

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

- Passwords are never stored in plaintext. Basic-auth entries are hashed with
  Argon2id; legacy unsalted SHA-256 hex digests still verify and are rewritten
  to Argon2id after the first successful login (see `BASIC_AUTH_REHASH_ON_LOGIN`)
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

## OIDC (reverse proxy / IAP)

`OIDC_*` настраивает **браузерный вход в reverse-proxy**, а не `AUTH_BACKEND`
для forward-SWG плоскости данных. Всё ниже относится только к
`REVERSE_PROXY_UPSTREAM`-режиму и остаётся experimental вне Day-1 пилота: см.
[project-status.md](../project-status.md) и
[pilot-auth.md](../getting-started/pilot-auth.md).

### Что делает прокси

1. Неаутентифицированный запрос уводится на `/-/login`. Если провайдер один —
   сразу к нему; если несколько — показывается страница выбора.
2. На authorization endpoint уходят `state`, `nonce` и PKCE-challenge (S256).
   Эндпоинты берутся из discovery-документа провайдера.
3. Колбэк (`/-/callback/{provider}`, GET или form_post) сверяет `state` с
   cookie, гасит его однократно и меняет код на токены.
4. `id_token` проверяется по подписи ключом из JWKS провайдера, затем по
   `iss`, `aud`, `azp`, `exp`, `nbf`, `iat` и `nonce`. Непроверенная почта
   (`email_verified: false`) отклоняется.
5. Выдаётся сессионная cookie `bsdm_session` со сроком
   `OIDC_SESSION_TTL_SECONDS`. Выход — `/-/logout`.

Имя пользователя выше по стеку выглядит как `{provider}:{email}` — почта
уникальна только внутри одного провайдера.

### Google

```bash
export REVERSE_PROXY_UPSTREAM=http://internal-app:8080
export OIDC_REDIRECT_BASE=https://proxy.corp.local
export OIDC_PROVIDERS=google

export OIDC_GOOGLE_CLIENT_ID=1234567890-abc.apps.googleusercontent.com
export OIDC_GOOGLE_CLIENT_SECRET=...
# Ограничить вход своим тенантом; без этого пустит любой аккаунт Google.
export OIDC_GOOGLE_ALLOWED_DOMAINS=corp.local
```

В Google Cloud Console нужен OAuth-клиент типа **Web application** с
Authorized redirect URI `https://proxy.corp.local/-/callback/google`.

`OIDC_GOOGLE_ALLOWED_DOMAINS` с ровно одним доменом дополнительно уходит в
параметр `hd`, чтобы Google сам показывал нужный тенант. Это подсказка для
экрана входа — сама проверка домена всё равно делается по claim'у после
верификации токена.

### Apple

```bash
export OIDC_PROVIDERS=apple
export OIDC_REDIRECT_BASE=https://proxy.corp.local

export OIDC_APPLE_CLIENT_ID=com.example.proxy          # Services ID, не App ID
export OIDC_APPLE_TEAM_ID=ABCDE12345
export OIDC_APPLE_KEY_ID=XYZ9876543
export OIDC_APPLE_PRIVATE_KEY_FILE=/etc/bsdm-proxy/AuthKey_XYZ9876543.p8
```

Три отличия Apple от остальных провайдеров, из-за которых он не заводится
«как обычный OIDC»:

- **Нет статического `client_secret`.** Его роль играет ES256-JWT, подписанный
  ключом из `.p8` (`iss` = Team ID, `sub` = Services ID). Прокси генерирует его
  на каждый обмен кода, так что ротация ключа сводится к замене файла.
- **Колбэк приходит POST-ом.** Запрос scope `name`/`email` переводит ответ в
  `response_mode=form_post`, то есть cross-site POST. Cookie со `state` в таком
  запросе доедет только с `SameSite=None; Secure` — **прокси обязан стоять за
  HTTPS**, иначе вход не завершится. Флаг выводится из схемы
  `OIDC_REDIRECT_BASE` и перекрывается `REVERSE_PROXY_SECURE_COOKIES`.
- **Имя пользователя приходит один раз.** Apple отдаёт `name` только при первой
  авторизации; `sub` и `email` стабильны, на них и стоит опираться.

Файл ключа монтируется только на чтение и только сервисному пользователю:

```yaml
services:
  proxy:
    volumes:
      - ./secrets/AuthKey_XYZ9876543.p8:/etc/bsdm-proxy/AuthKey_XYZ9876543.p8:ro
```

### Google и Apple одновременно

```bash
export OIDC_PROVIDERS=google,apple
export OIDC_REDIRECT_BASE=https://proxy.corp.local
# ... переменные обоих провайдеров из примеров выше
```

`/-/login` покажет обе кнопки. Redirect URI регистрируются свои для каждого:
`/-/callback/google` и `/-/callback/apple`.

### Произвольный issuer

```bash
export OIDC_PROVIDERS=corp
export OIDC_CORP_KIND=generic
export OIDC_CORP_ISSUER_URL=https://keycloak.corp.local/realms/main
export OIDC_CORP_CLIENT_ID=bsdm-proxy
export OIDC_CORP_CLIENT_SECRET=...
export OIDC_CORP_DISPLAY_NAME="Corporate SSO"
```

Для generic-провайдера discovery обязателен: без
`{issuer}/.well-known/openid-configuration` эндпоинты взять неоткуда.

### Ограничения

- Сессии живут в памяти процесса: рестарт разлогинивает всех, а в
  многоэкземплярной схеме нужен sticky routing.
- Группы из OIDC не читаются. `REVERSE_PROXY_ADMIN_GROUP` работает только на
  ветке AD/LDAP.
- `refresh_token` не запрашивается и не хранится: по истечении
  `OIDC_SESSION_TTL_SECONDS` пользователь проходит вход заново.

## Roadmap

- [x] NTLM auth — [#44](https://github.com/onixus/bsdm-proxy/issues/44)
- [x] Kerberos / SPNEGO with keytab
- [x] LDAP group lookup after NTLM/Kerberos principal resolution
- [x] Pilot Basic path + users file + smoke ([pilot-auth.md](../getting-started/pilot-auth.md))
- [ ] Auth Prometheus metrics (`bsdm_proxy_auth_*`)
