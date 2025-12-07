# Authentication

BSDM-Proxy supports multiple authentication backends for proxy access control.

## Supported Backends

### 1. Basic Authentication

Simple username extraction without external validation.

```bash
export AUTH_ENABLED=true
export AUTH_BACKEND=basic
export AUTH_REALM="BSDM-Proxy"
```

### 2. LDAP / Active Directory

Authenticate against LDAP or Active Directory servers.

```bash
export AUTH_ENABLED=true
export AUTH_BACKEND=ldap
export AUTH_REALM="Corporate Network"

# LDAP Configuration
export LDAP_SERVERS="ldap://dc1.example.com:389,ldap://dc2.example.com:389"
export LDAP_BASE_DN="dc=example,dc=com"
export LDAP_BIND_DN="cn=proxy-service,ou=services,dc=example,dc=com"
export LDAP_BIND_PASSWORD="service_password"
export LDAP_USER_FILTER="(sAMAccountName={username})"
export LDAP_GROUP_FILTER="(member={user_dn})"
export LDAP_USE_TLS=true
export LDAP_TIMEOUT=5
```

### 3. NTLM (Windows Integrated Authentication)

Challenge-response authentication for Windows environments.

```bash
export AUTH_ENABLED=true
export AUTH_BACKEND=ntlm
export NTLM_DOMAIN="CORPORATE"
export NTLM_WORKSTATION="PROXY01"
```

## Features

### User Caching

Successful authentications are cached to reduce load on authentication servers:

```bash
export AUTH_CACHE_TTL=300  # seconds (default: 5 minutes)
```

### Group Membership (LDAP)

LDAP backend extracts user group membership for analytics:

```json
{
  "username": "john.doe",
  "display_name": "John Doe",
  "email": "john.doe@example.com",
  "groups": [
    "CN=Engineering,OU=Groups,DC=example,DC=com",
    "CN=VPN Users,OU=Groups,DC=example,DC=com"
  ]
}
```

### Security

- Passwords are never stored in plaintext
- Cache uses SHA-256 password hashing
- LDAP connections support TLS/SSL
- Failed auth attempts are logged

## Configuration Examples

### Active Directory (Windows)

```yaml
services:
  proxy:
    environment:
      - AUTH_ENABLED=true
      - AUTH_BACKEND=ldap
      - AUTH_REALM=Corporate
      - LDAP_SERVERS=ldaps://dc.corp.local:636
      - LDAP_BASE_DN=dc=corp,dc=local
      - LDAP_BIND_DN=CN=ProxyService,CN=Users,DC=corp,DC=local
      - LDAP_BIND_PASSWORD=${LDAP_PASSWORD}
      - LDAP_USER_FILTER=(sAMAccountName={username})
      - LDAP_USE_TLS=true
```

### OpenLDAP

```yaml
services:
  proxy:
    environment:
      - AUTH_ENABLED=true
      - AUTH_BACKEND=ldap
      - LDAP_SERVERS=ldap://ldap.example.com:389
      - LDAP_BASE_DN=ou=users,dc=example,dc=com
      - LDAP_USER_FILTER=(uid={username})
      - LDAP_USE_TLS=false
```

### NTLM (Windows Domain)

```yaml
services:
  proxy:
    environment:
      - AUTH_ENABLED=true
      - AUTH_BACKEND=ntlm
      - NTLM_DOMAIN=CORPORATE
      - NTLM_WORKSTATION=PROXY01
```

## Client Configuration

### cURL with Basic Auth

```bash
curl -x http://username:password@localhost:1488 https://example.com
```

### Browser (Chrome/Firefox)

1. Configure proxy: `localhost:1488`
2. Enable "Use proxy authentication"
3. Enter credentials when prompted

### NTLM (Windows)

Windows will automatically use current user credentials:

```bash
# PowerShell
$proxy = [System.Net.WebProxy]::new('http://localhost:1488')
$proxy.UseDefaultCredentials = $true
[System.Net.WebRequest]::DefaultWebProxy = $proxy
```

## Metrics

Authentication metrics are exported to Prometheus:

```promql
# Authentication attempts
bsdm_proxy_auth_attempts_total{backend="ldap",result="success"}
bsdm_proxy_auth_attempts_total{backend="ldap",result="failure"}

# Cache statistics
bsdm_proxy_auth_cache_hits_total
bsdm_proxy_auth_cache_misses_total
bsdm_proxy_auth_cache_entries

# LDAP-specific
bsdm_proxy_auth_ldap_requests_total{server="dc1.example.com"}
bsdm_proxy_auth_ldap_duration_seconds
```

## Troubleshooting

### LDAP Connection Failed

```bash
# Test LDAP connectivity
ldapsearch -H ldap://dc.example.com -D "cn=admin,dc=example,dc=com" -W -b "dc=example,dc=com"

# Check logs
docker-compose logs -f proxy | grep -i ldap
```

### User Not Found

```bash
# Verify user filter
ldapsearch -H ldap://dc.example.com -b "dc=example,dc=com" "(sAMAccountName=username)"
```

### NTLM Challenge Failed

Ensure:
1. Domain is correctly configured
2. Client supports NTLM (Windows)
3. Proxy is joined to domain (if required)

## Security Best Practices

1. **Use TLS for LDAP** (`LDAP_USE_TLS=true`)
2. **Strong service account password**
3. **Limit service account permissions** (read-only)
4. **Short cache TTL** for sensitive environments
5. **Monitor failed auth attempts**
6. **Rotate service credentials regularly**

## Performance

- **Cache hit**: <0.1ms (local hash verification)
- **LDAP auth**: 50-200ms (depending on network)
- **NTLM auth**: 100-300ms (challenge-response)

## Roadmap

- [ ] OAuth2/OIDC support
- [ ] RADIUS authentication
- [ ] Multi-factor authentication (MFA)
- [ ] IP-based authentication bypass
- [ ] Rate limiting per user
