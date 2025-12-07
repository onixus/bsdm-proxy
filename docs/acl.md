# Access Control Lists (ACL)

Flexible access control system for BSDM-Proxy with multiple rule types and priority-based matching.

## Features

- ✅ **Domain-based rules** - Exact and wildcard matching
- ✅ **URL pattern matching** - Prefix and regex support
- ✅ **Category-based filtering** - Block by content category
- ✅ **Time-based access** - Schedule-based rules
- ✅ **User/group rules** - Per-user/group policies
- ✅ **IP-based rules** - Source IP filtering
- ✅ **Priority system** - Fine-grained control
- ✅ **Actions** - Allow, Deny, Redirect

## Rule Types

### 1. Domain Rules

```json
{
  "id": "block-gambling",
  "name": "Block gambling sites",
  "enabled": true,
  "priority": 100,
  "action": "deny",
  "rule_type": {
    "Domain": "*.gambling.com"
  }
}
```

**Wildcard patterns:**
- `example.com` - Exact match
- `*.example.com` - All subdomains
- `*example.com` - Ends with "example.com"

### 2. URL Prefix Rules

```json
{
  "id": "block-admin",
  "name": "Block admin pages",
  "enabled": true,
  "priority": 90,
  "action": "deny",
  "rule_type": {
    "UrlPrefix": "https://example.com/admin"
  }
}
```

### 3. Regex Rules

```json
{
  "id": "block-downloads",
  "name": "Block exe downloads",
  "enabled": true,
  "priority": 80,
  "action": "deny",
  "rule_type": {
    "Regex": "\\.exe$"
  }
}
```

### 4. Category Rules

```json
{
  "id": "block-adult",
  "name": "Block adult content",
  "enabled": true,
  "priority": 95,
  "action": "deny",
  "rule_type": {
    "Category": "adult"
  }
}
```

**Supported categories:**
- `adult`, `gambling`, `violence`, `weapons`, `drugs`
- `malware`, `phishing`, `spyware`
- `hacking`, `redirector`, `tracker`
- Custom categories from categorization engine

### 5. Time-based Rules

```json
{
  "id": "business-hours",
  "name": "Block social media during work",
  "enabled": true,
  "priority": 70,
  "action": "deny",
  "rule_type": {
    "TimeWindow": {
      "start": "09:00",
      "end": "17:00"
    }
  }
}
```

### 6. User/Group Rules

```json
{
  "id": "admin-allow",
  "name": "Allow admins everything",
  "enabled": true,
  "priority": 200,
  "action": "allow",
  "rule_type": {
    "Principal": {
      "user": null,
      "group": "admins"
    }
  }
}
```

### 7. IP Range Rules

```json
{
  "id": "internal-allow",
  "name": "Allow internal network",
  "enabled": true,
  "priority": 150,
  "action": "allow",
  "rule_type": {
    "IpRange": {
      "start": "192.168.1.0",
      "end": "192.168.1.255"
    }
  }
}
```

## Actions

### Allow
```json
{
  "action": "allow"
}
```
Permit the request to proceed.

### Deny
```json
{
  "action": "deny"
}
```
Block the request (HTTP 403).

### Redirect
```json
{
  "action": "redirect",
  "redirect_url": "https://blocked.company.com"
}
```
Redirect to another URL (HTTP 302).

## Priority System

Rules are evaluated in **descending priority order** (highest first).

```
Priority 200: Admin allow (matches first)
Priority 100: Block gambling
Priority 90:  Block admin pages
Priority 10:  Allow all
Default:      Deny all
```

**Best practices:**
- Use 200+ for override rules
- Use 100-199 for block rules
- Use 50-99 for allow rules
- Use 10-49 for default policies

## Configuration

### Environment Variables

```bash
# Enable ACL
ACL_ENABLED=true
ACL_DEFAULT_ACTION=deny  # allow, deny, redirect

# Rules file
ACL_RULES_PATH=/etc/bsdm-proxy/acl-rules.json

# Auto-reload
ACL_AUTO_RELOAD=true
ACL_RELOAD_INTERVAL=60  # seconds
```

### Rules File Format

```json
{
  "default_action": "deny",
  "rules": [
    {
      "id": "rule1",
      "name": "Description",
      "enabled": true,
      "priority": 100,
      "action": "allow",
      "rule_type": { "Domain": "example.com" },
      "comment": "Optional comment"
    }
  ]
}
```

## Examples

### Corporate Environment

```json
{
  "default_action": "deny",
  "rules": [
    {
      "id": "admin-override",
      "priority": 200,
      "action": "allow",
      "rule_type": { "Principal": { "group": "admins" } }
    },
    {
      "id": "allow-business",
      "priority": 100,
      "action": "allow",
      "rule_type": { "Category": "business" }
    },
    {
      "id": "block-adult",
      "priority": 150,
      "action": "deny",
      "rule_type": { "Category": "adult" }
    },
    {
      "id": "block-gambling",
      "priority": 150,
      "action": "deny",
      "rule_type": { "Category": "gambling" }
    },
    {
      "id": "block-malware",
      "priority": 180,
      "action": "deny",
      "rule_type": { "Category": "malware" }
    }
  ]
}
```

### School/Educational

```json
{
  "default_action": "allow",
  "rules": [
    {
      "id": "block-adult",
      "priority": 100,
      "action": "redirect",
      "rule_type": { "Category": "adult" },
      "redirect_url": "https://blocked.school.edu"
    },
    {
      "id": "block-social-during-class",
      "priority": 90,
      "action": "deny",
      "rule_type": { "Category": "social" },
      "time_window": { "start": "08:00", "end": "15:00" }
    },
    {
      "id": "allow-education",
      "priority": 80,
      "action": "allow",
      "rule_type": { "Category": "education" }
    }
  ]
}
```

### Public WiFi

```json
{
  "default_action": "allow",
  "rules": [
    {
      "id": "block-torrents",
      "priority": 100,
      "action": "deny",
      "rule_type": { "Regex": "\\.torrent$" }
    },
    {
      "id": "block-p2p-ports",
      "priority": 100,
      "action": "deny",
      "rule_type": { "UrlPrefix": ":6881" }
    },
    {
      "id": "block-malware",
      "priority": 150,
      "action": "deny",
      "rule_type": { "Category": "malware" }
    }
  ]
}
```

## Metrics

Prometheus metrics for ACL:

```promql
# ACL decisions
bsdm_proxy_acl_decisions_total{action="allow"}
bsdm_proxy_acl_decisions_total{action="deny"}
bsdm_proxy_acl_decisions_total{action="redirect"}

# Rules matched
bsdm_proxy_acl_rules_matched_total{rule_id="block-adult"}

# Evaluation time
bsdm_proxy_acl_eval_duration_seconds
```

## Best Practices

1. **Use specific rules** - More specific = higher priority
2. **Test rules** - Use allow-by-default during testing
3. **Document rules** - Use descriptive names and comments
4. **Monitor metrics** - Track deny/allow rates
5. **Regular review** - Audit rules periodically
6. **Whitelist critical** - High priority for business-critical domains
7. **Blacklist threats** - Highest priority for malware/phishing

## Troubleshooting

### Rule not matching

```bash
# Check logs
docker-compose logs -f proxy | grep -i acl

# Test domain matching
curl -x http://localhost:1488 https://example.com

# Check rule priority
cat acl-rules.json | jq '.rules | sort_by(.priority) | reverse'
```

### Performance issues

```bash
# Check regex cache size
curl http://localhost:9090/metrics | grep acl_regex_cache

# Reduce regex rules
# Use domain/prefix rules instead
```

## Integration

### With Authentication

User/group from auth system:
```json
{
  "rule_type": {
    "Principal": {
      "user": "john.doe@company.com",
      "group": null
    }
  }
}
```

### With Categorization

Automatic category from URL:
```json
{
  "rule_type": {
    "Category": "malware"
  }
}
```

## API

### Add Rule (REST)

```bash
curl -X POST http://localhost:9090/api/acl/rules \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "new-rule",
    "name": "New rule",
    "enabled": true,
    "priority": 100,
    "action": "deny",
    "rule_type": { "Domain": "blocked.com" }
  }'
```

### List Rules

```bash
curl http://localhost:9090/api/acl/rules
```

### Reload Rules

```bash
curl -X POST http://localhost:9090/api/acl/reload
```

---

**See also:**
- [Categorization](categorization.md)
- [Authentication](authentication.md)
