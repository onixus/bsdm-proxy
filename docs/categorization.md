# URL Categorization

Multi-backend URL categorization system with local and cloud-based threat intelligence.

## Overview

BSDM-Proxy supports 4 categorization engines:

1. **Shallalist** - Open-source local database
2. **URLhaus** - Malware URL database (abuse.ch)
3. **PhishTank** - Phishing detection
4. **Custom Database** - Your own categories

## Shallalist Integration

### What is Shallalist?

Shallalist is a free, German-maintained blacklist with 60+ categories and millions of domains.

**Download:** http://www.shallalist.de/

### Setup

```bash
# Download (updated weekly)
wget http://www.shallalist.de/Downloads/shallalist.tar.gz

# Extract
tar -xzf shallalist.tar.gz -C /var/lib/

# Structure:
/var/lib/shallalist/
  adv/domains
  adult/domains
  aggressive/domains
  ...
```

### Configuration

```bash
CATEGORIZATION_ENABLED=true
SHALLALIST_ENABLED=true
SHALLALIST_PATH=/var/lib/shallalist
```

### Categories (60+)

**Inappropriate:**
- adult, porn
- gambling, gamble
- violence, aggressive
- weapons, warez
- drugs, alcohol

**Malicious:**
- malware, virus
- phishing, phish
- spyware, spy
- hacking, hacker

**Advertising:**
- adv, advertising
- tracker, tracking
- redirector

**Safe:**
- education, schools
- news, press
- government, military
- health, medical
- finance, banking
- business
- shopping, shops
- social, socialnet

**Entertainment:**
- entertainment
- movies, video
- music, audio
- sports

[Full list](http://www.shallalist.de/categories.html)

## URLhaus Integration

### What is URLhaus?

URLhaus is abuse.ch's free malware URL database.

**Website:** https://urlhaus.abuse.ch/

### Features

- Real-time malware URL detection
- Botnet C&C tracking
- Malware distribution sites
- Free public API (no key)

### Configuration

```bash
URLHAUS_ENABLED=true
URLHAUS_API=https://urlhaus-api.abuse.ch/v1/url/
```

### API Response

```json
{
  "query_status": "ok",
  "url": "http://malicious.example.com",
  "threat": "malware_download",
  "tags": ["emotet", "botnet"]
}
```

**Category assigned:** `malware`

## PhishTank Integration

### What is PhishTank?

Community-driven phishing URL database.

**Website:** https://www.phishtank.com/

### Features

- Verified phishing URLs
- Community submissions
- Real-time verification
- Free API (registration required)

### Configuration

```bash
PHISHTANK_ENABLED=true
PHISHTANK_API=https://checkurl.phishtank.com/checkurl/
PHISHTANK_API_KEY=your_api_key_here
```

### API Response

```json
{
  "results": {
    "in_database": true,
    "verified": true,
    "phish_detail_page": "https://www.phishtank.com/phish_detail.php?phish_id=12345"
  }
}
```

**Category assigned:** `phishing`

## Custom Database

### Format (JSON)

```json
{
  "example.com": ["business", "finance"],
  "test.com": ["technology"],
  "internal.company.local": ["internal", "business"],
  "blocked-site.com": ["blocked"]
}
```

### Configuration

```bash
CUSTOM_DB_ENABLED=true
CUSTOM_DB_PATH=/etc/bsdm-proxy/custom-categories.json
```

### Auto-reload

```bash
CUSTOM_DB_AUTO_RELOAD=true
CUSTOM_DB_RELOAD_INTERVAL=300  # seconds
```

## Category Caching

### Why Cache?

- Reduce API calls
- Faster lookups
- Cost savings
- Offline operation

### Configuration

```bash
CATEGORIZATION_CACHE_TTL=3600  # 1 hour
```

### Cache Metrics

```promql
bsdm_proxy_categorization_cache_hits_total
bsdm_proxy_categorization_cache_misses_total
bsdm_proxy_categorization_cache_entries
```

## Usage with ACL

### Example: Block by Category

```json
{
  "id": "block-adult",
  "priority": 100,
  "action": "deny",
  "rule_type": {
    "Category": "adult"
  }
}
```

### Multiple Categories

A URL can have multiple categories:
- `example.com`: [`adv`, `tracker`]
- Matched if ANY category matches rule

## Performance

### Lookup Times

| Engine | Type | Latency |
|--------|------|--------|
| Shallalist | Local | <0.1ms |
| Custom DB | Local | <0.1ms |
| URLhaus | API | 50-200ms |
| PhishTank | API | 50-200ms |
| Cache hit | Memory | <0.01ms |

### Optimization

1. **Local first** - Shallalist + Custom DB checked first
2. **API fallback** - Only if no local match
3. **Caching** - All results cached (1h default)
4. **Async** - Non-blocking lookups

## Metrics

```promql
# Lookups by source
bsdm_proxy_categorization_lookups_total{source="shallalist"}
bsdm_proxy_categorization_lookups_total{source="urlhaus"}
bsdm_proxy_categorization_lookups_total{source="phishtank"}
bsdm_proxy_categorization_lookups_total{source="custom"}

# Performance
bsdm_proxy_categorization_duration_seconds{source}

# Cache
bsdm_proxy_categorization_cache_hits_total
bsdm_proxy_categorization_cache_hit_rate
```

## Best Practices

1. **Use Shallalist** - Best coverage, local, fast
2. **Enable URLhaus** - Real-time malware protection
3. **Enable PhishTank** - Phishing detection
4. **Custom whitelist** - Override false positives
5. **Monitor cache hit rate** - Should be >80%
6. **Update Shallalist weekly** - Fresh data

## Troubleshooting

### Shallalist not loading

```bash
# Check path
ls -la /var/lib/shallalist/adult/domains

# Check permissions
chmod -R 755 /var/lib/shallalist

# Check logs
docker-compose logs proxy | grep -i shallalist
```

### API not responding

```bash
# Test URLhaus
curl -X POST https://urlhaus-api.abuse.ch/v1/url/ -d "url=http://example.com"

# Test PhishTank
curl -X POST https://checkurl.phishtank.com/checkurl/ \
  -d "url=http://example.com&format=json"
```

### High API latency

- Increase cache TTL
- Disable non-critical APIs
- Use local databases only

---

**See also:**
- [ACL Configuration](acl.md)
- [Shallalist Categories](http://www.shallalist.de/categories.html)
