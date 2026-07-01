# Categorization

BSDM proxy categorizes HTTP(S) traffic using a layered engine: local domain lists, optional OTX threat intel, and optional ML (stub).

## Architecture

```
Request URL → extract hostname
    → Local category DB (UT1 Blacklists, optional)
    → OTX threat intel (optional)
    → ML classifier (stub, optional)
    → Category + confidence + source
```

## Local category database (UT1 Blacklists)

**UT1 Blacklists** ([Université Toulouse 1 Capitole](https://dsi.ut-capitole.fr/blacklists/)) replace the deprecated Shallalist. The on-disk layout is the same idea: one directory per category with a `domains` file (one hostname per line).

| Category folder | BSDM `Category` |
|-----------------|-----------------|
| `adult` | Adult |
| `agressif` | Malware |
| `chat` | Chat |
| `mixed` | Mixed |
| `publicite` | Ads |
| `redirector` | Redirector |
| `social_networks` | Social |
| `dangerous_material` | Dangerous |
| `drogue` | Drugs |
| `gambling` | Gambling |
| `hacking` | Hacking |
| `malware` | Malware |
| `phishing` | Phishing |
| `warez` | Warez |
| `violence` | Violence |
| `press` | News |
| `radio` | Radio |
| `webmail` | Webmail |
| `shopping` | Shopping |
| `bank` | Finance |
| `jobsearch` | JobSearch |
| `searchengines` | SearchEngines |
| `strong_redirector` | StrongRedirector |
| `ddos` | DDoS |
| `arjel` | Gambling |
| `cryptojacking` | Cryptojacking |
| `botnet` | Botnet |
| `exe` | Executable |

Subdomains match parent entries (e.g. `www.example.com` → `example.com`).

### Setup

```bash
export UT1_PATH=/var/lib/ut1-blacklists
./scripts/download-ut1-blacklists.sh

# In proxy environment:
CATEGORIZATION_ENABLED=true
UT1_ENABLED=true
UT1_PATH=/var/lib/ut1-blacklists
```

Legacy env names `SHALLALIST_ENABLED` / `SHALLALIST_PATH` still work but log a deprecation warning.

### Docker

Mount the extracted lists and enable UT1:

```yaml
proxy:
  environment:
    CATEGORIZATION_ENABLED: "true"
    UT1_ENABLED: "true"
    UT1_PATH: /var/lib/ut1-blacklists
  volumes:
    - ./data/ut1-blacklists:/var/lib/ut1-blacklists:ro
```

Download on the host first:

```bash
UT1_PATH=./data/ut1-blacklists ./scripts/download-ut1-blacklists.sh
```

## OTX (AlienVault Open Threat Exchange)

Optional threat enrichment via [OTX](https://otx.alienvault.com/). Set `OTX_API_KEY` and `OTX_ENABLED=true`. Results are cached in memory (default TTL 1 hour).

## ML classifier

Stub only (`ML_ENABLED`); not used in production paths yet.

## Policy integration

Categories feed URL filtering and policy rules. Events include `category`, `category_source` (`ut1`, `otx`, `ml`, `none`), and `category_confidence` in Kafka / ClickHouse.

## Configuration reference

| Variable | Default | Description |
|----------|---------|-------------|
| `CATEGORIZATION_ENABLED` | `false` | Master switch |
| `UT1_ENABLED` | `false` | Load UT1 domain lists |
| `UT1_PATH` | `/var/lib/ut1-blacklists` | Root path (`blacklists/<cat>/domains`) |
| `LOCAL_CATEGORY_DB_ENABLED` | — | Alias for `UT1_ENABLED` |
| `LOCAL_CATEGORY_DB_PATH` | — | Alias for `UT1_PATH` |
| `OTX_ENABLED` | `false` | OTX lookups |
| `OTX_API_KEY` | — | OTX API key |
| `OTX_CACHE_TTL_SECS` | `3600` | OTX cache TTL |
| `ML_ENABLED` | `false` | ML stub |

Deprecated: `SHALLALIST_ENABLED`, `SHALLALIST_PATH` (mapped to UT1).
