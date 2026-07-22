# Categorization

BSDM proxy categorizes HTTP(S) traffic using a layered engine: local domain lists, optional OTX threat intel, and optional ML (stub).

## Architecture

```
Request URL → extract hostname
    → In-memory category cache (sync)
    → Local category DB (UT1 Blacklists, optional)     ← hot path (#104)
    → URLhaus / PhishTank (optional, background task)  ← async enrich
    → OTX threat intel (optional, future)
    → ML classifier (stub, optional)
    → Category + confidence + source
```

### Hot path vs async enrichment (#104)

На пути ответа клиенту вызывается только **`categorize_local()`**:

- sync read in-memory cache (`std::sync::RwLock`)
- lookup в UT1 / custom domain DB

**URLhaus** и **PhishTank** не блокируют запрос: при отсутствии локальной категории запускается фоновый `tokio` task (`schedule_online_enrichment`), результат попадает в cache для следующих запросов.

Первый запрос к неизвестному URL может пройти ACL до завершения online enrich (и до истечения policy cache TTL). Для threat-intel это ожидаемый компромисс async-модели.

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

Categories feed URL filtering and policy rules. Events include `categories`, `threat_sources` (`ut1`, `urlhaus`, `phishtank`, …), and `acl_action` in Kafka / ClickHouse.

## Prometheus metrics (M4)

Exported on the proxy metrics port (`/metrics`):

| Metric | Labels | Description |
|--------|--------|-------------|
| `bsdm_proxy_categorization_lookups_total` | `source`, `result` | Hot-path lookups (`source`: ut1/custom/cache/unknown; `result`: hit/miss) |
| `bsdm_proxy_categorization_cache_hits_total` | — | In-memory category cache hits |
| `bsdm_proxy_categorization_cache_misses_total` | — | Cache miss → local DB scan |
| `bsdm_proxy_categorization_duration_seconds` | — | Histogram of `categorize_local` latency |
| `bsdm_proxy_categorization_category_total` | `category` | Categories returned |
| `bsdm_proxy_categorization_blocked_total` | `category`, `action` | ACL deny/redirect with those categories |
| `bsdm_proxy_categorization_online_enrich_scheduled_total` | — | Background URLhaus/PhishTank tasks |

Grafana: panels on **BSDM Proxy Dashboard** + SQL threat panels on **BSDM HTTP Traffic (ClickHouse)**.

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
| `URLHAUS_ENABLED` | `false` | Async URLhaus enrich |
| `URLHAUS_API` | abuse.ch URL check | URLhaus endpoint |
| `PHISHTANK_ENABLED` | `false` | Async PhishTank enrich |
| `PHISHTANK_API` | `https://checkurl.phishtank.com/checkurl/` | PhishTank endpoint |
| `PHISHTANK_API_KEY` | — | PhishTank `app_key` (recommended) |
| `CUSTOM_DB_ENABLED` | `false` | JSON custom category DB |
| `CUSTOM_DB_PATH` | — | Path to custom DB JSON |
| `ML_ENABLED` | `false` | ML stub |

After async enrich, category cache stores the feed id (`phishtank` / `urlhaus` / `multiple`) so subsequent requests emit `threat_sources` with that value (not only `cache`).

Deprecated: `SHALLALIST_ENABLED`, `SHALLALIST_PATH` (mapped to UT1).
