# Search API (ClickHouse)

REST endpoint for SOC retro-search over `bsdm.http_cache`. Implemented in **cache-indexer** admin HTTP server (same port as `/metrics`).

Part of OpenSearch → ClickHouse migration ([#125](https://github.com/onixus/bsdm-proxy/issues/125), [#130](https://github.com/onixus/bsdm-proxy/issues/130)).

## Enable

Enabled by default on cache-indexer admin port.

| Variable | Default | Description |
|----------|---------|-------------|
| `SEARCH_API_ENABLED` | `true` | `true` / `false` |
| `SEARCH_API_TOKEN` | — | Bearer token; if set, `Authorization: Bearer <token>` required |
| `SEARCH_API_MAX_LIMIT` | `10000` | Max rows per request |
| `SEARCH_API_DEFAULT_DAYS` | `30` | Default lookback when `from` omitted |
| `METRICS_PORT` | `8080` | Admin port (`/metrics`, `/health`, `/api/search`) |

## Endpoint

```
GET /api/search
```

### Query parameters

| Param | Required | Description |
|-------|----------|-------------|
| `domain` | no | Filter by domain (alphanumeric, `.@_-%` only) |
| `username` | no | Filter by username |
| `session_id` | no | Soft browsing session id (orders timeline ascending) |
| `from` | no | Unix timestamp (seconds); default: now − `days` |
| `to` | no | Unix timestamp (seconds); default: now |
| `days` | no | Lookback days if `from` omitted (default 30) |
| `limit` | no | Max rows (default 1000, capped by `SEARCH_API_MAX_LIMIT`) |
| `format` | no | `json` (default) or `csv` |

### Examples

```bash
# Full stack (proxy, Kafka, ClickHouse, cache-indexer)
docker compose up -d --build
curl -x http://127.0.0.1:1488 http://httpbin.org/get
sleep 5

# JSON (last 30 days, all domains)
curl -s 'http://127.0.0.1:8080/api/search?limit=10' | jq .

# Filter by domain
curl -s 'http://127.0.0.1:8080/api/search?domain=httpbin.org&days=7'

# Filter by session (redirect chain / browsing timeline)
curl -s 'http://127.0.0.1:8080/api/search?session_id=<id>&days=1'

# CSV export for SOC
curl -s 'http://127.0.0.1:8080/api/search?domain=example.com&format=csv' -o traffic.csv

# With bearer token
export SEARCH_API_TOKEN=secret
curl -H "Authorization: Bearer secret" 'http://127.0.0.1:8080/api/search?limit=5'
```

### Response

JSON array of objects with fields: `ts`, `username`, `client_ip`, `url`, `method`, `status`, `cache_status`, `domain`, `event_id`, `session_id`, `parent_event_id`, `redirect_url`.

Errors: `401` (unauthorized), `404` (search disabled), `500` (query failure).

## Security

- Filters are sanitized server-side; invalid characters are rejected (empty filter).
- Queries use ClickHouse parameterized SQL (`{param:Type}`), not string concatenation.
- Prefer setting `SEARCH_API_TOKEN` in production; do not expose port 8080 publicly without auth.

## Grafana alternative

For interactive dashboards use Grafana + ClickHouse datasource (`docker compose up`). Search API is for scripted export and integrations.

See [clickhouse-analytics.md](clickhouse-analytics.md).
