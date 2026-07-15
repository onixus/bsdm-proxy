# Search API

REST retro-search on **cache-indexer** admin port (same as `/metrics`). Backends: ClickHouse (full stack), SQLite / memory (Lite).

## Enable

| Variable | Default | Description |
|----------|---------|-------------|
| `INDEX_STORE` | `clickhouse` | `clickhouse` \| `sqlite` \| `memory` |
| `SEARCH_API_ENABLED` | `true` | `true` / `false` |
| `SEARCH_API_TOKEN` | — | Bearer for `GET /api/search` |
| `INGEST_API_TOKEN` | = search token | Bearer for `POST /api/events` |
| `SEARCH_API_MAX_LIMIT` | `10000` | Max rows per request |
| `SEARCH_API_DEFAULT_DAYS` | `30` | Default lookback when `from` omitted |
| `METRICS_PORT` | `8080` | Admin port |
| `SQLITE_PATH` | `/var/lib/cache-indexer/events.db` | When `INDEX_STORE=sqlite` |
| `KAFKA_BROKERS` | unset = off | Optional Kafka consumer → store |

## Endpoints

```
GET  /api/search
POST /api/events
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

JSON array of objects with fields: `ts` (unix seconds), `username`, `client_ip`, `url`, `method`, `status`, `cache_status`, `domain`, `event_id`, `session_id`, `parent_event_id`, `redirect_url`.

Errors: `401` (unauthorized), `404` (search disabled), `500` (query failure).

## Ingest (`POST /api/events`)

Body: one `CacheEvent` JSON, a JSON array, `{"events":[...]}`, or NDJSON. Response `202 {"accepted":N}`.

Lite proxy sets `EVENT_SINK_URL=http://cache-indexer:8080/api/events` (no Kafka). See [lite.md](lite.md).

## Security

- Filters are sanitized server-side; invalid characters are rejected (empty filter).
- ClickHouse queries use parameterized SQL (`{param:Type}`); SQLite uses bound params.
- Prefer setting `SEARCH_API_TOKEN` / `INGEST_API_TOKEN` in production; do not expose port 8080 publicly without auth.

## Grafana alternative

For interactive dashboards use Grafana + ClickHouse datasource (`docker compose up`). Lite uses SQLite Search API only.

See [clickhouse-analytics.md](clickhouse-analytics.md) · [lite.md](lite.md).
