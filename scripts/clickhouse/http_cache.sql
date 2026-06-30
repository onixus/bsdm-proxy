-- BSDM http-cache events (CacheEvent from bsdm-events crate)
-- Mounted into ClickHouse: /docker-entrypoint-initdb.d/

CREATE DATABASE IF NOT EXISTS bsdm;

CREATE TABLE IF NOT EXISTS bsdm.http_cache
(
    event_id String,
    ts DateTime64(3, 'UTC'),
    url String,
    method LowCardinality(String),
    status UInt16,
    cache_key String,
    cache_status LowCardinality(String),
    user_id Nullable(String),
    username LowCardinality(Nullable(String)),
    client_ip IPv4,
    domain LowCardinality(String),
    response_size UInt64,
    request_duration_ms UInt32,
    content_type LowCardinality(Nullable(String)),
    user_agent String,
    categories Array(LowCardinality(String)),
    threat_sources Array(LowCardinality(String)),
    acl_action LowCardinality(Nullable(String)),
    headers String DEFAULT '{}'
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (domain, username, ts, event_id)
TTL ts + INTERVAL 42 DAY
SETTINGS index_granularity = 8192;

-- M3: who accessed domain X (30 days)
-- SELECT ts, username, client_ip, url, method, status, cache_status
-- FROM bsdm.http_cache
-- WHERE domain = {domain:String} AND ts >= now() - INTERVAL 30 DAY
-- ORDER BY ts DESC LIMIT 1000;

-- M4: blocked events with threat sources
-- SELECT ts, username, domain, url, categories, threat_sources, acl_action
-- FROM bsdm.http_cache
-- WHERE cache_status = 'DENY' OR acl_action = 'deny'
--   AND ts >= now() - INTERVAL 7 DAY;
