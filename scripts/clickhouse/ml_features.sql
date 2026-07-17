-- M5 feature store tables (ADR 0003)
-- Applied via docker-entrypoint-initdb.d or:
--   clickhouse-client --multiquery < scripts/clickhouse/ml_features.sql

CREATE DATABASE IF NOT EXISTS bsdm;

-- Rolling entity windows extracted by ml-worker from http_cache.
CREATE TABLE IF NOT EXISTS bsdm.entity_features
(
    window_start DateTime64(3, 'UTC'),
    window_secs UInt32,
    entity_type LowCardinality(String),
    entity_id String,
    request_count UInt64,
    unique_domains UInt64,
    unique_urls UInt64,
    deny_count UInt64,
    threat_hit_count UInt64,
    avg_response_size Float64,
    avg_duration_ms Float64,
    gap_cv Float64,
    max_domain_len UInt64,
    extracted_at DateTime64(3, 'UTC')
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(window_start)
ORDER BY (entity_type, entity_id, window_start)
TTL window_start + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Model / stub scores keyed to an entity window.
CREATE TABLE IF NOT EXISTS bsdm.ml_scores
(
    scored_at DateTime64(3, 'UTC'),
    entity_type LowCardinality(String),
    entity_id String,
    window_start DateTime64(3, 'UTC'),
    model LowCardinality(String),
    score Float64,
    severity LowCardinality(String),
    features_json String DEFAULT '{}'
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(scored_at)
ORDER BY (entity_type, entity_id, scored_at)
TTL scored_at + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- M5.3 per-domain lexical phishing features (ml-worker phishing_lexical_v0).
CREATE TABLE IF NOT EXISTS bsdm.domain_phishing_features
(
    window_start DateTime64(3, 'UTC'),
    window_secs UInt32,
    domain String,
    request_count UInt64,
    unique_urls UInt64,
    weak_label_phishing UInt64,
    weak_label_phishtank UInt64,
    weak_label_ut1 UInt64,
    deny_count UInt64,
    suspicious_path_hits UInt64,
    avg_path_extra_len Float64,
    domain_len UInt64,
    hyphen_count UInt64,
    digit_count UInt64,
    subdomain_depth UInt64,
    entropy Float64,
    suspicious_keyword UInt8,
    is_ip_hostname UInt8,
    extracted_at DateTime64(3, 'UTC')
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(window_start)
ORDER BY (domain, window_start)
TTL window_start + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Example: top phishing-scored domains (last 24h)
-- SELECT entity_id, max(score) AS max_score, argMax(severity, score) AS severity
-- FROM bsdm.ml_scores
-- WHERE scored_at >= now() - INTERVAL 1 DAY
--   AND entity_type = 'client_ip'
-- GROUP BY entity_id
-- ORDER BY max_score DESC
-- LIMIT 50;
