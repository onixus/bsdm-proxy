# Конфигурация BSDM-Proxy

Компоненты читают настройки из переменных окружения. Канонические примеры для
native install находятся в `packaging/config/*.env.example`; Compose и Helm могут
задавать собственные значения.

Статусы optional-модулей: [Project status](../project-status.md).

## Proxy: runtime

| Переменная | Default | Назначение |
|---|---:|---|
| `HTTP_PORT` | `1488` | Proxy listener |
| `METRICS_PORT` | `9090` | Health, metrics и REST control |
| `MITM_ENABLED` | `true` | HTTPS MITM; требует `ca.key` и `ca.crt` |
| `SHUTDOWN_TIMEOUT_SECONDS` | `30` | Graceful shutdown |
| `WORKER_COUNT` | `1` | SO_REUSEPORT accept loops на Unix |
| `RUST_LOG` | component-specific | tracing filter |
| `TCP_SNDBUF_BYTES` | `524288` | Client socket send buffer; `0` не меняет |
| `HTTP_PRESERVE_HEADER_CASE` | `true` | Preserve/title-case HTTP/1 headers |

## L1 cache

| Переменная | Default | Назначение |
|---|---:|---|
| `CACHE_CAPACITY` | `10000` | Общее количество L1 entries на процесс |
| `CACHE_SHARDS` | `16` | Shards; capacity делится между ними |
| `CACHE_TTL_SECONDS` | `3600` | Fallback TTL |
| `MAX_CACHE_BODY_SIZE` | `10485760` | Максимальный body в байтах |
| `CACHE_SPILL_THRESHOLD_BYTES` | `262144` | Body выше порога уходит в mmap spill |
| `CACHE_SPILL_DIR` | temp dir | Каталог spill |
| `CACHE_COMPRESSION` | `off` | `off`, `zstd`, `brotli` |
| `CACHE_COMPRESS_MIN_BYTES` | `1024` | Минимум для compression |
| `CACHE_COMPRESS_ZSTD_LEVEL` | `3` | Zstd level |
| `CACHE_HONOR_CACHE_CONTROL` | `true` | Cache-Control и validators |
| `NEGATIVE_CACHE_ENABLED` | `true` | Negative cache |
| `NEGATIVE_CACHE_TTL_SECONDS` | `120` | Negative TTL |
| `STREAMING_MISS_ENABLED` | `true` | Tee MISS к клиенту и в cache |
| `MISS_COALESCE_ENABLED` | `true` | Singleflight одинаковых MISS |

`CACHE_CAPACITY` не умножается на `CACHE_SHARDS`.

## Redis L2

| Переменная | Default |
|---|---|
| `REDIS_L2_ENABLED` | `false` |
| `REDIS_URL` | `redis://127.0.0.1:6379` |
| `REDIS_KEY_PREFIX` | `bsdm:http:` |

Redis должен иметь явные `maxmemory` и eviction policy.

## Performance и sampling

| Переменная | Default | Семантика |
|---|---:|---|
| `PERF_FAST_CACHE_HIT` | `false` | Bench fast path; может обходить policy |
| `KAFKA_SAMPLE_RATE` | `0` | `0` — все события; `N` — примерно 1 из N |
| `METRICS_SAMPLE_RATE` | `0` | `0` — все histograms; `N` — 1 из N |
| `KAFKA_QUEUE_CAPACITY` | `8192` | Bounded queue proxy → producer |
| `KAFKA_ACKS` | `all` | Producer acknowledgement |
| `KAFKA_BATCH_SIZE` | library/default | Producer batch |
| `KAFKA_QUEUE_BUFFERING_MAX_MS` | library/default | Producer buffering |

Не включайте `PERF_FAST_CACHE_HIT` при обязательных ACL/categorization checks.

## Аутентификация

| Переменная | Default |
|---|---|
| `AUTH_ENABLED` | `false` |
| `AUTH_BACKEND` | `basic` |
| `AUTH_REALM` | `BSDM-Proxy` |
| `AUTH_CACHE_TTL` | backend-specific |
| `AUTH_CONN_CACHE_TTL_SECONDS` | `300` |
| `BASIC_AUTH_USERS_FILE` | unset |

Backend-specific:

- LDAP: `LDAP_SERVERS`, `LDAP_BASE_DN`, `LDAP_BIND_DN`,
  `LDAP_BIND_PASSWORD`, `LDAP_USER_FILTER`, `LDAP_GROUP_FILTER`,
  `LDAP_TIMEOUT`;
- NTLM: `NTLM_DOMAIN`, `NTLM_WORKSTATION`, `NTLM_USERS_FILE`,
  `NTLM_AUTH_HELPER`;
- Kerberos: `KRB5_SERVICE_PRINCIPAL`, `KRB5_KEYTAB`, `KRB5_KDC_URL`,
  `KRB5_HOSTNAME`, `KRB5_MAX_TIME_SKEW_SECONDS`.

Дополнительные backend требуют соответствующих Cargo features.
Подробнее: [Authentication](../features/authentication.md).

## ACL и categorization

| Переменная | Default |
|---|---|
| `ACL_ENABLED` | `false` |
| `ACL_DEFAULT_ACTION` | `allow` |
| `ACL_RULES_PATH` | implementation/deployment-specific |
| `ACL_AUTO_RELOAD` | `false` |
| `ACL_RELOAD_INTERVAL` | `60` |
| `ACL_API_TOKEN` | unset |
| `CONTROL_API_TOKEN` | fallback `ACL_API_TOKEN` |
| `CATEGORIZATION_ENABLED` | `false` |
| `UT1_ENABLED` | `false` |
| `UT1_PATH` | unset |
| `CUSTOM_DB_PATH` | unset |
| `LOCAL_CATEGORY_DB_PATH` | unset |
| `CATEGORIZATION_CACHE_TTL` | source-specific |
| `POLICY_DECISION_CACHE_TTL_SECONDS` | `120` |
| `POLICY_DECISION_CACHE_MAX_KEYS` | `10000` |

Online/offline feeds также используют `URLHAUS_API`, `PHISHTANK_API`,
`PHISHTANK_API_KEY`, `RKN_SYNC_URL` и `RKN_SYNC_INTERVAL_SECS`.

Switches источников: `URLHAUS_ENABLED`, `PHISHTANK_ENABLED`,
`CUSTOM_DB_ENABLED`, `RKN_SYNC_ENABLED`. `SHALLALIST_*` и
`LOCAL_CATEGORY_DB_*` сохранены как compatibility aliases; для новых
deployment используйте `UT1_*` и `CUSTOM_DB_*`.

## Rate limiting

| Переменная | Default |
|---|---:|
| `RATE_LIMIT_ENABLED` | `false` |
| `RATE_LIMIT_IP_RPS` | `100` |
| `RATE_LIMIT_IP_BURST` | `200` |
| `RATE_LIMIT_USER_RPS` | `50` |
| `RATE_LIMIT_USER_BURST` | `100` |
| `RATE_LIMIT_API_KEY_RPS` | `20` |
| `RATE_LIMIT_API_KEY_BURST` | `40` |
| `RATE_LIMIT_API_KEY_HEADER` | `x-api-key` |
| `RATE_LIMIT_API_KEY_BEARER` | `true` |
| `RATE_LIMIT_API_KEY_REQUIRED` | `false` |
| `RATE_LIMIT_MAX_KEYS` | `10000` |

## Hierarchy

| Переменная | Default |
|---|---|
| `HIERARCHY_ENABLED` | `false` |
| `CACHE_PARENTS`, `CACHE_SIBLINGS` | unset |
| `CACHE_PEERS_PATH`, `HIERARCHY_PEERS_PATH` | unset |
| `CACHE_SELECTION_STRATEGY` | `round-robin` |
| `ICP_BIND` | `0.0.0.0:3130` |
| `ICP_SERVER_ENABLED` | `true`, когда hierarchy включена |
| `ICP_TIMEOUT_MS` | `100` |
| `ICP_MAX_SIBLING_QUERIES` | `10` |
| `PARENT_TIMEOUT_SECONDS` | `5` |
| `HTCP_SERVER_ENABLED` | `false` |
| `PEER_DISCOVERY_ENABLED` | `false` |

Peer mTLS: `HIERARCHY_PEER_MTLS_ENABLED`, `HIERARCHY_PEER_CA_FILE`,
`HIERARCHY_PEER_CERT_FILE`, `HIERARCHY_PEER_KEY_FILE`.

Подробнее: [Hierarchical caching](../architecture/hierarchical-caching.md).

## Kafka и cache-indexer

| Переменная | Default |
|---|---|
| `KAFKA_BROKERS` | unset в proxy; `kafka:9092` в Compose |
| `KAFKA_TOPIC` | `cache-events` |
| `KAFKA_GROUP_ID` | `cache-indexer-group` |
| `INDEX_STORE` | `clickhouse` |
| `CLICKHOUSE_URL` | `http://clickhouse:8123` в Compose |
| `CLICKHOUSE_DATABASE` | `bsdm` |
| `CLICKHOUSE_TABLE` | `http_cache` |
| `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD` | unset |
| `SEARCH_API_ENABLED` | `true` |
| `SEARCH_API_TOKEN` | unset |
| `INGEST_API_TOKEN` | fallback search token |
| `SEARCH_API_MAX_LIMIT` | `10000` |
| `SEARCH_API_DEFAULT_DAYS` | `30` |
| `SQLITE_PATH` | deployment-specific |

Срок хранения задаётся TTL ClickHouse. См.
[ClickHouse](../analytics/clickhouse-retrosearch.md).

Дополнительный HTTP event sink proxy включается через `EVENT_SINK_URL`;
Bearer token задаётся `EVENT_SINK_TOKEN`.

## Session correlation и upstream TLS

| Переменная | Default |
|---|---:|
| `SESSION_IDLE_SECONDS` | `1800` |
| `SESSION_REDIRECT_TTL_SECONDS` | `60` |
| `SESSION_MAX_KEYS` | `50000` |
| `SESSION_MAX_REDIRECTS` | `20000` |
| `UPSTREAM_HTTP2_ENABLED` | `false` |
| `UPSTREAM_CA_CERT` | unset |

## Threat scores и ML

Proxy poll:

| Переменная | Default |
|---|---|
| `THREAT_SCORE_ENABLED` | `false` |
| `THREAT_SCORE_POLL_URL` | `http://127.0.0.1:8091/api/threat-scores` |
| `THREAT_SCORE_POLL_INTERVAL_SECS` | `60` |
| `THREAT_SCORE_CACHE_TTL_SECS` | `300` |
| `THREAT_SCORE_WARN_THRESHOLD` | `0.7` |
| `THREAT_SCORE_BLOCK_THRESHOLD` | `0` — blocking выключен |

ML worker:

- `ML_MODEL`;
- `ML_ENTITY_TYPES`;
- `ML_POLL_INTERVAL_SECS`, `ML_LOOKBACK_SECS`;
- `ML_MIN_REQUESTS`, `ML_SCORE_THRESHOLD`;
- `ML_BASELINE_LOOKBACK_SECS`, `ML_BASELINE_MIN_SAMPLES`;
- `ML_WRITEBACK_ENABLED`, `ML_WRITEBACK_MIN_SCORE`,
  `ML_WRITEBACK_TTL_SECS`;
- `ML_WEBHOOK_URL`.

Один процесс выбирает одну модель. Подробнее:
[ML security](../analytics/ml-security.md).

## Alert worker

Минимально требуется `ALERT_WEBHOOK_URL`. Основные параметры:

- `ALERT_RULES`;
- `ALERT_POLL_INTERVAL_SECS`, `ALERT_LOOKBACK_SECS`;
- `ALERT_DEDUPE_TTL_SECS`;
- `ALERT_WEBHOOK_HEADERS`, `ALERT_WEBHOOK_TIMEOUT_SECS`;
- thresholds с префиксами `ALERT_BLOCKED_BURST_*`,
  `ALERT_DOMAIN_BURST_*`, `ALERT_HIGH_ENTROPY_*`,
  `ALERT_OFF_HOURS_*` и `ALERT_BEACON_*`.

Полный пример: `packaging/config/alert-worker.env.example`. Подробнее:
[Threat alerting](../analytics/alerting.md).

## Semantic cache

| Переменная | Default |
|---|---|
| `SEMANTIC_CACHE_ENABLED` | `false` |
| `SEMANTIC_CACHE_PATH_PREFIXES` | LLM completion paths |
| `SEMANTIC_CACHE_TTL_SECONDS` | `3600` |
| `SEMANTIC_CACHE_SIMILARITY` | `1.0` — near-hit выключен |
| `SEMANTIC_CACHE_EMBED_DIMS` | `64` |
| `SEMANTIC_CACHE_MAX_INDEX` | `10000` |
| `SEMANTIC_VECTOR_BACKEND` | `local` |
| `SEMANTIC_VECTOR_URL` | unset |
| `SEMANTIC_VECTOR_COLLECTION` | `bsdm_semantic` |
| `SEMANTIC_VECTOR_API_KEY` | unset |
| `SEMANTIC_EMBED_PROVIDER` | `local` |
| `SEMANTIC_EMBED_URL` | unset |

Параметров `AI_CACHE_ENABLED`, `QDRANT_URL` и `OLLAMA_URL` proxy не читает.
Используйте имена выше.

## DNS sinkhole

| Переменная | Default |
|---|---|
| `DNS_SINKHOLE_ENABLED` | `true` |
| `DNS_SINKHOLE_BIND` | `0.0.0.0:53` |
| `DNS_SINKHOLE_UPSTREAM` | `1.1.1.1:53` |
| `DNS_SINKHOLE_ZONE_PATH` | required |
| `DNS_SINKHOLE_ACTION` | `sinkhole` |
| `DNS_SINKHOLE_DOH_ENABLED` | `true` |
| `DNS_SINKHOLE_DOH_BIND` | `0.0.0.0:8443` |
| `DNS_SINKHOLE_DOH_PATH` | `/dns-query` |
| `DNS_SINKHOLE_DOT_ENABLED` | `true` |
| `DNS_SINKHOLE_DOT_BIND` | `0.0.0.0:853` |
| `DNS_SINKHOLE_TLS_CERT`, `DNS_SINKHOLE_TLS_KEY` | required for DoH/DoT |

Подробнее: [DNS sinkhole](../features/dns-sinkhole.md).

## Experimental modules

### WASM

`WASM_ENABLED`, `WASM_MODULE_PATH`, `WASM_FUEL`, `WASM_FAIL_OPEN`.
Требует Cargo feature `wasm`.

### ICAP

`ICAP_ENABLED`, `ICAP_URL`, `ICAP_TIMEOUT_MS`, `ICAP_FAIL_OPEN`,
`ICAP_REQMOD`, `ICAP_RESPMOD`, `ICAP_MAX_BODY_BYTES`.

### eBPF/XDP

`EBPF_XDP_ENABLED`, `EBPF_XDP_IFACE`, `EBPF_XDP_MODE`,
`EBPF_XDP_MAX_ENTRIES`.

### Reverse proxy/OIDC

Runtime включается наличием `REVERSE_PROXY_UPSTREAM`. Дополнительно:
`OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_ISSUER_URL`,
`OIDC_REDIRECT_URI`, `REVERSE_PROXY_ADMIN_GROUP`.

Reverse/OIDC считается experimental и не является production security boundary.

### DLP/CASB

Отдельного `DLP_ENABLED` сейчас нет. Patterns и LLM domains управляются через
experimental control API. Пилот без DLP требует явного выключателя или пустого
набора паттернов.

### gRPC control plane

Требует Cargo feature `grpc`. `CONTROL_GRPC_ENABLED=false` по умолчанию;
listener задаётся `CONTROL_GRPC_BIND` (default `127.0.0.1:50051`).

### Cluster session and threat-sync scaffold

| Переменная | Default |
|---|---|
| `NODE_ID` | `node-1` |
| `REDIS_SESSION_TTL` | `86400` |
| `REDIS_SESSION_PREFIX` | `bsdm:session:` |
| `THREAT_SYNC_CHANNEL` | `bsdm:threat:sync` |

Параметры читаются кодом, но текущий binary создаёт session/threat stores без
Redis connection. Они не включают распределённый сценарий сами по себе.
