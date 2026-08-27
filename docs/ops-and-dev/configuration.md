# Конфигурация BSDM-Proxy

Компоненты читают настройки из переменных окружения. Канонические примеры для
native install находятся в `packaging/config/*.env.example`; Compose и Helm могут
задавать собственные значения.

Статусы optional-модулей: [Project status](../project-status.md).

## Proxy: runtime

| Переменная | Default | Назначение |
|---|---:|---|
| `HTTP_PORT` | `3128` | Proxy listener |
| `METRICS_PORT` | `9090` | Health, metrics и REST control |
| `DEPLOYMENT_PROFILE` | `production` | Профиль запуска (`production`, `development`, `test`); production запрещает `full-mitm` |
| `POLICY_MODE` | `selective-mitm` | Режим политики (`selective-mitm`, `sni`, `full-mitm`) |
| `ALLOW_FULL_MITM` | `false` | Дополнительное подтверждение для `full-mitm`; действует только в development/test |
| `MITM_CATEGORIES` | `malware,phishing,illegal-content` | Категории доменов для терминирования TLS в selective-mitm |
| `PINNING_EXCEPTIONS_PATH` | unset | Управляемый JSON-реестр Certificate Pinning exceptions |
| `PINNING_AUDIT_LOG_PATH` | `<registry>.audit.jsonl` | Append-only audit trail изменений реестра |
| `PINNING_EXCEPTIONS` | `.slack.com,.teams.microsoft.com,.zoom.us` | Legacy startup fallback; без reload и аудита |
| `MITM_ENABLED` | `true` | HTTPS MITM; требует `ca.key` и `ca.crt` при POLICY_MODE != sni |
| `MITM_CA_DIR` | `/etc/bsdm-proxy/certs` | Каталог с `ca.key`/`ca.crt`; при отсутствии CA читаются устаревшие `/certs` и `./certs` (с warning) |
| `TLS_OCSP_STAPLING` | `true` | OCSP staple (RFC 6960 DER, CA-signed **good**) on MITM/control TLS leaves |
| `TLS_OCSP_STAPLE_REFRESH_SECS` | `900` | TTL refresh cached `ServerConfig` + staple (60–86400) |
| `MITM_CERT_CACHE_MAX_ENTRIES` | `10000` | Лимит записей в кэшах MITM-сертификатов и `ServerConfig` (ключ — SNI); значения ниже `128` поднимаются до `128`. При заполнении вытесняются самые старые записи |
| `AGENT_DEVICES_PATH` | unset | Local durable agent device JSON |
| `AGENT_CRL_PATH` | unset | Local durable agent CRL JSON |
| `AGENT_DEVICES_REDIS_URL` | unset | Multi-node Redis URL for devices+CRL (preferred) |
| `AGENT_DEVICES_REDIS` | `false` | When `true`, use `REDIS_URL` for multi-node agent store |
| `AGENT_REDIS_PREFIX` | `bsdm:agent:` | Redis key prefix (HASH `…devices`, `…crl`, indexes) |
| `DLP_ENABLED` | `false` | Experimental native signature DLP; `false` = no built-in patterns / no body scan |
| `SHUTDOWN_TIMEOUT_SECONDS` | `30` | Graceful shutdown |
| `WORKER_COUNT` | `1` | SO_REUSEPORT accept loops на Unix |
| `RUST_LOG` | component-specific | tracing filter |
| `TCP_SNDBUF_BYTES` | `524288` | Client socket send buffer; `0` не меняет |
| `HTTP_PRESERVE_HEADER_CASE` | `true` | Preserve/title-case HTTP/1 headers |

`full-mitm` предназначен только для локальной диагностики. Он отклоняется при
`DEPLOYMENT_PROFILE=production`, даже если задан `ALLOW_FULL_MITM=true`. Для
явного debug-запуска нужны обе настройки:

```bash
DEPLOYMENT_PROFILE=development POLICY_MODE=full-mitm ALLOW_FULL_MITM=true \
  cargo run -p bsdm-proxy --bin proxy
```

В production используйте `selective-mitm` и управляйте расшифровкой через
`MITM_CATEGORIES`, либо `sni` для полного отключения TLS-терминирования.

## MITM circuit breaker

Автоматический перевод домена на blind `CONNECT` при росте доли ошибок TLS
(`proxy/src/mitm_breaker.rs`, [ADR 0007](../adr/0007-mitm-circuit-breaker.md)).

| Переменная | Default | Назначение |
|---|---:|---|
| `MITM_CIRCUIT_BREAKER_ENABLED` | `true` | Выключается только значениями `false` / `0` |
| `MITM_CIRCUIT_BREAKER_FAILURE_RATE` | `0.05` | Доля ошибок для срабатывания; принимается только `0 < rate <= 1`, иначе default |
| `MITM_CIRCUIT_BREAKER_MIN_SAMPLES` | `5` | Минимум попыток в окне до оценки доли ошибок (≥ 1) |
| `MITM_CIRCUIT_BREAKER_WINDOW_SECS` | `60` | Длина скользящего окна, секунды (≥ 1) |
| `MITM_CIRCUIT_BREAKER_COOLDOWN_SECS` | `0` | `0` — домен остаётся в bypass до ручного сброса; иначе авто-восстановление через N секунд |
| `MITM_CIRCUIT_BREAKER_MAX_DOMAINS` | `10000` | Максимум отслеживаемых доменов в памяти; значения ниже `128` поднимаются до `128` |

Некорректное значение любой переменной игнорируется и заменяется значением по
умолчанию.

Счётчики хранятся по домену, поэтому их число ограничено
`MITM_CIRCUIT_BREAKER_MAX_DOMAINS`. При заполнении вытеснение идёт тремя
ярусами: (1) закрытые счётчики без попыток внутри окна, (2) закрытые счётчики с
наименьшим числом попыток — так поток `CONNECT` по случайным хостам вытесняет
свои же одноразовые записи раньше домена, который breaker реально измеряет,
(3) если вся карта состоит из tripped-доменов — наименее недавно использованные
из них. Ярус 3 нужен, чтобы карта оставалась ограниченной: клиент может ввести
домен в tripped, оборвав собственный TLS-хендшейк. Вытесненный trip не теряется
из аудита и переустанавливается при следующих ошибках.

Текущее состояние видно в `GET /api/mitm/circuit-breaker`: `tracked_domains`,
`max_domains`, `evicted_domains_total`, `evicted_tripped_domains_total`
(сработал ярус 3) и `dropped_attempts_total` (попытки, которые не удалось
записать вообще).

Ключами счётчиков служат точные имена хостов: ведущие и завершающие точки
отбрасываются. Единственный источник ключей — имя из `CONNECT`, то есть данные
клиента, поэтому wildcard-ключей вида `.example.com` не существует и клиент не
может ввести в bypass весь родительский домен. Аудит срабатываний и сбросов пишется в `PINNING_AUDIT_LOG_PATH`.
Статус и сброс: `GET /api/mitm/circuit-breaker`,
`POST /api/mitm/circuit-breaker/reset` (Bearer). Процедура оператора —
[certificate-pinning.md](../features/certificate-pinning.md#mitm-circuit-breaker-detection-and-operator-reset).

## Threat intel shadow matching (proxy)

Наблюдение за совпадениями трафика с IOC без блокировки (`proxy/src/ti_shadow.rs`,
[ADR 0008](../adr/0008-threat-intel-shadow-mode.md)). Proxy читает **только**
shadow-выгрузку коллектора и никогда не меняет allow/deny решение.

| Переменная | Default | Назначение |
|---|---:|---|
| `TI_SHADOW_MATCH_ENABLED` | `true` | Выключается значениями `0`/`false`/`no`/`off` |
| `TI_SHADOW_FEED_PATH` | `/var/lib/bsdm-proxy/threat-intel/threat_domains.json.shadow` | Файл shadow-выгрузки `threat-intel` |
| `TI_SHADOW_RELOAD_SECS` | `300` | Интервал перечитывания файла; значения меньше `10` поднимаются до `10` |

Совпадение помечает событие полем `threat_shadow_match` (имя фида) — колонка
`threat_shadow_match` в ClickHouse — и увеличивает
`bsdm_proxy_ti_shadow_matches_total{feed}`. Отсутствующий файл не является
ошибкой: коллектор мог ещё не сформировать выгрузку.

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

Безопасная процедура управления pinning-исключениями описана в
[Certificate Pinning Exceptions](../features/certificate-pinning.md).

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

> Колонка Default — это встроенный fallback, когда переменная не задана вообще.
> Поставляемые эталонные конфиги (`bsdm-proxy.env`, корневой `docker-compose.yml`,
> `deploy/compose/docker-compose.pilot.yml`) задают `AUTH_ENABLED=true`.
> При `AUTH_BACKEND=basic` обязательно задайте `BASIC_AUTH_USERS_FILE`: без него
> прокси принимает ЛЮБЫЕ учётные данные. Лабораторные стеки
> (`docker-compose.lite.yml`, `.test.yml`, `.ha.yml`, `.hierarchy.yml`,
> `.redis-l2.yml`) намеренно оставлены с `AUTH_ENABLED=false` и не предназначены
> для прода.

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

> Как и выше, колонка Default — встроенный fallback. Эталонные конфиги
> (`bsdm-proxy.env`, корневой `docker-compose.yml`, pilot-overlay) поставляются
> с `ACL_ENABLED=true`, но с `ACL_DEFAULT_ACTION=allow`. Это не упущение:
> поставляемый набор `config/bsdm-etc/acl-rules.json` — blocklist (85 правил,
> все `deny`, ни одного `allow`), поэтому `deny` по умолчанию заблокировал бы
> весь трафик, а не ужесточил политику. Учтите также, что переменная работает
> лишь как fallback: `default_action` берётся из JSON-файла правил, когда он
> её задаёт, а все поставляемые наборы задают `allow`. Перевод ACL в
> fail-closed — отдельная работа: сначала baseline из `allow`-правил под
> реальный трафик, затем `"default_action": "deny"` в самом файле правил.

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
| `RPZ_CONFIRM_GROWTH_RULES` | `5000` | Абсолютный порог правил, выше которого `POST /api/dns/rpz/lists` требует `?confirm=true` |
| `RPZ_CONFIRM_GROWTH_PCT` | `50` | Относительный порог: прирост зоны больше этого процента тоже требует `?confirm=true` |

`dns-sinkhole` **отказывается** загружать observe-only артефакт коллектора: и по
имени (путь оканчивается на `.shadow`), и по машинному маркеру внутри зоны
(`_bsdm-enforcement-mode IN TXT "shadow"`). На старте это ошибка без отката на
fallback-зону — иначе неверный `DNS_SINKHOLE_ZONE_PATH` тихо маскировался бы.
Баннер-комментарий в зоне оставлен для человека: любой парсер его выбрасывает.

Мутации `/api/dns/*` пишут JSONL-аудит в `<DNS_RPZ_STATE_DIR>/rpz-audit.jsonl`
(`0600`). Добавление списка поддерживает `?dryRun=true` — предпросмотр числа
правил, размера зоны до/после и первых 20 строк без записи и без компиляции
зоны.

Подробнее: [DNS sinkhole](../features/dns-sinkhole.md).

## Threat intel collector

Отдельный опциональный worker `threat-intel` (профиль Compose `threat-intel`).

> **Shadow Mode по умолчанию.** Модуль ведёт мониторинг угроз; блокировка по фидам
> требует явного `TI_ENFORCEMENT_MODE=enforce` и критериев перехода из
> [ADR 0008](../adr/0008-threat-intel-shadow-mode.md).

| Переменная | Default |
|---|---|
| `TI_ENFORCEMENT_MODE` | `shadow` |
| `TI_SOURCES` | `openphish,phishstats,phishing_database,urlhaus` |
| `TI_<SOURCE>_URL` | endpoint вендора |
| `TI_POLL_INTERVAL_SECS` | `900` |
| `TI_HTTP_TIMEOUT_SECS` | `30` |
| `TI_MAX_ATTEMPTS` | `3` |
| `TI_RETRY_BACKOFF_SECS` | `5` |
| `TI_MAX_BODY_MB` | `64` |
| `TI_MAX_INDICATORS_PER_FETCH` | `500000` |
| `TI_OUTPUT_DIR` | `./data/threat-intel` |
| `TI_SQLITE_PATH` | `<TI_OUTPUT_DIR>/ioc.db` |
| `TI_RPZ_ENABLED` | `true` (в shadow пишутся только `threats.rpz.shadow` / `threat_domains.json.shadow`) |
| `TI_MIN_CONFIDENCE_SCORE` | `75` |
| `TI_RUN_ONCE` | `false` |
| `METRICS_PORT` | `8093` |

В режиме `shadow` enforcement-артефакты под «боевыми» именами не создаются:
коллектор пишет `threats.rpz.shadow` и `threat_domains.json.shadow`
(`threat-intel/src/config.rs`, `threat-intel/src/collector.rs`), а сама зона
несёт баннер `SHADOW MODE … Do NOT load this zone into dns-sinkhole`
(`threat-intel/src/rpz.rs`). Метрика SOAR-действий по режимам —
`threat_intel_soar_blocks_total{mode}`; в shadow `POST /api/v1/soar/block`
отвечает `202` с `"mode":"shadow"` и `"enforced":false`.

Полный пример: `packaging/config/threat-intel.env.example`. Подробнее:
[Threat intel collector](../features/threat-intel-collector.md) ·
[ADR 0008](../adr/0008-threat-intel-shadow-mode.md).

### Admin/SOAR API коллектора: доступ и аудит

Листенер `METRICS_PORT` обслуживает `/health`, `/metrics`, SOAR и
`/api/v1/ml/*`. Мутирующие вызовы `POST /api/v1/soar/*` (block, unblock)
закрыты Bearer-токеном и пишутся в аудит (`threat-intel/src/api_auth.rs`,
`threat-intel/src/main.rs`).

| Переменная | Default | Назначение |
|---|---:|---|
| `TI_API_TOKEN` | unset | Bearer для `POST /api/v1/soar/*`; сравнение constant-time. Без него мутации закрыты |
| `TI_API_ALLOW_INSECURE` | `false` | Явная лабораторная лазейка: открыть мутации без токена. Не задавать в пилоте |
| `TI_ADMIN_BIND` | `127.0.0.1` | Хост admin/SOAR/metrics-листенера |
| `TI_SOAR_AUDIT_PATH` | `<TI_OUTPUT_DIR>/soar-audit.jsonl` | JSONL-аудит SOAR-действий, файл создаётся с правами `0600` |

Постура выбирается так: fail-closed всегда, кроме единственного случая
`TI_API_ALLOW_INSECURE=true`. `DEPLOYMENT_PROFILE` на неё **не влияет**: эту
переменную переключают другие сервисы по своим причинам, и раньше любое
не-production значение тихо открывало мутации SOAR без токена.

- **Отказ**: мутация без валидного Bearer получает `401 Unauthorized` с
  заголовком `WWW-Authenticate: Bearer`, **до** обращения к хранилищу —
  отклонённый вызов не создаёт и не удаляет индикаторы. Токен с другой схемой
  (`Basic`) или пустой Bearer считаются отсутствующими.
- **Открытые эндпоинты**: `GET /health`, `GET /metrics`,
  `GET /api/v1/soar/investigate`, `GET /api/v1/ml/*` — авторизация не требуется
  (проверка применяется только к `POST /api/v1/soar/*`).
- **Старт без токена не падает**: в отличие от proxy control plane, коллектор
  продолжает собирать фиды, а мутации остаются закрытыми; выбранная постура
  пишется в лог при старте (`info` при заданном токене, `warn` при его
  отсутствии и при открытом lab-режиме).
- **Аудит**: на каждый block/unblock — и принятый, и отклонённый — добавляется
  строка JSONL с полями `timestamp_unix`, `actor` (поле `operator` из тела),
  `peer` (адрес клиента), `action`, `indicator`, `change_reason` (поле `reason`),
  `mode` (`shadow`/`enforce`), `outcome` (`accepted`/`denied`), `source_path`.
  Управляющие символы вырезаются, отсутствующие значения пишутся как `unknown`.
- **Сеть**: порт `8093` больше не публикуется на хост — в Compose сервис
  объявлен через `expose`, Prometheus скрейпит `/metrics` внутри сети
  `bsdm-net`, поэтому в Compose/Helm задан `TI_ADMIN_BIND=0.0.0.0`. При
  локальном запуске бинарника листенер остаётся на `127.0.0.1`. Публиковать порт
  наружу — только вместе с заданным `TI_API_TOKEN`.

## AmneziaWG (BSDM Connect)

> **Только лаборатория (Beta).** AmneziaWG и `bsdm-connect` **не входят в
> production-контур пилота и не поддерживаются в продакшене** — в матрице Day-1
> они отмечены **OFF** ([pilot-deployment.md](../getting-started/pilot-deployment.md)),
> зрелость — **Beta (lab)** ([project-status.md](../project-status.md)), issue #331.

| Переменная | Default | Описание |
|---|---|---|
| `AWG_CONFIG_PATH` | `/etc/amnezia/amneziawg/awg0.conf` | Путь к конфигурационному файлу сервера AWG |
| `AWG_SERVER_ENDPOINT` | `127.0.0.1:51820` | Внешний IP:Port эндпоинта для клиентов |
| `AWG_RELOAD_CMD` | unset | Команда синхронизации интерфейса sidecar (например `awg syncconf awg0 ...`) |
| `AWG_CLIENT_DNS` | `10.8.0.1` | DNS сервер для генерируемых клиентских профилей |
| `AWG_CLIENT_MTU` | `1360` | MTU для клиентских туннелей (с учетом оверхеда обфускации) |

## Experimental modules

### WASM

`WASM_ENABLED`, `WASM_MODULE_PATH`, `WASM_FUEL`, `WASM_FAIL_OPEN`.
Требует Cargo feature `wasm`.

### ICAP

`ICAP_ENABLED`, `ICAP_URL`, `ICAP_TIMEOUT_MS`, `ICAP_FAIL_OPEN`,
`ICAP_REQMOD`, `ICAP_RESPMOD`, `ICAP_MAX_BODY_BYTES`.

Эталонный `bsdm-proxy.env` поставляется с `ICAP_FAIL_OPEN=false` (fail-closed):
при недоступности или таймауте ICAP-сервера запрос блокируется, а не проходит
непроверенным. Следствие для эксплуатации: авария ICAP становится аварией
трафика — включайте `ICAP_ENABLED=true` только с мониторингом и резервированием
ICAP-эндпоинта. `ICAP_FAIL_OPEN=true` возвращает прежнее поведение: трафик идёт,
но во время аварии молча НЕ сканируется (размен доступности против безопасности).

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
