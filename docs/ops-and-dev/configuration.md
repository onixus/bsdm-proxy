# Конфигурация и параметры BSDM-Proxy

В этом документе описаны все доступные параметры настройки прокси-сервера. Конфигурация осуществляется через переменные окружения (файл `.env`) или графический интерфейс (Admin Console). 

---

## 1. Основные параметры (General)

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `HTTP_PORT` | `1488` | Порт для HTTP/HTTPS прокси-трафика. |
| `METRICS_PORT` | `9090` | Порт для метрик Prometheus и API управления. |
| `RUST_LOG` | `info,bsdm_proxy=info` | Уровень логирования (trace, debug, info, warn, error). |
| `SHUTDOWN_TIMEOUT_SECONDS` | `30` | Таймаут плавного завершения работы (Graceful shutdown). |
| `MAX_CACHE_BODY_SIZE` | `10` | Максимальный размер тела ответа (в МБ), который будет сохранен в кэше. |
| `MITM_ENABLED` | `true` | Включение перехвата HTTPS (MITM). Требует сертификатов `ca.crt` и `ca.key`. |
| `WORKER_COUNT` | `1` | Количество рабочих потоков прокси-сервера (для многоядерных систем). |

---

## 2. Кэширование (L1 Cache & L2)

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `CACHE_CAPACITY` | `10000` | Максимальное количество записей в L1 кэше. |
| `CACHE_TTL_SECONDS` | `3600` | Время жизни записи в кэше по умолчанию (в секундах). |
| `CACHE_SHARDS` | `16` | Количество шардов кэша для снижения lock contention. |
| `CACHE_HONOR_CACHE_CONTROL`| `true` | Уважать заголовки Cache-Control от upstream серверов. |
| `NEGATIVE_CACHE_ENABLED` | `true` | Кэширование ответов с ошибками (4xx, 5xx). |
| `NEGATIVE_CACHE_TTL_SECONDS`| `120` | Время жизни негативного кэша (в секундах). |
| `CACHE_SPILL_THRESHOLD_BYTES`| `256` (KB) | Порог размера тела (в байтах), после которого оно сбрасывается на диск (mmap). |
| `REDIS_L2_ENABLED` | `false` | Включение распределенного L2 кэша через Redis. |
| `REDIS_URL` | `redis://redis:6379`| URL для подключения к Redis. |
| `PERF_FAST_CACHE_HIT` | `false` | Оптимизация (fast-path) для сверхбыстрой отдачи кэша (обход некоторых фильтров). |
| `STREAMING_MISS_ENABLED` | `true` | Стриминг ответа клиенту параллельно с загрузкой в кэш. |

---

## 3. Аутентификация и ZTNA (Authentication)

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `AUTH_ENABLED` | `false` | Включение аутентификации Proxy-Authenticate. |
| `AUTH_BACKEND` | `basic` | Провайдер аутентификации: `basic`, `ldap` или `ntlm`. |
| `AUTH_REALM` | `BSDM-Proxy` | Имя realm для формы авторизации. |
| `AUTH_CACHE_TTL` | `300` | Время жизни кэша успешных авторизаций. |
| **LDAP параметры** | | `LDAP_SERVERS`, `LDAP_BASE_DN`, `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD`, `LDAP_USER_FILTER`, `LDAP_USE_TLS`. |
| **NTLM параметры** | | `NTLM_DOMAIN`, `NTLM_WORKSTATION`. |
| `REVERSE_PROXY_ENABLED` | `false` | Режим обратного проксирования (ZTNA / IAP). |
| `OIDC_*` | | Настройки OIDC для обратного прокси (`OIDC_CLIENT_ID`, `OIDC_ISSUER_URL` и т.д.). |

---

## 4. Фильтрация и ACL (Filtering)

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `ACL_ENABLED` | `false` | Включение политик доступа. |
| `ACL_DEFAULT_ACTION` | `allow` | Действие по умолчанию (`allow` или `deny`). |
| `ACL_RULES_PATH` | `/etc/bsdm-proxy/acl-rules.json` | Путь к файлу правил ACL. |
| `ACL_AUTO_RELOAD` | `false` | Автоматическая перезагрузка правил при изменении. |
| `ACL_RELOAD_INTERVAL` | `60` | Интервал проверки изменений файла ACL (в секундах). |
| `CATEGORIZATION_ENABLED` | `false` | Включение проверки категорий доменов (Malware, Adult, RKN и т.д.). |
| `RKN_SYNC_ENABLED` | `false` | Синхронизация списков РКН. |
| `UT1_ENABLED` | `true` | Использование оффлайн-баз UT1. |
| `URLHAUS_ENABLED` | `false` | Использование API URLhaus для блокировки вредоносов. |

---

## 5. Оценка угроз (ML Threat Score)

Взаимодействует с `ml-worker` для динамического блокирования аномалий.

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `THREAT_SCORE_ENABLED` | `false` | Включение применения ML оценок угроз. |
| `THREAT_SCORE_POLL_URL`| `http://127.0.0.1:8091/api/threat-scores` | URL воркера ML для получения списка угроз. |
| `THREAT_SCORE_BLOCK_THRESHOLD`| `0.9` | Порог уверенности ML, после которого трафик блокируется. |

---

## 6. Иерархия кэша (ICP / HTCP)

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `HIERARCHY_PEERS_PATH` | *(пусто)* | Путь к JSON файлу конфигурации пиров. |
| `ICP_SERVER_ENABLED` | `false` | Включение ICP сервера (UDP). |
| `ICP_BIND` | `0.0.0.0:3130` | Адрес прослушивания ICP. |
| `PEER_DISCOVERY_ENABLED` | `false` | Авто-обнаружение пиров через multicast. |

---

## 7. Сеть и TLS (Network & TLS)

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `UPSTREAM_CA_CERT` | *(пусто)* | Пользовательский CA для проверки upstream серверов. |
| `UPSTREAM_HTTP2_ENABLED`| `false` | Включение протокола HTTP/2 при запросах к upstream. |
| `PRESERVE_HEADER_CASE` | `false` | Сохранять регистр HTTP заголовков (полезно для старых legacy систем). |

---

## 8. Защита и eBPF (Security)

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `RATE_LIMIT_ENABLED` | `false` | Включение лимитирования запросов. |
| `RATE_LIMIT_MAX_KEYS` | `100000` | Максимальное количество ключей в памяти rate limiter'а. |
| `EBPF_XDP_ENABLED` | `false` | Использование eBPF XDP для дропа пакетов на уровне ядра (L4). |
| `EBPF_XDP_IFACE` | `eth0` | Сетевой интерфейс для привязки XDP. |

---

## 9. Плагины и Аналитика (Kafka, Wasm, ICAP)

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `WASM_ENABLED` | `false` | Включение Wasm Request Hooks. |
| `ICAP_ENABLED` | `false` | Инспекция трафика через ICAP (Антивирус/DLP). |
| `ICAP_URL` | `icap://...` | URL ICAP сервера. |
| `KAFKA_SAMPLE_RATE` | `0` (откл) | Процент сэмплирования событий трафика для отправки в Kafka. |
| `KAFKA_BROKERS` | `kafka:9092` | Брокеры Kafka для аналитики. |

---

## 10. AI Семантический Кэш (AI Cache)

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `AI_CACHE_ENABLED` | `false` | Включение семантического L0 кэша (векторизация). |
| `OLLAMA_URL` | `http://...` | URL Ollama для генерации эмбеддингов. |
| `QDRANT_URL` | `http://...` | URL Qdrant векторной базы. |
