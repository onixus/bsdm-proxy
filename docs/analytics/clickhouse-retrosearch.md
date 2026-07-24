# Ретропоиск и Аналитика на ClickHouse (ClickHouse Retro-Search & Search API)

Платформа ретропоиска `bsdm-proxy` обеспечивает исторический поиск по
метаданным HTTP-трафика, переданным proxy в analytics pipeline. Глубина
поиска ограничена фактическим TTL таблиц. Репозиторный DDL содержит
исторический default 42 дня; для пилота на 100 пользователей принят TTL
до пяти дней.

Документ описывает архитектуру ClickHouse, схему данных `bsdm.http_cache`, индексатор `cache-indexer` и REST-интерфейс `/api/search`.

> См. также: [ADR 0002: ClickHouse Analytics](../adr/0002-clickhouse-analytics.md) · [alerting.md](alerting.md) · [ml-security.md](ml-security.md)

---

## 1. Быстрый старт

```bash
# Запуск полного стека (Proxy + Kafka + ClickHouse + Indexer + Grafana)
docker compose up -d --build

# Проверка схемы таблиц ClickHouse
curl 'http://127.0.0.1:8123/?query=SHOW+TABLES+FROM+bsdm'

# Генерация тестового трафика
curl -x http://127.0.0.1:1488 http://httpbin.org/get

# Проверка записей в ClickHouse и через Search API
curl 'http://127.0.0.1:8123/?query=SELECT+count()+FROM+bsdm.http_cache'
curl 'http://127.0.0.1:8080/api/search?limit=5'
```

* **Grafana Дашборды:** http://localhost:3000 (`admin/admin`) — готовые дашборды **BSDM HTTP Traffic (ClickHouse)** и метрики прокси.
* **REST Search API:** `http://localhost:8080/api/search` (поддерживает JSON и CSV выгрузки для SOC).

---

## 2. Схема Данных ClickHouse

Файл DDL: `scripts/clickhouse/http_cache.sql` создаёт таблицу
`bsdm.http_cache` с TTL 42 дня и дневным партиционированием
(`PARTITION BY toYYYYMMDD(ts)`). Перед эксплуатацией измените TTL под свой
профиль; команда для пилотных пяти дней приведена в
[pilot-deployment.md](../getting-started/pilot-deployment.md).

### Поля таблицы `bsdm.http_cache`:
| Поле | Тип | Описание |
|------|-----|----------|
| `ts` | `DateTime` | Метка времени запроса |
| `event_id` | `UUID` | Уникальный ID события |
| `client_ip` | `String` | IP-адрес клиента |
| `username` | `Nullable(String)` | Имя авторизованного пользователя |
| `method` | `String` | HTTP метод (GET, POST и т.д.) |
| `domain` | `String` | Домен целевого узла |
| `url` | `String` | Полный URL запроса |
| `status` | `UInt16` | HTTP-код ответа |
| `cache_status` | `String` | Статус кэша (HIT, MISS, REVALIDATED, COALESCED-HIT) |
| `response_size` | `UInt64` | Размер ответа в байтах |
| `categories` | `Array(String)` | Категории домена (UT1) |
| `acl_action` | `String` | Действие ACL (allow, block) |
| `threat_sources` | `Array(String)` | Источники обнаруженных угроз (PhishTank, ML) |
| `session_id` | `String` | Soft browsing ID сессии (IP + User + User-Agent) |
| `parent_event_id` | `Nullable(UUID)` | ID родительского запроса (для цепочек редиректов) |
| `redirect_url` | `Nullable(String)` | Целевой URL при редиректе (`Location`) |

---

## 3. Примеры полезных SQL-запросов для SOC

```sql
-- Кто ходил на конкретный домен за последние 5 дней:
SELECT ts, username, client_ip, url, method, status, cache_status, session_id
FROM bsdm.http_cache
WHERE domain = 'example.com'
  AND ts >= now() - INTERVAL 5 DAY
ORDER BY ts DESC
LIMIT 1000;

-- Реконструкция цепочки редиректов и хронологии сессии:
SELECT ts, event_id, parent_event_id, status, url, redirect_url
FROM bsdm.http_cache
WHERE session_id = 'c12a8f90-...'
ORDER BY ts ASC;

-- Топ пользователей по поглощаемому трафику за 7 дней:
SELECT username, domain, count() AS requests, sum(response_size) AS total_bytes
FROM bsdm.http_cache
WHERE ts >= now() - INTERVAL 7 DAY AND username IS NOT NULL
GROUP BY username, domain
ORDER BY total_bytes DESC
LIMIT 50;
```

---

## 4. Конфигурация `cache-indexer`

Сервис `cache-indexer` вычитывает события из Kafka (или принимает по HTTP) и производит пакетную вставку в ClickHouse в формате `JSONEachRow`.

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `INDEX_STORE` | `clickhouse` | Хранилище: `clickhouse`, `sqlite` или `memory` |
| `METRICS_PORT` | `8080` | Порт `/metrics`, `/health`, `/api/search` |
| `SEARCH_API_ENABLED` | `true` | Включить REST Search API |
| `SEARCH_API_TOKEN` | *unset* | Bearer-токен авторизации для `/api/search` |
| `INGEST_API_TOKEN` | *same as search* | Bearer-токен авторизации для `POST /api/events` |
| `SEARCH_API_MAX_LIMIT` | `10000` | Максимальное количество строк в выгрузке |
| `SEARCH_API_DEFAULT_DAYS` | `30` | Период поиска по умолчанию (дней) |
| `CLICKHOUSE_URL` | `http://clickhouse:8123` | HTTP URL ClickHouse |
| `CLICKHOUSE_DATABASE` | `bsdm` | Имя базы данных |
| `CLICKHOUSE_TABLE` | `http_cache` | Имя таблицы |

Метрики Prometheus:
* `cache_indexer_inserts_total{backend="clickhouse"}`
* `cache_indexer_insert_errors_total{backend}`
* `cache_indexer_batch_duration_seconds`

---

## 5. Спецификация REST Search API (`/api/search`)

### Эндпоинты
* `GET  /api/search` — выполнение ретропоиска.
* `POST /api/events` — прямой инжест событий (в Lite-режиме без Kafka).

### Параметры запроса `GET /api/search`:
| Параметр | Обязательный | Описание |
|----------|--------------|----------|
| `domain` | Нет | Фильтр по домену |
| `username` | Нет | Фильтр по имени пользователя |
| `session_id` | Нет | Фильтр по сессии с хронологической сортировкой |
| `from` | Нет | Unix timestamp начала периода |
| `to` | Нет | Unix timestamp конца периода |
| `days` | Нет | Глубина поиска в днях (по умолчанию 30) |
| `limit` | Нет | Количество строк (по умолчанию 1000, максимум `SEARCH_API_MAX_LIMIT`) |
| `format` | Нет | Формат ответа: `json` (по умолчанию) или `csv` |

### Примеры использования:

```bash
# Поиск событий по домену в формате JSON
curl -s 'http://127.0.0.1:8080/api/search?domain=httpbin.org&days=7' | jq .

# Экспорт результатов в CSV для SOC / ИБ-расследования
curl -s 'http://127.0.0.1:8080/api/search?domain=malicious.org&format=csv' -o incident.csv

# Запрос с авторизацией по Bearer токену
curl -H "Authorization: Bearer secret_token" \
  'http://127.0.0.1:8080/api/search?limit=5'
```

---

## 6. Безопасность и Санитаризация
- Параметры поиска санитаризируются на стороне сервера; любые спецсимволы отсекаются.
- ClickHouse и SQLite запросы используют исключительно параметризованные выражение (`{param:Type}` / bound params), исключая SQL-инъекции.
