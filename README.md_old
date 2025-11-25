# BSDM-Proxy

**B**usiness **S**ecure **D**ata **M**onitoring Proxy

Кеширующий HTTPS-прокси с подменой сертификатов на базе [Pingora](https://github.com/cloudflare/pingora), интегрированный с Kafka и OpenSearch для анализа и мониторинга трафика.

## ⚠️ Предупреждение

Создание MITM-прокси (Man-in-the-Middle) для HTTPS — это атака на цепочку доверия TLS. Использование данного инструмента допустимо **только** в следующих сценариях:

- Корпоративная среда с явным согласием пользователей
- DLP (Data Loss Prevention) и контроль утечек данных
- Защита от вредоносного ПО и фильтрация контента
- Соблюдение нормативных требований (compliance)

**Требования:**
- Корневой CA-сертификат должен быть установлен на клиентских устройствах
- Пользователи должны быть уведомлены о мониторинге
- Соблюдение законодательства о защите персональных данных

## Архитектура

```
[Клиент] --HTTPS--> [BSDM-Proxy:1488]
                         |
                         +---> [L1 Cache] (in-memory)
                         +---> [Kafka] ---> [Cache-Indexer] ---> [OpenSearch]
                         |
                         +--HTTPS--> [Upstream Server]
```

## Возможности

- **MITM TLS-прокси**: Подмена сертификатов для инспекции HTTPS-трафика
- **Двухуровневое кеширование**: 
  - L1: in-memory кеш в Pingora
  - L2: OpenSearch для долгосрочного хранения и аналитики
- **Асинхронная индексация**: Через Kafka для минимизации задержек
- **Полнотекстовый поиск**: OpenSearch для анализа кешированного контента
- **Высокая производительность**: На базе Cloudflare Pingora

## Компоненты

### 1. Proxy (`proxy/`)
Главный компонент — TLS-прокси на Pingora:
- Слушает порт **1488**
- Подменяет сертификаты для MITM
- Кеширует ответы в памяти
- Отправляет события кеширования в Kafka

### 2. Cache Indexer (`cache-indexer/`)
Сервис индексации:
- Читает события из Kafka (топик `cache-events`)
- Индексирует в OpenSearch (индекс `http-cache`)
- Поддерживает full-text поиск по контенту

## Быстрый старт

### Предварительные требования

- Docker & Docker Compose
- Rust 1.75+ (для локальной разработки)

### 1. Генерация сертификатов

```bash
mkdir -p certs
cd certs

# Корневой CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=RU/ST=Moscow/L=Moscow/O=BSDM/CN=BSDM Root CA"

# Серверный сертификат для прокси
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/C=RU/ST=Moscow/L=Moscow/O=BSDM/CN=*.bsdm.local"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365

cd ..
```

### 2. Запуск инфраструктуры

```bash
docker-compose up -d
```

Это запустит:
- Kafka + Zookeeper (порт 9092)
- OpenSearch (порт 9200)
- BSDM-Proxy (порт 1488)
- Cache-Indexer

### 3. Установка CA-сертификата на клиенте

**Linux:**
```bash
sudo cp certs/ca.crt /usr/local/share/ca-certificates/bsdm-ca.crt
sudo update-ca-certificates
```

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/ca.crt
```

**Windows:**
Импортировать `certs/ca.crt` в хранилище «Доверенные корневые центры сертификации»

### 4. Настройка прокси

Установите в браузере/системе прокси:
- **Адрес:** `localhost` или IP сервера
- **Порт:** `1488`
- **Протокол:** HTTPS

### 5. Проверка

```bash
# Запрос через прокси
curl -x https://localhost:1488 https://example.com

# Проверка OpenSearch
curl http://localhost:9200/http-cache/_search?pretty
```

## Конфигурация

### Переменные окружения

**Proxy:**
- `KAFKA_BROKERS` — адреса Kafka (по умолчанию: `kafka:9092`)
- `RUST_LOG` — уровень логирования (`info`, `debug`, `trace`)

**Cache Indexer:**
- `KAFKA_BROKERS` — адреса Kafka
- `OPENSEARCH_URL` — URL OpenSearch (по умолчанию: `http://opensearch:9200`)
- `KAFKA_GROUP_ID` — consumer group (по умолчанию: `cache-indexer-group`)
- `KAFKA_TOPIC` — топик Kafka (по умолчанию: `cache-events`)

### Настройка кеширования

В `proxy/src/main.rs` можно изменить параметры кеша:
```rust
let cache = HttpCache::new()
    .set_max_file_size_bytes(10 * 1024 * 1024) // 10 MB
    .set_cache_lock_timeout(Duration::from_secs(2));
```

## Разработка

### Локальная сборка

```bash
# Сборка всех компонентов
cargo build --release

# Запуск прокси
cargo run --bin proxy --release

# Запуск индексера
cargo run --bin cache-indexer --release
```

### Структура проекта

```
bsdm-proxy/
├── Cargo.toml              # Workspace definition
├── docker-compose.yml      # Инфраструктура
├── proxy/
│   ├── Cargo.toml
│   ├── Dockerfile
│   └── src/
│       └── main.rs         # TLS-прокси на Pingora
└── cache-indexer/
    ├── Cargo.toml
    ├── Dockerfile
    └── src/
        └── main.rs         # Kafka → OpenSearch индексер
```

## Безопасность

### Рекомендации по развертыванию

1. **Изолируйте инфраструктуру**: Используйте отдельную сеть для компонентов
2. **Шифруйте Kafka**: Настройте TLS для Kafka в продакшене
3. **Защитите OpenSearch**: Включите аутентификацию и TLS
4. **Ротация сертификатов**: Автоматизируйте обновление CA и серверных сертификатов
5. **Логирование**: Включите audit-логи для соответствия compliance
6. **Мониторинг**: Настройте алерты на аномальный трафик

### Ограничения MITM

- **Certificate Pinning**: Не работает с приложениями, использующими pinning
- **Двусторонний TLS**: Требует дополнительной настройки для mTLS
- **HSTS**: Браузеры могут блокировать HTTPS-сайты с HSTS при первом посещении

## OpenSearch: Запросы и аналитика

### Примеры поиска

```bash
# Поиск по URL
curl -X GET "http://localhost:9200/http-cache/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "match": { "url": "example.com" }
  }
}'

# Поиск по контенту
curl -X GET "http://localhost:9200/http-cache/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "match": { "body": "search term" }
  }
}'

# Агрегация по доменам
curl -X GET "http://localhost:9200/http-cache/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "aggs": {
    "domains": {
      "terms": { "field": "url.keyword", "size": 10 }
    }
  }
}'
```

## Производительность

- **Задержка L1-кеша**: <1 мс (in-memory)
- **Throughput**: Зависит от Pingora (~100k+ req/s на одном ядре)
- **Kafka**: Асинхронная отправка не блокирует proxy
- **OpenSearch**: Индексация с batch-обработкой

## Лицензия

MIT License - см. [LICENSE](LICENSE)

## Известные проблемы

- WebSocket: Требуется отдельная обработка (TODO)
- HTTP/3 (QUIC): Не поддерживается в текущей версии Pingora
- Streaming: Большие файлы могут вызвать проблемы с памятью

## Roadmap

- [ ] Поддержка HTTP/2 Server Push
- [ ] Интеграция с threat intelligence (VirusTotal, etc.)
- [ ] Dashboard для визуализации (Grafana/Kibana)
- [ ] Machine Learning для обнаружения аномалий
- [ ] Policy engine для гибкой фильтрации


## Авторы

Разработано с использованием AI - не рекомендуется к использованию

---

**Disclaimer:** Используйте исключительно в легальных целях с согласия всех сторон. Авторы не несут ответственности за неправомерное использование.
