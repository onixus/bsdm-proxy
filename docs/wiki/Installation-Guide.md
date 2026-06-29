# Руководство по установке BSDM-Proxy

## Системные требования

**Минимальные:**
- CPU: 2 ядра
- RAM: 4 GB
- Диск: 10 GB свободного места
- OS: Linux (Ubuntu 20.04+), macOS 11+, Windows 10/11 + WSL2

**Рекомендуемые для production:**
- CPU: 4+ ядра
- RAM: 8+ GB
- Диск: 50+ GB (SSD)
- Network: 1 Gbps+

## Установка зависимостей

### Docker

```bash
# Ubuntu/Debian
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# macOS
brew install --cask docker
```

### Rust (опционально, для локальной сборки)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

Требуется Rust 1.83+ (см. `Dockerfile`). Для сборки с rdkafka нужны системные пакеты: `cmake`, `libssl-dev`, `pkg-config`, `librdkafka-dev`, `libclang-dev`.

## Быстрый старт

### 1. Клонирование

```bash
git clone https://github.com/onixus/bsdm-proxy.git
cd bsdm-proxy
```

### 2. Генерация сертификатов

```bash
mkdir -p certs && cd certs
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=RU/ST=Moscow/L=Moscow/O=BSDM/CN=BSDM Root CA"
cd ..
```

### 3. Запуск

```bash
docker compose up -d
docker compose ps
```

### 4. Установка CA

```bash
# Linux
sudo cp certs/ca.crt /usr/local/share/ca-certificates/bsdm-ca.crt
sudo update-ca-certificates

# macOS
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain certs/ca.crt

# Windows: certmgr.msc → Доверенные корневые ЦС → Импорт certs/ca.crt
```

### 5. Проверка

```bash
# Тест proxy (порт 1488 — HTTP forward proxy, не HTTPS)
curl -x http://localhost:1488 https://httpbin.org/get

# Метрики и health
curl http://localhost:9090/health
curl http://localhost:9090/metrics | grep bsdm_proxy

# OpenSearch
curl http://localhost:9200/_cluster/health?pretty
curl http://localhost:9200/http-cache/_count?pretty

# Мониторинг
open http://localhost:9091   # Prometheus
open http://localhost:3000   # Grafana (admin/admin)
open http://localhost:5601   # OpenSearch Dashboards
```

## Версии инфраструктуры

| Компонент | Версия |
|-----------|--------|
| Kafka / Zookeeper | 7.9.8 |
| OpenSearch | 3.7.0 |
| OpenSearch Dashboards | 3.7.0 |
| Prometheus | v3.12.0 |
| Grafana | 12.3.8 |

## Переменные окружения proxy

| Переменная | По умолчанию | Описание |
|-----------|-------------|----------|
| `HTTP_PORT` | `1488` | Порт proxy |
| `METRICS_PORT` | `9090` | Порт метрик |
| `KAFKA_BROKERS` | `kafka:9092` | Kafka брокеры |
| `CACHE_CAPACITY` | `10000` | Размер L1 кеша |
| `CACHE_TTL_SECONDS` | `3600` | TTL кеша (сек) |
| `MAX_CACHE_BODY_SIZE` | `10485760` | Макс. размер body (bytes) |
| `RUST_LOG` | `info` | Уровень логов |

## Troubleshooting

| Проблема | Решение |
|---------|----------|
| Docker не запускается | `docker compose down -v && docker compose up -d` |
| OpenSearch OOM | Увеличьте `OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g` |
| OpenSearch не стартует после обновления | `docker compose down -v` (удалит данные) и перезапуск |
| Kafka timeout | `docker compose restart kafka` |
| Сертификаты | `rm -rf certs/*` и повторите шаг 2 |
| Proxy не отвечает | Проверьте `curl http://localhost:9090/health` |

## Примеры

### Python

```python
import requests

proxies = {'http': 'http://localhost:1488', 'https': 'http://localhost:1488'}
requests.get('https://example.com', proxies=proxies, verify='certs/ca.crt')
```

### Node.js

```javascript
const https = require('https');
const fs = require('fs');

const agent = new https.Agent({
  host: 'localhost',
  port: 1488,
  ca: fs.readFileSync('certs/ca.crt'),
});
```

---

[← Home](Home) | [Полный README](https://github.com/onixus/bsdm-proxy#readme)
