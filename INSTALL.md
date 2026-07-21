# Руководство по установке BSDM-Proxy

BSDM-Proxy — высокопроизводительный кэширующий HTTPS forward-прокси на Rust с поддержкой TLS MITM, гибкой ACL-авторизацией, аналитическим конвейером Kafka → ClickHouse, модулями eBPF/XDP, DoH/DoT и ICAP.

---

## 📋 Системные требования

### Для сборки из исходников

| Компонент | Минимальная версия | Назначение |
|-----------|--------------------|------------|
| **Rust / Cargo** | 1.85+ (рекомендуется 1.88+ stable) | Компиляция проектов |
| **OpenSSL** | `libssl-dev` | Шифрование TLS / MITM |
| **librdkafka** | `librdkafka-dev` | Подключение к Apache Kafka |
| **Clang / LLVM** | `libclang-dev` | Компиляция eBPF / XDP модулей |
| **Protobuf** | `protobuf-compiler` | gRPC Control Plane |
| **CMake & pkg-config** | Latest | Сборка C-зависимостей |

#### Установка зависимостей в Debian / Ubuntu:
```bash
sudo apt-get update && sudo apt-get install -y \
  build-essential \
  libssl-dev \
  pkg-config \
  cmake \
  librdkafka-dev \
  libclang-dev \
  protobuf-compiler
```

---

## 🔐 Подготовка MITM-сертификатов

Если включен перехват TLS (`MITM_ENABLED=true`, по умолчанию включен), прокси требует наличие ключевой пары CA для динамической генерации сертификатов сайтов:

```bash
# Генерация ca.key и ca.crt в каталог ./certs/
./scripts/gen-ca.sh
```

---

## 🚀 Варианты развертывания

### Вариант 1: Docker Compose (Рекомендуется для Dev / Lab)

#### 1. Lite-режим (Proxy + SQLite Search API, без Kafka и ClickHouse)
Подходит для локальной разработки и легких серверов.

```bash
# 1. Сгенерировать CA сертификат
./scripts/gen-ca.sh

# 2. Запустить Lite-стек
docker compose -f docker-compose.lite.yml up -d --build
```

#### 2. Полный стек (Proxy + Indexer + Kafka + ClickHouse + Prometheus + Grafana)
Подходит для полноценного окружения с аналитикой и мониторингом.

```bash
# 1. Сгенерировать CA сертификат
./scripts/gen-ca.sh

# 2. Запустить полный стек
docker compose up -d --build

# 3. Проверить статус контейнеров
docker compose ps
```

---

### Вариант 2: Локальная сборка и запуск через Cargo

#### Сборка из исходных текстов
```bash
# Debug сборка основного прокси (auth-basic + kafka)
cargo build -p bsdm-proxy --bin proxy

# Release сборка всех ключевых бинарников (proxy + cache-indexer)
cargo build --release -p bsdm-proxy --bin proxy -p cache-indexer --bin cache-indexer

# Lite сборка без зависимости от librdkafka
cargo build -p bsdm-proxy --no-default-features --features auth-basic --bin proxy
```

#### Ручной запуск прокси
```bash
HTTP_PORT=1488 METRICS_PORT=9090 MITM_ENABLED=true cargo run -p bsdm-proxy --bin proxy
```

---

### Вариант 3: Установка Native-пакета в Linux (systemd)

Для развертывания на выделенных серверах (Bare Metal / VM) без Docker:

```bash
# 1. Сборка пакета установки
./scripts/build-package.sh

# 2. Распаковка архива
tar xzf dist/bsdm-proxy-*-linux-x86_64.tar.gz
cd bsdm-proxy-*-linux-x86_64

# 3. Инсталляция системы
sudo ./install.sh --create-user --systemd

# 4. Скопировать сертификаты
sudo cp certs/ca.key certs/ca.crt /etc/bsdm-proxy/certs/

# 5. Запуск службы
sudo systemctl enable --now bsdm-proxy
```

---

### Вариант 4: Развертывание в Kubernetes (Helm)

Подходит для продуктовых HA-кластеров.

```bash
# Установка Helm-чарта
helm install bsdm ./charts/bsdm -n bsdm-proxy --create-namespace

# Установка с продакшн-конфигурацией
helm install bsdm ./charts/bsdm -f charts/bsdm/values-prod.yaml -n bsdm-proxy --create-namespace
```

---

## 🌐 Порты и эндпоинты

| Сервис | Порт | Протокол | Назначение / Эндпоинты |
|--------|------|----------|------------------------|
| **Proxy HTTP/HTTPS** | `1488` | HTTP / CONNECT | Основной прокси-порт |
| **Proxy Metrics & Health** | `9090` | HTTP | `/health`, `/ready`, `/metrics` |
| **Cache Indexer Admin & Search** | `8080` | HTTP | Admin API, поиск по кэшу |
| **DNS Sinkhole (UDP)** | `53` | UDP | Plain DNS RPZ sinkhole |
| **DNS Sinkhole (DoT)** | `853` | TCP / TLS | DNS over TLS |
| **DNS Sinkhole (DoH)** | `8443` | HTTPS | DNS over HTTPS |
| **Prometheus** | `9090` | HTTP | Мониторинг метрик |
| **Grafana** | `3000` | HTTP | Дашборды и графики |

---

## 🧪 Проверка работоспособности

После запуска прокси вы можете проверить его состояние следующими командами:

```bash
# 1. Проверка Healthcheck
curl http://127.0.0.1:9090/health

# 2. Проверка HTTP проксирования
curl -x http://127.0.0.1:1488 http://httpbin.org/get

# 3. Проверка HTTPS MITM проксирования
curl --cacert certs/ca.crt -x http://127.0.0.1:1488 https://httpbin.org/uuid
```
