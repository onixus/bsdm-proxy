# Wiki & Портал Документации BSDM-Proxy

Добро пожаловать в единый центр документации и база знаний **BSDM-Proxy** — корпоративного высокопроизводительного HTTPS-прокси на Rust с ClickHouse аналитикой и ML-безопасностью.

---

## 🗺️ Карта Wiki Документации

```
docs/
├── 🚀 getting-started/       # Быстрый старт, способы развертывания и автономные режимы
├── 🏗️ architecture/          # Устройство ядра, кэширование, производительность и расчет ресурсов
├── 🛡️ features/              # Функциональные модули (ACL, Auth, Wasm, DNS, ICAP, AI Cache)
├── 📊 analytics/             # Аналитика трафика ClickHouse, ретропоиск, алерты и ML
├── 🛠️ ops-and-dev/           # Инструкция разработчика, Kubernetes, бенчмарки и логгирование
├── 📜 adr/                   # Принятые архитектурные решения (ADR 0001–0004)
└── 📦 releases/              # История релизов и списки изменений
```

---

## 🚀 1. Быстрый старт и Развертывание (`getting-started/`)

| Документ | Описание |
|----------|----------|
| [deployment.md](getting-started/deployment.md) | Все способы установки: Zero-compilation installer (`install-binaries.sh`), Docker Compose, Systemd native |
| [lite-mode.md](getting-started/lite-mode.md) | Автономный запуск в Lite-режиме (Proxy + SQLite Search API без Kafka/ClickHouse) |
| [../README.md](../README.md) | Главное руководство проекта и минимальный старт |

---

## 🏗️ 2. Архитектура и Устройство ядра (`architecture/`)

| Документ | Описание |
|----------|----------|
| [overview.md](architecture/overview.md) | Архитектура системы, поток обработки запросов, блокеры и безопасность |
| [hierarchical-caching.md](architecture/hierarchical-caching.md) | Многоуровневое кэширование L1/L2, Redis, протоколы ICP, HTCP и Cache Digest |
| [capacity-planning.md](architecture/capacity-planning.md) | Расчет аппаратных ресурсов (RAM, CPU, диск) под различный объем трафика |
| [performance.md](architecture/performance.md) | Оптимизация производительности, zero-copy I/O и сетевые буферы |
| [structure.md](architecture/structure.md) | Структура репозитория, воркспейса Cargo и описание модулей |

---

## 🛡️ 3. Функциональные Модули Прокси (`features/`)

| Документ | Описание |
|----------|----------|
| [acl-policy.md](features/acl-policy.md) | Движок правил ACL, временные окна TimeWindow, IP/domain правила |
| [authentication.md](features/authentication.md) | Аутентификация пользователей: Basic, LDAP, NTLM, Kerberos |
| [control-plane.md](features/control-plane.md) | REST и gRPC Control Plane API (горячая перезагрузка ACL, TLS сертификатов и иерархии) |
| [categorization.md](features/categorization.md) | Категориальная фильтрация веб-ресурсов (списки UT1) и метрики |
| [wasm-plugins.md](features/wasm-plugins.md) | Рантайм Wasmtime, SDK `bsdm-wasm-sdk`, написание и hot-reload плагинов |
| [dns-sinkhole.md](features/dns-sinkhole.md) | Защищенный шифрованный DNS-шлюз (UDP, DoH RFC 8484, DoT RFC 7858) |
| [icap-inspection.md](features/icap-inspection.md) | Интеграция с антивирусными сканерами по протоколу ICAP (RFC 3507) |
| [semantic-cache.md](features/semantic-cache.md) | Семантическое кэширование AI & LLM запросов с интеграцией Qdrant Vector DB |

---

## 📊 4. Аналитика, Поиск и ML-безопасность (`analytics/`)

| Документ | Описание |
|----------|----------|
| [clickhouse-retrosearch.md](analytics/clickhouse-retrosearch.md) | Схема ClickHouse DDL, ретропоиск, индексатор `cache-indexer` и REST `/api/search` API |
| [alerting.md](analytics/alerting.md) | Движок алертов `alert-worker`, C&C беконы, энтропия Шеннона и SIEM webhooks |
| [ml-security.md](analytics/ml-security.md) | Feature Store, модели UEBA z-score, Lexical Phishing, C&C ML, Flight Risk и Threat Score Write-Back |

---

## 🛠️ 5. Эксплуатация и Разработка (`ops-and-dev/`)

| Документ | Описание |
|----------|----------|
| [development.md](ops-and-dev/development.md) | Инструкция для разработчиков, сборка, юнит-тесты и E2E тестовый каркас |
| [k8s-architecture.md](ops-and-dev/k8s-architecture.md) | Развертывание в Kubernetes, Helm-чарт `charts/bsdm` и ClickHouse Operator (CHI) |
| [benchmarks.md](ops-and-dev/benchmarks.md) | Нагрузочные тесты и профили бенчмарков HTTP Archive |
| [logging.md](ops-and-dev/logging.md) | Формат структурированных логов (JSON) и Prometheus-метрики |
| [licensing.md](ops-and-dev/licensing.md) | Лицензирование и проверка совместимости сторонних библиотек |
| [configuration.md](ops-and-dev/configuration.md) | Полный справочник всех настроек и переменных окружения |

---

## 📜 6. Архитектурные Решения (ADR) (`adr/`)

* [ADR 0001: Tiered Sharded L1 Cache](adr/0001-tiered-sharded-l1-cache.md)
* [ADR 0002: ClickHouse Analytics Store](adr/0002-clickhouse-analytics.md)
* [ADR 0003: ML Worker & Feature Store](adr/0003-ml-worker-feature-store.md)
* [ADR 0004: DNS Sinkhole Sidecar](adr/0004-dns-sinkhole-sidecar.md)

---

## 📦 7. История Релизов (`releases/`)

* [v0.6.0 (Wasm SDK, DoH/DoT, eBPF, Flight Risk ML)](roadmap.md)
* [v0.5.7+033 (Admin Console Overhaul, Capacity Planning)](releases/v0.5.7+033.md)
* [v0.5.0 (Threat Analytics, M4, Alert Worker)](releases/v0.5.0.md)
* [v0.3.2 (Data Plane Throughput, P1 Hot Path)](releases/v0.3.2.md)
* [v0.3.1 (ClickHouse Cutover, Search API)](releases/v0.3.1.md)
* [v0.3.0 (Squid Parity, HTCP, Redis L2)](releases/v0.3.0.md)
* [v0.2.3-test (M1 Foundation Release)](releases/v0.2.3-test.md)

---

## 🧭 Навигация по Ролям

* 🔧 **Инженеры эксплуатации (DevOps / System Administrators):**
  1. [Быстрый старт и деплой](getting-started/deployment.md)
  2. [Lite-режим](getting-started/lite-mode.md)
  3. [Планирование ресурсов](architecture/capacity-planning.md)
  4. [Kubernetes и Helm](ops-and-dev/k8s-architecture.md)

* 🛡️ **ИБ-специалисты (SOC / Threat Hunters):**
  1. [Ретропоиск в ClickHouse и Search API](analytics/clickhouse-retrosearch.md)
  2. [Алерты и интеграция с SIEM](analytics/alerting.md)
  3. [ML-модели выявления угроз и аномалий](analytics/ml-security.md)
  4. [Правила доступа ACL](features/acl-policy.md)

* 💻 **Разработчики (Core & Wasm Contributors):**
  1. [Руководство по разработке](ops-and-dev/development.md)
  2. [Обзор архитектуры](architecture/overview.md)
  3. [Разработка Wasm-плагинов](features/wasm-plugins.md)
  4. [Контроль качества и бенчмарки](ops-and-dev/benchmarks.md)
