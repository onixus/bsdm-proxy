# Лицензирование и third-party компоненты

Обзор лицензий переиспользуемого ПО для кода `1.0.0-rc.1`. Состав и версии
проверяются по manifests/lockfiles, Dockerfile и Compose. Это не юридическое
заключение и не полный повторный аудит всех транзитивных зависимостей.

> См. также: [NOTICE](../../NOTICE) · [LICENSE](../../LICENSE)

---

## Лицензия проекта

**BSDM-Proxy** распространяется под **MIT License** ([LICENSE](../../LICENSE)).

Workspace-крейты:

| Крейт | Лицензия |
|-------|----------|
| `bsdm-proxy` (proxy) | MIT |
| `cache-indexer` | MIT |
| `alert-worker` | MIT |
| `ml-worker` | MIT |
| `dns-sinkhole` | MIT |
| `threat-intel` | MIT |
| `bsdm-events` | MIT |
| `bsdm-wasm-sdk` | MIT |
| `bsdm-proxy-e2e` | MIT (только тесты, не в release) |

---

## Сводка по областям

| Область | Статус | Примечание |
|---------|--------|------------|
| Дефолтная сборка (`auth-basic`, `kafka`) | ✅ Permissive | MIT / Apache-2.0 / BSD — без GPL/AGPL |
| `auth-ldap`, `auth-ntlm` | ✅ Permissive | ldap3, sspi — Apache-2.0 OR MIT |
| `auth-kerberos` | ⚠️ AGPL | `kerberos_keytab` — **AGPL-3.0** |
| Docker Compose (инфра) | ⚠️ AGPL | Grafana core — **AGPL-3.0** |
| Внешние БД (UT1 Blacklists) | ⚠️ Admin | Лицензия данных — на стороне администратора |

---

## Rust-зависимости

### Дефолтная production-сборка

Стандартная сборка proxy и cache-indexer:

```bash
cargo build --release -p bsdm-proxy --bin proxy -p cache-indexer --bin cache-indexer
```

Проверка лицензий runtime-графа (без dev/build deps):

```bash
cargo install cargo-license
cargo license --avoid-dev-deps --avoid-build-deps
```

Точный граф зависит от lockfile и выбранных features. Блокирующий CI запускает
`cargo deny --locked check` для default features: advisories и
bans/licenses/sources. `--all-features` — отдельный report-only job с известным
AGPL `kerberos_keytab` и RSA advisory; его красный результат не скрывается
успешным default-feature gate ([development](development.md#github-merge-gate-и-опциональные-features)).

### Прямые зависимости proxy

| Компонент | Лицензия | Назначение |
|-----------|----------|------------|
| hyper, tokio, bytes | MIT | HTTP server / async |
| quick_cache | MIT | L1 cache |
| rdkafka | MIT | Kafka producer |
| rustls, ring | Apache-2.0 / ISC / MIT | TLS (MITM, upstream) |
| redis | BSD-3-Clause | Redis L2 (опц.) |
| brotli, zstd | BSD-3 / MIT | Сжатие тела кеша |
| prometheus | Apache-2.0 | `/metrics` |
| reqwest | Apache-2.0 OR MIT | HTTP client (categorization) |
| serde, chrono, regex | Apache-2.0 OR MIT | Сериализация, время, ACL |

Полный список прямых зависимостей — в [NOTICE](../../NOTICE).

### Опциональные auth-features

| Feature | Crate | Лицензия | Риск |
|---------|-------|----------|------|
| `auth-ldap` | ldap3 | Apache-2.0 OR MIT | Нет |
| `auth-ntlm` | sspi | Apache-2.0 OR MIT | Нет |
| `auth-kerberos` | kerberos_keytab | **AGPL-3.0** | **Copyleft** |

```bash
# Показать copyleft при сборке с Kerberos
cd proxy && cargo license --features auth-kerberos --json \
  | jq '.[] | select(.license | test("GPL"))'
```

**Рекомендации для `auth-kerberos`:**

- Не включать в enterprise/release binary без юридической оценки AGPL.
- Для AD/Kerberos рассмотреть LDAP (`auth-ldap`) как permissive-альтернативу.
- При необходимости Kerberos — оценить замену `kerberos_keytab` или dual-licensing.

Дефолтный CI и release-пакет **не** включают `auth-kerberos`.

### Нативные библиотеки

При сборке Docker-образа ([Dockerfile](../../Dockerfile)) статически линкуются:

| Библиотека | Лицензия |
|------------|----------|
| librdkafka (через rdkafka-sys) | BSD-2-Clause |
| OpenSSL 3.x | Apache-2.0 ([upstream LICENSE](https://github.com/openssl/openssl/blob/openssl-3.3.0/LICENSE.txt)) |
| lz4, zlib, zstd, cyrus-sasl | Permissive (Alpine packages) |

---

## Docker Compose (инфраструктура)

Образы **не входят** в бинарники BSDM-Proxy — подтягиваются при `docker compose up`.

| Образ | Лицензия | Compose-файл |
|-------|----------|--------------|
| `confluentinc/cp-kafka:7.9.8` | Apache-2.0 (community Kafka) | `docker-compose.yml` |
| `confluentinc/cp-zookeeper:7.9.8` | Apache-2.0 | `docker-compose.yml` |
| `clickhouse/clickhouse-server:24.12` | Apache-2.0 | `docker-compose.yml` |
| `prom/prometheus:v3.12.0` | Apache-2.0 | `docker-compose.yml` |
| **`grafana/grafana:12.3.8`** | **AGPL-3.0** | `docker-compose.yml` |
| `grafana-clickhouse-datasource` | Apache-2.0 | Grafana plugin |
| `grafana-piechart-panel` | MIT | Grafana plugin |
| `redis:7.4-alpine` | RSALv2 OR SSPLv1 ([Redis 7.4 LICENSE](https://github.com/redis/redis/blob/7.4/LICENSE.txt)); отличается от BSD-лицензии Rust-клиента `redis-rs` | `deploy/compose/docker-compose.redis-l2.yml`, `.ha.yml` |
| `kennethreitz/httpbin` | BSD | `deploy/compose/docker-compose.test.yml` (только тесты) |

### Grafana (AGPL-3.0)

С Grafana 8.0 core перешёл с Apache-2.0 на **AGPL-3.0**.

- **Внутреннее использование** без модификаций — обычно приемлемо.
- **SaaS / модификации / перепродажа** — могут потребоваться обязательства AGPL или [Grafana Enterprise](https://grafana.com/licensing/).
- Плагин ClickHouse datasource — отдельно под Apache-2.0.

Альтернатива: развернуть только Prometheus + Search API без Grafana UI.

---

## Внешние данные и API

Не являются Rust-зависимостями; администратор подключает самостоятельно.

| Источник | Тип | Лицензия |
|----------|-----|----------|
| **UT1 Blacklists** | Локальная БД категорий | Условия [UT1](https://dsi.ut-capitole.fr/blacklists/) — проверяйте перед production |
| **URLhaus** | HTTP API (abuse.ch) | Условия использования API |
| **PhishTank** | HTTP API | Условия использования API |
| MITM CA (`certs/`) | Генерируется локально | — |

---

## Соответствие и аудит

### Регулярная проверка

```bash
# Полный граф runtime-зависимостей
cargo license --avoid-dev-deps --avoid-build-deps

# С optional auth
cd proxy && cargo license --features auth-all

# Security advisories (отдельно от лицензий)
cargo install cargo-audit
cargo audit
```

### Файлы проекта

| Файл | Назначение |
|------|------------|
| [LICENSE](../../LICENSE) | MIT — лицензия BSDM-Proxy |
| [NOTICE](../../NOTICE) | Краткий реестр third-party (прямые deps, Docker, native) |
| `docs/ops-and-dev/licensing.md` | Этот документ — детали и рекомендации |

### Исторические компоненты (удалены)

Следующие компоненты **больше не используются** (с v0.3.1):

- Pingora (ранний HTTP stack)
- OpenSearch Rust client (заменён на ClickHouse)
- `docker-compose.clickhouse.yml` (слит в основной compose)

---

## Рекомендации для release / enterprise

1. Собирать release **без** `auth-kerberos`, если не проведена AGPL-оценка.
2. Включать [NOTICE](../../NOTICE) в release tarball (`packaging/`).
3. Для Docker-стека документировать AGPL Grafana для compliance-команды.
4. Проверять действующий `cargo-deny` policy (`deny.toml`) для точного feature graph; optional-feature report не заменяет blocking default gate.

---

*Последний зафиксированный аудит: 2026-08 · v0.9.14 · `cargo license` +
compose manifest.*
