# Логирование

BSDM-Proxy и cache-indexer используют [tracing](https://docs.rs/tracing) + [tracing-subscriber](https://docs.rs/tracing-subscriber). Уровень и область логов задаются переменной окружения **`RUST_LOG`** ([`EnvFilter`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html)).

## Переменные

| Переменная | Компонент | Описание |
|------------|-----------|----------|
| `RUST_LOG` | proxy, cache-indexer | Фильтр уровней (`error`, `warn`, `info`, `debug`, `trace`) и модулей |
| `RUST_BACKTRACE` | оба | `1` — полный backtrace при panic (для отладки) |

## Значения по умолчанию

Если `RUST_LOG` **не задана**:

| Бинарник | Fallback | Примечание |
|----------|----------|------------|
| `proxy` | `info,bsdm_proxy=debug` | Удобно для локальной разработки (`cargo run`) |
| `cache-indexer` | `info,cache_indexer=info` | Сообщения indexer на уровне `info` |

В production задавайте `RUST_LOG` явно через env-файл или systemd — см. [packaging/config/bsdm-proxy.env.example](../../packaging/config/bsdm-proxy.env.example).

### Рекомендуемые профили

**Production (proxy):**
```bash
RUST_LOG=info,bsdm_proxy=info
```

**Production (cache-indexer):**
```bash
RUST_LOG=info,cache_indexer=info
```

**Отладка прокси (MITM, ACL, hierarchy, rate limit):**
```bash
RUST_LOG=info,bsdm_proxy=debug
```

**Минимальный шум (только предупреждения и ошибки):**
```bash
RUST_LOG=warn
```

**Трассировка одного модуля:**
```bash
RUST_LOG=info,bsdm_proxy::icp=debug,bsdm_proxy::hierarchy=debug
```

## Имена модулей (targets)

Используйте имя крейта с подчёркиванием:

| Крейт | Префикс в `RUST_LOG` |
|-------|----------------------|
| `bsdm-proxy` | `bsdm_proxy` |
| `cache-indexer` | `cache_indexer` |

Подмодули: `bsdm_proxy::proxy_service`, `bsdm_proxy::icp`, `bsdm_proxy::acl`, `bsdm_proxy::auth` и т.д.

## Где настраивается в репозитории

| Файл | `RUST_LOG` |
|------|------------|
| [packaging/config/bsdm-proxy.env.example](../../packaging/config/bsdm-proxy.env.example) | `info,bsdm_proxy=info` |
| [packaging/config/cache-indexer.env.example](../../packaging/config/cache-indexer.env.example) | `info,cache_indexer=info` |
| [docker-compose.yml](../../docker-compose.yml) | `info,bsdm_proxy=debug` / `info,cache_indexer=debug` |
| [deploy/compose/docker-compose.hierarchy.yml](../../deploy/compose/docker-compose.hierarchy.yml) | `info,bsdm_proxy=info` |
| [deploy/compose/docker-compose.test.yml](../../deploy/compose/docker-compose.test.yml) | `warn` |
| [proxy/src/main.rs](../../proxy/src/main.rs) | init + fallback |
| [cache-indexer/src/main.rs](../../cache-indexer/src/main.rs) | init + fallback |

systemd подхватывает env из `/etc/bsdm-proxy/bsdm-proxy.env` и `cache-indexer.env` ([packaging/systemd/](../../packaging/systemd/)).

## Что логируется

### Proxy (`bsdm_proxy`)

| Уровень | Примеры |
|---------|---------|
| `info` | Старт, порты, включённые подсистемы (ACL, hierarchy, rate limit), graceful shutdown |
| `warn` | Неизвестная стратегия peer selection, ошибки ICP, fallback auth backend |
| `debug` | MITM-соединения, cache hit/miss, ACL decisions, peer fetch |
| `error` | Ошибки upstream, Kafka flush, критические сбои обработки |

### cache-indexer

| Уровень | Примеры |
|---------|---------|
| `info` | Старт, Kafka/ClickHouse endpoints, batch insert stats |
| `warn` | Пропуск событий, retryable ошибки |
| `error` | Сбой consumer, ClickHouse insert errors |

Метрики и health **не** дублируются в логах — используйте `/metrics` и `/health` на `METRICS_PORT` (по умолчанию `9090`).

## Observability & Policy Decision Sources (`decision_source`)

Каждое политическое решение в BSDM-Proxy маркируется полем **`decision_source`**:

| `decision_source` | Описание источника решения |
|-------------------|----------------------------|
| `dns` | Запрос перехвачен и обработан DNS-sinkhole (UDP RPZ / DoH / DoT) |
| `sni` | Запрос обработан по SNI без TLS-расшифровки (`POLICY_MODE=sni` или проксирование CONNECT) |
| `mitm` | Запрос прошёл через TLS MITM расшифровку (`POLICY_MODE=full-mitm` / `selective-mitm`) |
| `pinning-bypass` | TLS MITM расшифровка пропущена из-за совпадения с `pinning_exceptions` |
| `auth-deny` | Запрос заблокирован на этапе аутентификации |

### Prometheus Метрика:
```prometheus
# HELP bsdm_proxy_policy_decision_source_total Total policy decisions by decision source
# TYPE bsdm_proxy_policy_decision_source_total counter
bsdm_proxy_policy_decision_source_total{source="mitm"} 4812
bsdm_proxy_policy_decision_source_total{source="sni"} 1920
bsdm_proxy_policy_decision_source_total{source="pinning-bypass"} 14
```

Поле `decision_source` сквозным образом передаётся через `CacheEvent`, сохраняется в ClickHouse (`bsdm.http_cache`), доступно в REST Search API (`/api/search?decision_source=mitm`) и отображается на Grafana дашборде.

## Просмотр логов

**Docker Compose:**
```bash
docker compose logs -f proxy
docker compose logs -f cache-indexer
docker compose logs -f proxy 2>&1 | grep -iE 'acl|ldap|icp|rate.?limit'
```

**systemd:**
```bash
journalctl -u bsdm-proxy -f
journalctl -u bsdm-cache-indexer -f
```

**Локальный запуск:**
```bash
RUST_LOG=info,bsdm_proxy=debug cargo run -p bsdm-proxy --bin proxy
```

## Связанные документы

- [development.md](development.md) — локальный запуск и отладка
- [authentication.md](../features/authentication.md) — логи LDAP/auth
- [acl.md](../features/acl-policy.md) — логи ACL
- [packaging/README.md](../../packaging/README.md) — установка и env-файлы
