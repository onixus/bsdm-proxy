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

В production задавайте `RUST_LOG` явно через env-файл или systemd — см. [packaging/config/bsdm-proxy.env.example](../packaging/config/bsdm-proxy.env.example).

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
| [packaging/config/bsdm-proxy.env.example](../packaging/config/bsdm-proxy.env.example) | `info,bsdm_proxy=info` |
| [packaging/config/cache-indexer.env.example](../packaging/config/cache-indexer.env.example) | `info,cache_indexer=info` |
| [docker-compose.yml](../docker-compose.yml) | `info,bsdm_proxy=debug` / `info,cache_indexer=debug` |
| [docker-compose.hierarchy.yml](../docker-compose.hierarchy.yml) | `info,bsdm_proxy=info` |
| [docker-compose.test.yml](../docker-compose.test.yml) | `warn` |
| [proxy/src/main.rs](../proxy/src/main.rs) | init + fallback |
| [cache-indexer/src/main.rs](../cache-indexer/src/main.rs) | init + fallback |

systemd подхватывает env из `/etc/bsdm-proxy/bsdm-proxy.env` и `cache-indexer.env` ([packaging/systemd/](../packaging/systemd/)).

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
| `info` | Старт, Kafka/OpenSearch endpoints, bulk index stats |
| `warn` | Пропуск событий, retryable ошибки |
| `error` | Сбой consumer, OpenSearch bulk errors |

Метрики и health **не** дублируются в логах — используйте `/metrics` и `/health` на `METRICS_PORT` (по умолчанию `9090`).

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
- [authentication.md](authentication.md) — логи LDAP/auth
- [acl.md](acl.md) — логи ACL
- [packaging/README.md](../packaging/README.md) — установка и env-файлы
