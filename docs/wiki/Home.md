# BSDM-Proxy Wiki

Высокопроизводительный кеширующий HTTPS-прокси на Hyper с интеграцией Kafka, OpenSearch, Prometheus и Grafana.

## Страницы

- [Installation Guide](Installation-Guide) — установка и быстрый старт
- [Полный README](https://github.com/onixus/bsdm-proxy#readme) — архитектура, метрики, конфигурация
- [OPTIMIZATIONS.md](https://github.com/onixus/bsdm-proxy/blob/main/OPTIMIZATIONS.md) — детали оптимизаций
- [Authentication](https://github.com/onixus/bsdm-proxy/blob/main/docs/authentication.md) — Basic/LDAP/NTLM
- [ACL](https://github.com/onixus/bsdm-proxy/blob/main/docs/acl.md) — правила доступа
- [Hierarchical Caching](https://github.com/onixus/bsdm-proxy/blob/main/docs/hierarchical-caching.md) — иерархический кеш

## Компоненты и порты

| Сервис | Порт | Описание |
|--------|------|----------|
| Proxy | 1488 | HTTP forward proxy (MITM TLS к upstream) |
| Metrics | 9090 | `/health`, `/ready`, `/metrics` |
| Kafka | 9092 | Очередь событий кеша |
| OpenSearch | 9200 | Поиск и аналитика |
| OpenSearch Dashboards | 5601 | UI для OpenSearch |
| Prometheus | 9091 | Сбор метрик |
| Grafana | 3000 | Дашборды (`admin` / `admin`) |

## Версии Docker-образов

| Сервис | Образ |
|--------|-------|
| Kafka | `confluentinc/cp-kafka:7.9.8` |
| Zookeeper | `confluentinc/cp-zookeeper:7.9.8` |
| OpenSearch | `opensearchproject/opensearch:3.7.0` |
| OpenSearch Dashboards | `opensearchproject/opensearch-dashboards:3.7.0` |
| Prometheus | `prom/prometheus:v3.12.0` |
| Grafana | `grafana/grafana:12.3.8` |

> Kafka обновлена до последней ветки 7.x с ZooKeeper. Confluent Platform 8.x требует KRaft и отдельной миграции.

## Быстрая проверка

```bash
curl -x http://localhost:1488 https://httpbin.org/get
curl http://localhost:9090/health
curl http://localhost:9200/_cluster/health?pretty
```

---

**Версия proxy:** 2.1.0 | **Лицензия:** MIT
