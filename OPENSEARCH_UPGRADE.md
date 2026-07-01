# OpenSearch: версии и обновление

Актуальная версия в `docker-compose.yml`: **OpenSearch 3.7.0** + **OpenSearch Dashboards 3.7.0**.

> См. также: [docs/docker.md](docs/docker.md) · [docs/deployment.md](docs/deployment.md)

---

## Текущая конфигурация (compose)

| Сервис | Образ | Порт |
|--------|-------|------|
| opensearch | `opensearchproject/opensearch:3.7.0` | 9200, 9600 |
| opensearch-dashboards | `opensearchproject/opensearch-dashboards:3.7.0` | 5601 |
| dashboards-setup | `curlimages/curl:8.5.0` | — (one-shot) |

Переменные OpenSearch в compose:

```yaml
OPENSEARCH_JAVA_OPTS: -Xms1g -Xmx1g
DISABLE_SECURITY_PLUGIN: true
discovery.type: single-node
```

Индекс cache-indexer: `http-cache` (см. `OPENSEARCH_INDEX`).

---

## Проверка после запуска

```bash
curl http://localhost:9200/_cluster/health
# ожидается: "status":"green" или "yellow"

curl http://localhost:9200
# version.number: 3.7.0

curl http://localhost:5601/api/status
# OpenSearch Dashboards ready
```

---

## Обновление версии OpenSearch

### 1. Остановка (с сохранением данных)

```bash
docker compose stop opensearch opensearch-dashboards cache-indexer
```

Для чистой установки (удаление данных):

```bash
docker compose down -v
```

### 2. Изменение тегов в docker-compose.yml

```yaml
opensearch:
  image: opensearchproject/opensearch:3.7.0   # новый тег

opensearch-dashboards:
  image: opensearchproject/opensearch-dashboards:3.7.0
```

Версии OpenSearch и Dashboards **должны совпадать** по major.minor.

### 3. Pull и запуск

```bash
docker compose pull opensearch opensearch-dashboards
docker compose up -d opensearch opensearch-dashboards
docker compose up -d cache-indexer dashboards-setup
```

### 4. Проверка индексации

```bash
curl http://localhost:9200/http-cache/_count
docker compose logs -f cache-indexer
```

---

## Требования

| Параметр | Значение |
|----------|----------|
| JDK | 21+ (включён в официальный образ) |
| RAM (минимум) | 1 GB heap (`OPENSEARCH_JAVA_OPTS`) |
| `vm.max_map_count` | ≥ 262144 на хосте |

```bash
sudo sysctl -w vm.max_map_count=262144
```

---

## История миграций

| From | To | Примечание |
|------|-----|------------|
| 2.11.0 | 3.3.x | Переход на OpenSearch 3.x, JDK 21, Lucene 10 |
| 3.3.x | 3.7.0 | Текущая версия в репозитории |

При апгрейде через major (2.x → 3.x) рекомендуется `docker compose down -v` и переиндексация — прямой rolling upgrade между major без snapshot не поддерживается в dev-стеке.

---

## Troubleshooting

### OutOfMemoryError

Увеличьте heap в `docker-compose.yml`:

```yaml
OPENSEARCH_JAVA_OPTS: -Xms2g -Xmx2g
```

### Медленный старт

OpenSearch 3.x инициализируется 60–90 секунд. Healthcheck в compose: 10 retries × 10s.

### cache-indexer не пишет в OpenSearch

1. Проверьте `OPENSEARCH_URL=http://opensearch:9200` в cache-indexer.
2. Убедитесь, что Kafka healthy и topic `cache-events` существует.
3. Логи: `docker compose logs cache-indexer`.

---

## Ресурсы

- [OpenSearch releases](https://github.com/opensearch-project/OpenSearch/releases)
- [Upgrade guide](https://opensearch.org/docs/latest/upgrade-to/upgrade-to/)
- [OpenSearch Dashboards](https://opensearch.org/docs/latest/dashboards/)

---

*Версия документа: 2026-06 · OpenSearch 3.7.0*
