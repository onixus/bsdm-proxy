# OpenSearch Upgrade Guide

Руководство по обновлению OpenSearch в стеке BSDM-Proxy.

**Текущая версия в `docker-compose.yml`:** `opensearchproject/opensearch:3.7.0`  
**OpenSearch Dashboards:** `opensearchproject/opensearch-dashboards:3.7.0`

## Что нового в 3.7.0

OpenSearch 3.7.0 (июнь 2026) — актуальный релиз в линейке 3.x. По сравнению с 3.3.2:

- Улучшения производительности индексации и поиска на базе Lucene 10.x
- Развитие AI/ML возможностей (hybrid search, semantic search)
- Обновлённый OpenSearch Dashboards UI
- JDK 21 (включён в Docker-образ)

## Сравнение версий

| Параметр | 2.11.0 | 3.3.2 | 3.7.0 |
|----------|--------|-------|-------|
| **JDK** | 11/17 | 21 | 21 |
| **Lucene** | 9.7.0 | 10.1.0 | 10.x |
| **RAM (min)** | 512MB | 1GB | 1GB |
| **Support** | EOL | Active | Active |

## Миграция

### Шаг 1: Остановка текущего стека

```bash
# Остановка без удаления данных (если нужно сохранить индексы)
docker compose down

# ИЛИ полная очистка (рекомендуется при смене мажорной версии)
docker compose down -v
```

> При обновлении между версиями 3.x обычно достаточно `docker compose pull && docker compose up -d`. Если OpenSearch не стартует — используйте `docker compose down -v` (данные будут удалены).

### Шаг 2: Загрузка новых образов

```bash
docker pull opensearchproject/opensearch:3.7.0
docker pull opensearchproject/opensearch-dashboards:3.7.0

docker images | grep opensearch
```

### Шаг 3: Запуск

```bash
docker compose up -d

docker compose logs -f opensearch
```

### Шаг 4: Проверка

```bash
curl http://localhost:9200
curl http://localhost:9200/_cluster/health?pretty
curl http://localhost:5601/api/status
```

Ожидаемый фрагмент ответа:

```json
{
  "name": "opensearch-node1",
  "cluster_name": "opensearch-cluster",
  "version": {
    "number": "3.7.0",
    "lucene_version": "10.x",
    "minimum_wire_compatibility_version": "3.0.0",
    "minimum_index_compatibility_version": "3.0.0"
  },
  "tagline": "The OpenSearch Project: https://opensearch.org/"
}
```

Проверка индексации cache-indexer:

```bash
curl http://localhost:9200/http-cache/_count?pretty
```

## Требования

### JDK 21

OpenSearch 3.x требует Java 21. В официальном Docker-образе JDK уже включён.

### Память

В `docker-compose.yml` задано:

```yaml
OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g
```

Для production с большим объёмом данных увеличьте до 2GB и более.

## Новые возможности 3.x

### Hybrid Search

Комбинирует keyword и semantic поиск:

```json
POST /http-cache/_search
{
  "query": {
    "hybrid": {
      "queries": [
        {
          "match": {
            "url": "github"
          }
        },
        {
          "neural": {
            "url_embedding": {
              "query_text": "github repositories",
              "model_id": "...",
              "k": 10
            }
          }
        }
      ]
    }
  }
}
```

### Search Relevance Workbench

Инструмент для настройки релевантности поиска в Dashboards.

## Breaking Changes

1. **JDK 21 обязателен** — собственные плагины нужно перекомпилировать под Java 21.
2. **Минимум 1GB RAM** — вместо 512MB в OpenSearch 2.x.
3. **Удалены устаревшие API** — см. [changelog](https://github.com/opensearch-project/OpenSearch/releases/tag/3.7.0).

## Troubleshooting

### OutOfMemoryError

```yaml
environment:
  - "OPENSEARCH_JAVA_OPTS=-Xms2g -Xmx2g"
```

### UnsupportedClassVersionError

Обновите образ без кеша:

```bash
docker pull opensearchproject/opensearch:3.7.0
docker compose up -d --force-recreate opensearch
```

### Медленный старт

OpenSearch 3.x инициализируется 60–90 секунд. Дождитесь прохождения healthcheck в `docker compose ps`.

### OpenSearch не стартует после обновления

```bash
docker compose down -v
docker compose up -d
```

## Rollback

```bash
# Вернуться к предыдущей версии в docker-compose.yml, например 3.3.2
docker compose down -v
docker compose up -d
```

## Ресурсы

- [OpenSearch 3.7.0 Release Notes](https://github.com/opensearch-project/OpenSearch/releases/tag/3.7.0)
- [Migration Guide](https://docs.opensearch.org/latest/upgrade-to/upgrade-to/)
- [What's New in 3.x](https://opensearch.org/blog/)
- [Breaking Changes](https://github.com/opensearch-project/OpenSearch/blob/main/CHANGELOG.md)

## Checklist

- [ ] Сделан backup данных (если нужно)
- [ ] Остановлен текущий стек
- [ ] Скачаны образы 3.7.0
- [ ] Запущен обновлённый стек
- [ ] Проверена версия (`curl http://localhost:9200`)
- [ ] Проверен Dashboards (http://localhost:5601)
- [ ] Проверена индексация cache-indexer

---

**Версия документа:** 2.0  
**Дата:** Июнь 2026  
**Автор:** BSDM-Proxy Team
