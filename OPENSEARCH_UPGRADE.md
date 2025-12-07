# OpenSearch 3.3.2 Upgrade Guide

## 🎉 Что нового

### Обновление с 2.11.0 → 3.3.2

**OpenSearch 3.3.2** (декабрь 2025) - последняя стабильная версия

### Основные изменения:

#### 1. **JDK 21** (обязательно)
- OpenSearch 3.x требует Java 21
- В Docker образе уже включен

#### 2. **Lucene 10.1.0**
- Улучшенная производительность индексации
- Оптимизированный поиск

#### 3. **AI/ML улучшения**
- Hybrid search с Z-score normalization
- Memory-optimized Faiss engine
- Improved semantic search

#### 4. **Производительность**
- Увеличена память: 512MB → 1GB
- Лучшее управление ресурсами

## 🚀 Миграция

### Шаг 1: Переключение на ветку

```bash
git fetch origin
git checkout feature/opensearch-3.3
```

### Шаг 2: Остановка старой версии

```bash
# Остановка без удаления данных (если нужно сохранить)
docker-compose down

# ИЛИ полная очистка (для чистой установки)
docker-compose down -v
```

### Шаг 3: Загрузка новых образов

```bash
# Скачивание OpenSearch 3.3.2
docker pull opensearchproject/opensearch:3.3.2
docker pull opensearchproject/opensearch-dashboards:3.3.2

# Проверка
docker images | grep opensearch
```

### Шаг 4: Запуск

```bash
# Запуск с новой версией
docker-compose up -d

# Мониторинг запуска
docker-compose logs -f opensearch
```

### Шаг 5: Проверка

```bash
# Проверка версии
curl http://localhost:9200
```

Ожидаемый вывод:
```json
{
  "name" : "opensearch-node1",
  "cluster_name" : "opensearch-cluster",
  "cluster_uuid" : "...",
  "version" : {
    "number" : "3.3.2",
    "build_type" : "tar",
    "build_hash" : "...",
    "build_date" : "2025-12-XX",
    "build_snapshot" : false,
    "lucene_version" : "10.1.0",
    "minimum_wire_compatibility_version" : "3.0.0",
    "minimum_index_compatibility_version" : "3.0.0"
  },
  "tagline" : "The OpenSearch Project: https://opensearch.org/"
}
```

## 🔍 Сравнение версий

| Параметр | 2.11.0 | 3.3.2 |
|------------|---------|--------|
| **JDK** | 11/17 | 21 (required) |
| **Lucene** | 9.7.0 | 10.1.0 |
| **RAM (min)** | 512MB | 1GB |
| **Дата релиза** | Окт 2023 | Дек 2025 |
| **Support** | EOL скоро | Active |
| **AI/ML** | Базовый | Улучшенный |

## 💡 Новые фичи 3.3.2

### 1. Hybrid Search

Комбинирует keyword + semantic поиск:

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

### 2. Search Relevance Workbench

Инструмент для оптимизации поиска в Dashboards.

### 3. Memory-Optimized Faiss

Улучшенный векторный поиск для ML.

### 4. Improved Dashboards UI

- Обновлённый дизайн
- Быстрее загрузка
- Лучшая визуализация

## ⚠️ Breaking Changes

### 1. JDK 21 обязателен

Если используете собственные плагины - перекомпилируйте под Java 21.

### 2. Увеличены требования к памяти

Минимум: 1GB RAM (вместо 512MB)

### 3. API изменения

Некоторые устаревшие API удалены. Проверьте [changelog](https://github.com/opensearch-project/OpenSearch/releases/tag/3.3.2).

## 🐛 Troubleshooting

### Ошибка: "OutOfMemoryError"

Увеличьте heap size:

```yaml
environment:
  - "OPENSEARCH_JAVA_OPTS=-Xms2g -Xmx2g"
```

### Ошибка: "UnsupportedClassVersionError"

Это означает старый JDK. Пересоберите Docker образ:

```bash
docker pull opensearchproject/opensearch:3.3.2 --no-cache
```

### Медленный старт

OpenSearch 3.x требует больше времени на инициализацию (~60-90 сек).

## 🔙 Rollback

Если что-то пошло не так:

```bash
# Вернуться на main с 2.11.0
git checkout main
docker-compose down -v
docker-compose up -d
```

## 📚 Ресурсы

- [OpenSearch 3.3.2 Release Notes](https://github.com/opensearch-project/OpenSearch/releases/tag/3.3.2)
- [Migration Guide](https://opensearch.org/docs/latest/upgrade-to/upgrade-to/)
- [What's New in 3.x](https://opensearch.org/blog/)
- [Breaking Changes](https://github.com/opensearch-project/OpenSearch/blob/main/CHANGELOG.md)

## ✅ Checklist

- [ ] Сделан backup данных (если нужно)
- [ ] Остановлена старая версия
- [ ] Скачаны образы 3.3.2
- [ ] Запущена новая версия
- [ ] Проверена версия (curl)
- [ ] Проверен Dashboards (UI)
- [ ] Проверена индексация

---

**Версия:** 1.0  
**Дата:** Декабрь 2025  
**Автор:** BSDM-Proxy Team
