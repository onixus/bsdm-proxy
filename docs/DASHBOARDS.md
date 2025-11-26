# OpenSearch Dashboards - Руководство по использованию

## Доступ к Dashboards

После запуска `docker-compose up -d` OpenSearch Dashboards будет доступен по адресу:

**http://localhost:5601**

## Первый запуск

### 1. Проверка статуса

```bash
# Проверка что Dashboards запущен
docker-compose ps opensearch-dashboards

# Проверка логов
docker-compose logs -f opensearch-dashboards
```

### 2. Создание Index Pattern

1. Откройте http://localhost:5601
2. Перейдите в **Management** → **Index Patterns**
3. Нажмите **Create Index Pattern**
4. Введите паттерн: `http-cache*`
5. Выберите **timestamp** как Time field
6. Нажмите **Create**

## Основные возможности

### Discover - Поиск запросов

Просмотр всех закешированных HTTP-запросов:

1. **Discover** → Выберите `http-cache*`
2. **Фильтры:**
   - По пользователю: `username: "john_doe"`
   - По IP: `client_ip: "192.168.1.100"`
   - По домену: `domain: "api.github.com"`
   - По статус коду: `status: 200`

### Visualize - Создание визуализаций

#### 1. Топ доменов (Столбчатая диаграмма)

1. **Visualize** → **Create Visualization**
2. Выберите **Vertical Bar**
3. Выберите индекс `http-cache*`
4. **Metrics:**
   - Y-axis: Count
5. **Buckets:**
   - X-axis: Terms
   - Field: `domain.keyword`
   - Size: 10
6. **Save**: "Топ-10 доменов"

#### 2. Статус коды (Круговая диаграмма)

1. **Visualize** → **Pie Chart**
2. **Buckets:**
   - Slice: Terms
   - Field: `status`
3. **Save**: "Распределение HTTP статусов"

#### 3. Активность пользователей (Таблица)

1. **Visualize** → **Data Table**
2. **Buckets:**
   - Split Rows: Terms
   - Field: `username.keyword`
   - Order By: Metric Count (Descending)
   - Size: 20
3. **Metrics:**
   - Count
   - Average `request_duration_ms`
   - Sum `response_size`
4. **Save**: "Активность пользователей"

#### 4. Временная линия запросов

1. **Visualize** → **Line Chart**
2. **Metrics:**
   - Y-axis: Count
3. **Buckets:**
   - X-axis: Date Histogram
   - Field: `timestamp`
   - Interval: Auto
4. **Save**: "Запросы по времени"

### Dashboard - Создание дашборда

1. **Dashboard** → **Create Dashboard**
2. **Add** → Выберите созданные визуализации
3. Разместите панели и измените размер
4. **Save**: "BSDM Proxy Analytics"

## Примеры запросов

### Поиск медленных запросов (>1 сек)

```
request_duration_ms:>1000
```

### Поиск ошибок (5xx)

```
status:[500 TO 599]
```

### Поиск по JSON ответам

```
content_type:"application/json" AND status:200
```

### Поиск по конкретному User-Agent

```
user_agent:*Chrome*
```

## Dev Tools - Консоль OpenSearch

Прямой доступ к OpenSearch API:

```json
# Получить статистику индекса
GET /http-cache/_stats

# Агрегация: топ пользователей
GET /http-cache/_search
{
  "size": 0,
  "aggs": {
    "top_users": {
      "terms": {
        "field": "username.keyword",
        "size": 10
      }
    }
  }
}

# Поиск за последний час
GET /http-cache/_search
{
  "query": {
    "range": {
      "timestamp": {
        "gte": "now-1h"
      }
    }
  }
}
```

## Полезные советы

### Настройка временного фильтра

В правом верхнем углу Dashboards выберите:
- **Last 15 minutes** - для real-time мониторинга
- **Last 24 hours** - для анализа дня
- **Last 7 days** - для трендов

### Auto-refresh

Включите автоматическое обновление:
- Нажмите на часы в правом верхнем углу
- Выберите **Auto-refresh** → **10 seconds**

### Экспорт/импорт дашбордов

**Экспорт:**
1. **Management** → **Saved Objects**
2. Выберите дашборд
3. **Export** → скачается JSON

**Импорт:**
1. **Management** → **Saved Objects**
2. **Import**
3. Выберите JSON файл

## Troubleshooting

### Dashboards не запускается

```bash
# Проверка логов
docker-compose logs opensearch-dashboards

# Перезапуск
docker-compose restart opensearch-dashboards
```

### Не видно данных

Проверьте что индекс создан:

```bash
curl "http://localhost:9200/_cat/indices?v"
```

Если `http-cache` отсутствует - проверьте cache-indexer:

```bash
docker-compose logs cache-indexer
```

### Ошибка "No matching indices found"

1. Убедитесь что есть данные в OpenSearch
2. Проверьте Index Pattern в Management
3. Пересоздайте Index Pattern

## Пример готового Dashboard

Скачайте преднастроенный dashboard:

```bash
curl -o bsdm-dashboard.json https://raw.githubusercontent.com/onixus/bsdm-proxy/OSD/dashboards/bsdm-analytics.json
```

Импортируйте через **Management** → **Saved Objects** → **Import**

---

[← Вернуться к README](../README.md)
