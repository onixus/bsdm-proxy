# Пилот: Threat Intelligence в режиме Shadow (Hybrid Profile)

Руководство по развертыванию, наблюдению и сбору телеметрии Threat Intelligence в **теневом режиме (Shadow Mode)** в рамках функционального пилота **Hybrid Policy** (Selective MITM + DNS Sinkhole + Threat Intel).

Связанные документы:
- [Архитектурное решение ADR 0008: Threat Intel Shadow Mode](../adr/0008-threat-intel-shadow-mode.md)
- [Пилотное развертывание Hybrid Policy](pilot-deployment.md)
- [Описание коллектора фидов угроз](../features/threat-intel-collector.md)
- [Шаблон решения Go/No-Go (Секция 2.4)](../ops-and-dev/pilot-go-no-go-template.md)
- [Нагрузочный профиль Selective MITM](../ops-and-dev/load-test-selective-mitm.md)

---

## 1. Архитектура и цели Shadow Mode

В соответствии с [ADR 0008](../adr/0008-threat-intel-shadow-mode.md) в пилотной эксплуатации все внешние фиды индикаторов компрометации (IOC) функционируют **исключительно в режиме наблюдения (Shadow Mode)**:

1. **Никакой слепой блокировки (Zero False-Positive Outage)**: Сторонние фиды угроз часто содержат ложные срабатывания (CDN, Shared Hosting, популярные облачные сервисы). В режиме `shadow` совпадения не обрывают сессии пользователей.
2. **Обогащение событий (Event Enrichment)**: При совпадении домена или URL запроса с базой угроз ядро `proxy` (`ti_shadow.rs`) выставляет флаг `threat_shadow_match = 1` и проставляет метку источника фида (`threat_feed`) в поток событий `CacheEvent` (Kafka → ClickHouse).
3. **Генерация теневых артефактов**: Компилятор зон генерирует файлы с суффиксом `.shadow` (`threats.rpz.shadow` и `threat_domains.json.shadow`), изолируя их от боевого data-plane enforcement.
4. **Валидация качества**: За 14-дневное окно наблюдения оператор и SOC оценивают точность источников фидов и верифицируют отсутствие пересечений с корпоративным Allowlist.

```
                    Входящий трафик (DNS/HTTP/TLS)
                               │
                ┌──────────────┴──────────────┐
                │        bsdm-proxy           │
                │  (POLICY_MODE=selective-mitm│
                │   TI_SHADOW_MATCH=true)     │
                └──────────────┬──────────────┘
                               │
            ┌──────────────────┼──────────────────┐
            ▼                                     ▼
   Трафик пропускается               Событие в аналитику
   (200 OK / Selective MITM)        threat_shadow_match = 1
                                    threat_feed = "openphish"
                                    bsdm_proxy_ti_shadow_matches_total++
```

---

## 2. Развертывание пилотного контура

Запуск сервиса `threat-intel` в режиме `shadow` интегрирован в базовый `docker-compose.yml` и оверлей [docker-compose.pilot.yml](../../deploy/compose/docker-compose.pilot.yml) через Docker-профиль `threat-intel`.

### 2.1 Подготовка переменных окружения

```bash
# Обязательные токены безопасности Control Plane
export CONTROL_API_TOKEN="$(openssl rand -hex 24)"
export ACL_API_TOKEN="$(openssl rand -hex 24)"
export SEARCH_API_TOKEN="$(openssl rand -hex 24)"

# Токен для защищенного SOAR API коллектора угроз
export TI_API_TOKEN="$(openssl rand -hex 24)"

# Фиксация режима Shadow
export TI_ENFORCEMENT_MODE=shadow
export POLICY_MODE=selective-mitm
```

### 2.2 Команда запуска стека

```bash
docker compose \
  -f docker-compose.yml \
  -f deploy/compose/docker-compose.pilot.yml \
  --profile threat-intel \
  up -d --build
```

### 2.3 Конфигурация по умолчанию в пилоте

| Параметр | Значение | Назначение |
|---|:---:|---|
| `TI_ENFORCEMENT_MODE` | `shadow` | Запись артефактов `.shadow` без активного блокирования |
| `TI_SOURCES` | `openphish,phishstats,phishing_database,urlhaus` | Активные источники фидов |
| `TI_POLL_INTERVAL_SECS` | `900` (15 мин) | Периодичность обновления индикаторов |
| `TI_SHADOW_MATCH_ENABLED` | `true` | Включение теневого матчера в прокси (`proxy`) |
| `TI_SHADOW_FEED_PATH` | `/var/lib/bsdm-proxy/threat-intel/threat_domains.json.shadow` | Путь к теневому экспорту фидов |
| `TI_SHADOW_RELOAD_SECS` | `300` (5 мин) | Периодичность перечитывания файла теневых фидов ядром |

---

## 3. Проверка готовности (Smoke Validation)

Перед подачей пилотного трафика выполните проверку ключевых точек:

1. **Healthcheck коллектора**:
   ```bash
   curl -fsS http://127.0.0.1:8093/health
   # Ответ: {"status":"ok",...}
   ```

2. **Проверка статуса режима в метриках**:
   ```bash
   curl -fsS http://127.0.0.1:8093/metrics | grep "threat_intel_enforcement_mode"
   # Ожидаемый вывод:
   # threat_intel_enforcement_mode{mode="shadow"} 1
   # threat_intel_enforcement_mode{mode="enforce"} 0
   ```

3. **Проверка генерации артефактов**:
   ```bash
   docker compose exec proxy ls -la /var/lib/bsdm-proxy/threat-intel/
   # В каталоге должны присутствовать:
   # - threats.rpz.shadow
   # - threat_domains.json.shadow
   # - report.json
   ```

4. **Проверка сквозного теневого матчинга**:
   ```bash
   # Выполните запрос через прокси к домену, присутствующему в теневом фиде
   # Запрос должен успешно пройти (HTTP 200), не вызывая 403 Forbidden:
   curl -x http://127.0.0.1:3128 http://httpbin.org/get

   # Проверьте счетчик теневых совпадений:
   curl -fsS http://127.0.0.1:9090/metrics | grep "bsdm_proxy_ti_shadow_matches_total"
   ```

---

## 4. Сбор телеметрии и мониторинг

### 4.1 Ключевые метрики Prometheus

Скрейпинг выполняется с `:9090/metrics` (ядро proxy) и `:8093/metrics` (threat-intel):

- **Качество сбора фидов**:
  - `threat_intel_fetches_total{source, result="ok|http_error|parse_error"}` — успешность раундов опроса.
  - `threat_intel_indicators_total{source, kind}` — объем активных индикаторов.
  - `threat_intel_last_success_timestamp_seconds{source}` — отсутствие "залипания" сбора.
  - `threat_intel_stored_indicators` — размер активной базы в SQLite.
- **Теневой матчинг на Data Plane**:
  - `bsdm_proxy_ti_shadow_matches_total{feed}` — количество совпадений трафика с фидами.
- **DNS Sinkhole**:
  - `bsdm_dns_sinkhole_blocked_total` — срабатывания первого рубежа до прокси.

### 4.2 Аналитические запросы в ClickHouse

Подключение к клиенту:
```bash
docker compose exec clickhouse clickhouse-client
```

1. **Сводка теневых сработок по источникам фидов за последние 24 часа**:
   ```sql
   SELECT 
       threat_feed,
       count() AS total_matches,
       uniqExact(domain) AS unique_domains,
       uniqExact(client_ip) AS affected_clients
   FROM bsdm.cache_events
   WHERE threat_shadow_match = 1 
     AND timestamp > now() - INTERVAL 1 DAY
   GROUP BY threat_feed
   ORDER BY total_matches DESC;
   ```

2. **Топ-20 доменов с теневыми совпадениями для аудита ложных срабатываний**:
   ```sql
   SELECT 
       domain,
       threat_feed,
       count() AS hits,
       any(url) AS sample_url,
       min(timestamp) AS first_seen,
       max(timestamp) AS last_seen
   FROM bsdm.cache_events
   WHERE threat_shadow_match = 1 
     AND timestamp > now() - INTERVAL 7 DAY
   GROUP BY domain, threat_feed
   ORDER BY hits DESC
   LIMIT 20;
   ```

3. **Проверка на пересечение с корпоративными белыми списками (Allowlist)**:
   ```sql
   SELECT domain, threat_feed, count() AS hits
   FROM bsdm.cache_events
   WHERE threat_shadow_match = 1 
     AND acl_action = 'allow'
     AND timestamp > now() - INTERVAL 7 DAY
   GROUP BY domain, threat_feed;
   -- В идеальном профиле запрос должен возвращать 0 строк либо известные исключения.
   ```

---

## 5. SOC-триаж ложных срабатываний в Admin Console

Оператор и дежурный инженер ИБ используют встроенную консоль управления (`http://localhost:9090/admin/`):

1. **Threat Investigation Modal (`ThreatInvestigationModal.tsx`)**:
   - При обнаружении подозрительного индикатора в логах вызовите карточку расследования.
   - Проверьте дату добавления, уровень доверия (`confidence_score`), теги и цепочку источников фидов.
   - При выявлении ложного срабатывания (False Positive) воспользуйтесь кнопкой **Whitelist Domain** — домен мгновенно добавляется в административный Allowlist с наивысшим приоритетом.
2. **ML Domain Inspector (`MlDomainInspector.tsx`)**:
   - Проверка лексических аномалий, энтропии доменного имени, расстояния Дамерау-Левенштейна до корпоративных брендов и поиск гомоглифов (Unicode confusables).
3. **RPZ Live Status (`RpzManagement.tsx`)**:
   - Контроль серийного номера зоны SOA BIND, количества скомпилированных правил и статуса отката (`rollback`).

---

## 6. Чек-лист завершения пилота и переход к Enforce

Для принятия решения о включении активной блокировки (`TI_ENFORCEMENT_MODE=enforce`) по окончании пилотного окна заполняется **Секция 2.4 шаблона [pilot-go-no-go-template.md](../ops-and-dev/pilot-go-no-go-template.md)**:

- [ ] Период непрерывного наблюдения в Shadow Mode составил **не менее 14 дней**.
- [ ] Отсутствуют пробелы в сборе фидов (`threat_intel_last_success_timestamp_seconds` актуален).
- [ ] Доля подтвержденных ложных срабатываний (False Positives) по каждому фиду **< 1%**.
- [ ] Количество совпадений с критическими бизнес-системами компании равно **0**.
- [ ] Тройной защитный барьер Triple-Gate (`ti_enforce.rs`) протестирован на стенде.
- [ ] Протокол Go/No-Go подписан руководителем ИБ.
