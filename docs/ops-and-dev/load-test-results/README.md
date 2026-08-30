# Hybrid Load-Test Results Archive

Каталог отчетов нагрузочного тестирования гибридного профиля BSDM-Proxy (Issue #269, #326).
Отчеты генерируются автоматически скриптом [`scripts/run-hybrid-load-test.sh`](../../../scripts/run-hybrid-load-test.sh) и служат доказательной базой для приемочных испытаний (Go/No-Go решения по пилоту).

---

## 1. Структура каталога

| Файл | Описание |
|---|---|
| [`latest.md`](latest.md) | Актуальная копия последнего эталонного прогона на пилотном профиле |
| [`20260830T210000Z.md`](20260830T210000Z.md) | **Эталонный отчет Phase 2 Scale** (100 пользователей, 60с, 307.5 RPS, Selective MITM) |
| [`20260804T132958Z.md`](20260804T132958Z.md) | Исторический отчет Phase 1 Baseline (20 пользователей, 16с, старт пилота) |

> **Правило фиксации:** В репозиторий коммитятся только верифицированные эталонные прогоны, документирующие базовые профили пилота или CI baseline. Не коммитьте шумные локальные прогоны с нестабильным публичным upstream.

---

## 2. Сводная таблица эталонных прогонов

| Snapshot | Дата (UTC) | Профиль / Фаза | Конкурентные пользователи | Длительность | Throughput (Proxy RPS) | Error Rate | Latency p95 / p99 | MITM Mix (Metrics) | Вердикт SLO |
|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| [`latest.md`](latest.md) / [`20260830T210000Z.md`](20260830T210000Z.md) | 2026-08-30 | **Phase 2 Scale (Pilot Peak)** | **100** | **60.0 s** | **307.5 req/s** | **0.21%** | **4.8 ms / 8.9 ms** | 15.0% MITM / 80.0% SNI / 5.0% DNS | **PASS (GO)** |
| [`20260804T132958Z.md`](20260804T132958Z.md) | 2026-08-04 | Phase 1 Baseline (Day 1) | 20 | 16.4 s | 156.4 req/s | 4.94% | 3.1 ms / 3.7 ms | 16.6% MITM / 83.4% SNI | PASS (Soft) |

---

## 3. Схема отчета и источники метрик

Каждый отчет содержит стандартизированные поля:

| Поле в отчете | Источник данных | Описание |
|---|---|---|
| `Timestamp (UTC)` | `$RUN_ID` / `date -u +%Y%m%dT%H%M%SZ` | Идентификатор запуска и метка времени |
| `Concurrent users` | `$CONCURRENT_USERS` | Количество параллельных воркеров-клиентов |
| `Duration (s)` | Wall-clock time | Фактическое время выполнения нагрузочного цикла |
| `Traffic mix target` | `PCT_SNI` / `PCT_MITM` / `PCT_DNS` | Целевое клиентское распределение запросов (дефолт 80/15/5) |
| `Client OK / ERR` | Client curl / dig status | Число успешных (2xx/3xx/DNS ok) и сбойных запросов |
| `Error rate (%)` | `100 * ERR / TOTAL` | Доля ошибок клиента |
| `Proxy requests (Δ)` | `Δ bsdm_proxy_requests_total` | Прирост счетчика обработанных прокси-запросов |
| `Proxy RPS` | `Δ requests / Duration` | Реальная средняя производительность прокси |
| `Cache hits (Δ)` | `Δ bsdm_proxy_cache_hits_total` | Число попаданий в L1/L2 кэш |
| `Latency p50/p95/p99 (ms)` | Client `curl -w %{time_total}` | Перцентили задержки «клиент — прокси — апстрим» |
| `decision_source * (Δ)` | `Δ bsdm_proxy_policy_decision_source_total` | Реальное распределение решений политики (`sni`, `mitm`, `dns`, `pinning-bypass`) |
| `Host / stack notes` | `docker stats --no-stream` | Снимок утилизации CPU/RAM контейнерами |

---

## 4. Критерии приемки по SLO (Pilot Pass/Fail Gate)

Для перехода пилота в статус **GO** результаты в [`latest.md`](latest.md) должны удовлетворять следующим порогам:

```text
+------------------------------------+--------------------------+-----------------------+
| Критерий                           | Порог SLO                | Результат 100-User    |
+------------------------------------+--------------------------+-----------------------+
| Error Rate                         | < 0.5% (строгий)         | 0.21%       [PASS]    |
| Latency p95 (cached/fast path)     | <= 10.0 ms               | 4.8 ms      [PASS]    |
| Latency p99 (selective-MITM)       | <= 50.0 ms               | 8.9 ms      [PASS]    |
| Proxy RPS (sustained)              | >= 50-100 req/s          | 307.5 req/s [PASS]    |
| Decision source skew               | Без аномальных утечек    | Совпадает   [PASS]    |
| Proxy CPU (пик)                    | < 70%                    | 22.4%       [PASS]    |
| Host RAM / Swap                    | < 80% RAM, 0 B swap      | 28.7%, 0 B  [PASS]    |
| Health Probes                      | 100% 200 OK              | OK          [PASS]    |
+------------------------------------+--------------------------+-----------------------+
```

---

## 5. Связанная документация

- [Методология и запуск гибридного теста](../load-test-selective-mitm.md)
- [Чек-лист решения Pilot Go/No-Go (раздел 2.1 Performance)](../pilot-go-no-go-template.md)
- [Развертывание пилотного стенда](../../getting-started/pilot-deployment.md)
- [Сайзинг и планирование мощностей](../../architecture/capacity-planning.md)
