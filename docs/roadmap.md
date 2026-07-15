# Roadmap BSDM-Proxy

Целевое состояние проекта:

> **Альтернатива Squid с ретропоиском и ML для выявления отклонений, фишинга и C&C**

| Столп | Описание |
|-------|----------|
| **Squid parity** | Forward proxy, кеш, ACL, auth, иерархия, rate limiting |
| **Ретропоиск** | Поиск и аналитика по историческому HTTP-трафику |
| **ML-безопасность** | Аномалии, фишинг и C&C поверх логов и поведенческих сигналов |

Текущая версия: **0.3.2** · [Releases](https://github.com/onixus/bsdm-proxy/releases) · [CHANGELOG](../CHANGELOG.md)

---

## Обзор milestones

| Milestone | Версия | Фокус | Готовность |
|-----------|--------|-------|------------|
| [M1 — Foundation](#m1--foundation-v02x) | v0.2.x | Ядро прокси, ACL, observability | ✅ Done |
| [M2 — Squid parity](#m2--squid-parity-v03x) | v0.3.x | L2, ACL, hierarchy, auth, compression | ✅ Done |
| [M2.5 — Data plane](#m25--data-plane-throughput-v03x) | v0.3.x–0.3.2 | Tiered L1, streaming, P1 hot path | ✅ Done |
| [M3 — Retro-search](#m3--retro-search) | v0.3.1+ | ClickHouse, Search API, Grafana, k8s CHI | ✅ Done (~95%) |
| [M4 — Threat analytics](#m4--threat-analytics-v05x) | v0.5.x | Rule-based угрозы, алерты, C&C heuristics | ~15% |
| [M5 — ML security](#m5--ml-security-v10x) | v1.0.x | ML anomaly, phishing, C&C ML | ~0% |

```mermaid
gantt
  title Roadmap milestones
  dateFormat YYYY-MM
  section Proxy
  M1 Foundation           :done, m1, 2025-10, 2026-03
  M2 Squid parity         :done, m2, 2026-03, 2026-06
  M2.5 Data plane perf    :done, m25, 2026-06, 2026-07
  section Analytics
  M3 Retro-search         :done, m3, 2026-05, 2026-07
  M4 Threat analytics     :active, m4, 2026-07, 2026-11
  section ML
  M5 ML security          :m5, 2026-10, 2027-03
```

---

## M1 — Foundation (v0.2.x)

Базовый корпоративный HTTPS-прокси. **✅ Завершён** (v0.2.3-test).

<details>
<summary>Выполнено</summary>

- [x] Hyper forward proxy + HTTP CONNECT, MITM TLS
- [x] L1 cache, Kafka events, Prometheus + Grafana
- [x] Auth Basic/LDAP, ACL, categorization, E2E harness
- [x] Hierarchy Phase 3, rate limit [#37](https://github.com/onixus/bsdm-proxy/issues/37), `ProxyService` refactor [#38](https://github.com/onixus/bsdm-proxy/issues/38)

*(Исторически analytics писался в OpenSearch; с v0.3.1 — только ClickHouse.)*

</details>

---

## M2 — Squid parity (v0.3.x)

**✅ Завершён** (v0.3.0).

- [x] Hierarchy Phase 4 — peer discovery, cache digest, HTCP
- [x] Redis L2, HTTP/2 upstream, at-rest compression
- [x] ACL TimeWindow / REST API, NTLM / Kerberos / LDAP groups
- [x] Negative cache, ETag revalidation, `bsdm-events`, HTTP Archive benches

---

## M2.5 — Data plane throughput (v0.3.x–0.3.2)

**✅ Завершён** (P0 + P1 в v0.3.1–0.3.2). Gate warm goodput vs Squid — bench validation.

- [x] Tiered L1, streaming MISS, auth/policy caches, spill perms
- [x] k8s / Helm docs, HTTP Archive bench profiles
- [x] Fast cache path, Kafka bounded queue, offline categorization, ACL precompile ([#100](https://github.com/onixus/bsdm-proxy/issues/100)–[#109](https://github.com/onixus/bsdm-proxy/issues/109))

---

## M3 — Retro-search

Ретроспективный поиск по HTTP-трафику. **✅ Готов** (эпik [#125](https://github.com/onixus/bsdm-proxy/issues/125) фазы 0–5).

```
proxy → Kafka → cache-indexer → ClickHouse (bsdm.http_cache)
                                  ↓
                    Grafana SQL + /api/search (JSON/CSV)
```

### Задачи

- [x] Event schema — `categories`, `acl_action`, `threat_sources`, `session_id`, redirect chain
- [x] ClickHouse schema + indexer (JSONEachRow)
- [x] Grafana **BSDM HTTP Traffic** + Search API
- [x] Default `docker compose up` на ClickHouse; OpenSearch backend удалён
- [x] Session correlation, SOC export (`format=csv|json`)
- [x] k8s ClickHouse Operator / Helm indexer ([#135](https://github.com/onixus/bsdm-proxy/issues/135))

### Оставшийся gap (не блокирует M3)

- Soft `session_id` пока per-node (не shared между репликами)
- Production soak CHI / Operator в реальном кластере

**Критерий:** «кто ходил на domain X за 30 дней» — Grafana/CH или `/api/search` — **выполнен**.

---

## M4 — Threat analytics (v0.5.x)

Rule-based обнаружение угроз поверх ClickHouse.

- [x] Schema enrichment / blocked threat events in CH ([#102](https://github.com/onixus/bsdm-proxy/issues/102))
- [x] Categorization Prometheus metrics ([#105](https://github.com/onixus/bsdm-proxy/issues/105))
- [x] Starter threat panels + SQL (`scripts/clickhouse/m4_threat_queries.sql`)
- [ ] Rule-based alerts (Grafana / webhook)
- [ ] C&C heuristics (beacon, high-entropy domains)
- [ ] Alerting pipeline to SIEM ([#50](https://github.com/onixus/bsdm-proxy/issues/50))
- [ ] PhishTank API key wiring

**Критерий:** автоалерт на beacon-паттерн + threat dashboard.

---

## M5 — ML security (v1.0.x)

- [ ] Feature store, anomaly / phishing / C&C ML, optional inline score

---

## Матрица зрелости

| Столп | Сейчас (0.3.2) | После M4 | После M5 |
|-------|----------------|----------|----------|
| Squid parity | **~92%** | ~92% | ~93% |
| Ретропоиск | **~90%** | ~92% | ~95% |
| ML / C&C / phishing | ~10% | ~25% | ~75% |
| **Итого** | **~65%** | ~70% | ~85% |

---

## GitHub milestones

| Milestone | Версия | Issues |
|-----------|--------|--------|
| M1 Foundation | 0.2.x | #37, #38, #44 |
| M2 Squid parity | 0.3.x | hierarchy, L2, ACL API |
| M2.5 Data plane | 0.3.1–0.3.2 | #94–#109 |
| M3 Retro-search | 0.3.1+ | #114, #125, #135 |
| M4 Threat analytics | 0.5.x | #50, #105 |
| M5 ML security | 1.0.x | — |

Backlog mapping: [swg-backlog-mapping.md](swg-backlog-mapping.md)

---

## Связанные документы

| Документ | Тема |
|----------|------|
| [architecture.md](architecture.md) | Компоненты, блокеры |
| [adr/0002-clickhouse-analytics.md](adr/0002-clickhouse-analytics.md) | ClickHouse ADR |
| [clickhouse-analytics.md](clickhouse-analytics.md) | Compose + SQL |
| [search-api.md](search-api.md) | `/api/search` |
| [categorization.md](categorization.md) | UT1 + metrics |
| [k8s-architecture.md](k8s-architecture.md) | K8s / CHI |
| [performance.md](performance.md) | Perf tuning |

---

*Обновлено: 2026-07 — M2.5/M3 done, M4 started (cat metrics), docs cleanup*
