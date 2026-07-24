# Roadmap BSDM-Proxy

Текущая версия workspace: **`0.6.1-1`**.

Roadmap описывает порядок работ. Фактическая зрелость реализации определяется
[матрицей статуса](project-status.md), а не отметкой milestone или наличием UI.

## Реализованная основа

### Core proxy

- HTTP forward proxy и CONNECT;
- HTTPS MITM;
- sharded L1, mmap spill, compression и revalidation;
- Redis L2 и cache hierarchy;
- Basic/LDAP/NTLM/Kerberos auth;
- ACL, categorization и rate limiting;
- REST control plane, health и Prometheus metrics.

### Analytics

- Kafka event pipeline;
- cache-indexer;
- ClickHouse schema и retro-search;
- Grafana dashboards;
- alert-worker;
- ML feature store, UEBA/phishing/beacon scoring и threat-score write-back.

### Optional modules

- Lite mode с SQLite;
- local/Qdrant semantic cache;
- DNS sinkhole, DoH и DoT;
- WASM request hook PoC;
- ICAP REQMOD/RESPMOD PoC;
- eBPF/XDP, DLP/CASB, reverse proxy/OIDC и AWG prototypes.

Слово «реализован» для optional-модуля не означает production readiness.

## Ближайший приоритет: стабилизация пилота

### P0 — целостность и безопасность

- [ ] Добавить DLP/CASB columns или миграцию в ClickHouse schema.
- [ ] Добавить постоянный `DLP_ENABLED` и документированный default.
- [ ] Проверять OIDC state, nonce, issuer, audience и JWT signature.
- [ ] Удалить synthetic eBPF counters; читать подтверждённые kernel metrics.
- [ ] Связать AWG control API с реальным lifecycle sidecar/config.
- [ ] Закрыть control/search/metrics endpoints auth и network-policy defaults.

### P1 — воспроизводимый пилот

- [ ] Провести full-path load test: MITM + auth + ACL + Kafka + ClickHouse.
- [ ] Зафиксировать профиль 100 пользователей и retention 5 дней.
- [x] Добавить reproducible pilot Compose overlay.
- [ ] Добавить эквивалентный pilot values-файл для Helm.
- [ ] Проверить backup/restore ClickHouse и CA rotation.
- [ ] Добавить dashboards для Kafka lag, ClickHouse merges и disk pressure.
- [ ] Проверить отдельный процесс на каждую ML-модель.

### P2 — optional modules

- [ ] ICAP resilience и отдельный buffered-response benchmark.
- [ ] Реальный embedding provider contract и Qdrant capacity test.
- [ ] WASM ABI versioning, module signing и richer test suite.
- [ ] DNSSEC/recursive-resolver integration strategy.
- [ ] Admin Console build/deployment и end-to-end control API tests.

## После успешного пилота

### Data-plane HA

- две proxy-реплики за L4 load balancer;
- Redis L2 с явной eviction/persistence policy;
- session/rate-limit semantics между репликами;
- failover test без потери policy enforcement.

### Analytics reliability

- Kafka и ClickHouse topology по требуемому RPO/RTO;
- migrations и schema compatibility;
- backup/restore drills;
- retention и tiered storage по фактическому event volume.

### Multi-cluster

- [x] Добавить local session/threat-sync stores и control API scaffolding.
- global session state;
- threat indicator synchronization;
- cluster identity и mTLS;
- conflict resolution и backpressure.

Scaffolding пока запускается без Redis connection, subscriber и policy
integration. Multi-cluster не считается реализованным до подтверждения
single-cluster operational model и выполнения пунктов выше.

## Дальнейшие исследования

- endpoint tunnel/agent для Windows, macOS и Linux;
- identity-aware access после production-grade OIDC;
- plugin distribution после стабилизации WASM ABI;
- local ML/SLM categorization после определения latency и false-positive budget.

## Правила roadmap

1. Выполненная задача не повышает зрелость функции автоматически.
2. Production-ready требует tests, security review, deployment path, observability
   и rollback.
3. Capacity numbers публикуются вместе с workload assumptions.
4. Исторические release notes не переписываются под текущую архитектуру.
5. Маркетинговые сравнения и неподтверждённые проценты зрелости не являются
   техническим roadmap.
