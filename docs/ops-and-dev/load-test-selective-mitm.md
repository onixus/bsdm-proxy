# Load Test Profile: Selective MITM + DNS + Auth (Issue #269)

Reproducible Hybrid pilot profile for ~100 concurrent users.

**Related:** [Pilot deployment](../getting-started/pilot-deployment.md) ·
[Pilot DNS](../getting-started/pilot-dns.md) ·
[`scripts/run-hybrid-load-test.sh`](../../scripts/run-hybrid-load-test.sh) ·
results under [`load-test-results/`](load-test-results/).

---

## Goals

1. Exercise the recommended Hybrid path: **SNI-first + Selective MITM + DNS** (pilot day-1 UDP sinkhole).
2. Produce **latency (p50/p95/p99)**, **error rate**, **decision_source mix**, and **proxy RPS**.
3. Be re-runnable from a laptop or CI (lite stack) and from a full pilot compose (+ DNS smoke).

This is a **pilot capacity probe**, not a vendor-grade SLA certification.

---

## Traffic mix (default)

| Share | Path | How the script drives it |
|---|---|---|
| **80%** | SNI / non-MITM HTTPS (or HTTP fallback) | `SNI_URL` (default `https://httpbin.org/get`) |
| **15%** | Selective MITM candidate | `MITM_URL` (default `https://httpbin.org/anything/phishing`) |
| **5%** | DNS sinkhole (UDP :5353) | `dig @DNS_HOST -p DNS_PORT DNS_QNAME` — smoke: [pilot-dns.md](../getting-started/pilot-dns.md) |

Percentages are client-side dice rolls (`PCT_SNI` / `PCT_MITM` / `PCT_DNS`).  
Actual **policy** mix is read from Prometheus counters:

`bsdm_proxy_policy_decision_source_total{source="sni|mitm|dns|pinning-bypass"}`.

MITM only occurs when proxy policy classifies the host into `MITM_CATEGORIES`
(or when categorization/UT1 maps the domain to those categories). Without
categorization, most HTTPS may stay on the SNI path — that is expected and
should be reflected in the results table.

---

## Assumptions

| Assumption | Default / notes |
|---|---|
| Concurrent workers | 100 (`CONCURRENT_USERS`) |
| Duration | 30s CI / 60–300s pilot (`TEST_DURATION`) |
| Auth | Off by default; set `BASIC_AUTH=user:pass` when `AUTH_ENABLED=true` |
| CA | `certs/ca.crt` for MITM trust on the client |
| Retention | Pilot ClickHouse/Prometheus ≤ 5 days (see pilot compose) |
| Upstream RTT | Client latency **includes** public upstream (httpbin) unless you point at a local mock |
| Experimental modules | **Off** (no ICAP / AWG / eBPF / WASM in this profile) |

---

## How to run

### A. Phase 1: 20-User Baseline Profile (Day 1–14)

Рекомендуемый стартовый профиль для начала пилота (20 пользователей):

```bash
CONCURRENT_USERS=20 TEST_DURATION=60 \
  RESULTS_DIR=docs/ops-and-dev/load-test-results \
  ./scripts/run-hybrid-load-test.sh
```

### B. Phase 2: 100-User Scale Profile (Day 15–28)

Пиковая нагрузка 100 пользователей:

```bash
CONCURRENT_USERS=100 TEST_DURATION=120 \
  RESULTS_DIR=docs/ops-and-dev/load-test-results \
  ./scripts/run-hybrid-load-test.sh
```

### C. Lite stack (CI / laptop)

```bash
./scripts/gen-ca.sh
docker compose -f deploy/compose/docker-compose.lite.yml up -d --build
# wait for health
curl -fsS http://127.0.0.1:9090/health

# DNS share needs dig + sinkhole (full compose). Lite has no DNS — 5% share degrades.
CONCURRENT_USERS=20 TEST_DURATION=30 \
  ./scripts/run-hybrid-load-test.sh
```

### D. Full pilot compose (Hybrid stack)

```bash
export CONTROL_API_TOKEN="$(openssl rand -hex 16)"
export ACL_API_TOKEN="$(openssl rand -hex 16)"
export SEARCH_API_TOKEN="$(openssl rand -hex 16)"

./scripts/gen-ca.sh
docker compose -f docker-compose.yml -f deploy/compose/docker-compose.pilot.yml up -d --build

./scripts/run-dns-pilot-smoke.sh   # dig @127.0.0.1 -p 5353

DNS_HOST=127.0.0.1 DNS_PORT=5353 DNS_QNAME=badsite.test \
CONCURRENT_USERS=100 TEST_DURATION=60 \
  RESULTS_DIR=docs/ops-and-dev/load-test-results \
  ./scripts/run-hybrid-load-test.sh
```

### E. Auth-enabled pass

```bash
# Proxy: AUTH_ENABLED=true + BASIC_AUTH_USERS_FILE (see pilot-auth.md)
# Smoke first:
#   AUTH_USER=pilot AUTH_PASS=… ./scripts/run-auth-pilot-smoke.sh
BASIC_AUTH='pilot:your-strong-password' \
CONCURRENT_USERS=100 TEST_DURATION=60 \
  RESULTS_DIR=docs/ops-and-dev/load-test-results \
  ./scripts/run-hybrid-load-test.sh
```

### F. Isolated / Offline Mock Upstream Mode (Lab & CI)

Для изолированных сред без доступа к публичному интернету (`httpbin.org`) или для исключения сетевого джиттера внешних апстримов:

```bash
# 1. Запуск локального многопоточного mock upstream в фоне:
python3 scripts/mock-upstream-threaded.py &
MOCK_PID=$!

# 2. Запуск нагрузочного теста через локальный mock:
SNI_URL="http://127.0.0.1:18080/get" \
MITM_URL="http://127.0.0.1:18080/get" \
HTTP_URL="http://127.0.0.1:18080/get" \
CONCURRENT_USERS=100 TEST_DURATION=60 \
RESULTS_DIR=docs/ops-and-dev/load-test-results \
  ./scripts/run-hybrid-load-test.sh

# 3. Остановка mock upstream:
kill $MOCK_PID 2>/dev/null || true
```

### Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `PROXY` | `http://127.0.0.1:3128` | Proxy URL |
| `METRICS_URL` | `http://127.0.0.1:9090` | Control/metrics base |
| `CONCURRENT_USERS` | `100` | Parallel workers |
| `TEST_DURATION` | `30` | Seconds (use `60`–`120` for pilot acceptance) |
| `CA_CERT` | `certs/ca.crt` | Trust store for MITM validation |
| `BASIC_AUTH` | empty | `user:pass` for Basic auth testing |
| `PCT_SNI` / `PCT_MITM` / `PCT_DNS` | 80 / 15 / 5 | Client request distribution mix |
| `SNI_URL` / `MITM_URL` / `HTTP_URL` | httpbin defaults | Upstream probe endpoints |
| `DNS_HOST` / `DNS_PORT` / `DNS_QNAME` | 127.0.0.1 / 5353 / badsite.test | DNS sinkhole probe settings |
| `RESULTS_DIR` | `docs/ops-and-dev/load-test-results` | Output folder for markdown reports |
| `WRITE_RESULTS` | `1` | Write markdown report (`<run-id>.md` and `latest.md`) |
| `STRICT` | `0` | Exit with code 2 if error rate > 5% |

---

## Metrics collected

| Metric | Source |
|---|---|
| Latency p50 / p95 / p99 (ms) | Client `curl -w %{time_total}` |
| Error rate (%) | Client success/fail counters |
| Proxy RPS | Δ `bsdm_proxy_requests_total` / duration |
| Cache hits | Δ `bsdm_proxy_cache_hits_total` |
| decision_source mix | Δ `bsdm_proxy_policy_decision_source_total` |
| Resource usage | `docker stats` snapshot in result file |

---

## SLO Acceptance Criteria (Pilot Go/No-Go Gate)

| Check / Metric | Pilot SLO Threshold | Description |
|---|---|---|
| **Health Stability** | `/health` OK before and after | Прокси сохраняет работоспособность без паник и утечек |
| **Error Rate** | < 0.5% (strict) / < 5.0% (soft) | Доля сетевых и HTTP-ошибок под полной нагрузкой |
| **Latency p95 (HIT)** | ≤ 10.0 ms | Добавленная задержка на fast/cache HIT пути |
| **Latency p99 (MITM)** | ≤ 50.0 ms | Добавленная задержка на селективном TLS MITM пути |
| **Throughput (RPS)** | ≥ 50–100 req/s | Устойчивая пропускная способность при 100 параллельных пользователях |
| **Decision Source Mix** | 80% SNI / 15% MITM / 5% DNS | Соответствие трафика политике без утечек в `pinning-bypass` |
| **Host Resources** | CPU < 70%, RAM < 80%, swap = 0 | Отсутствие деградации узла под пиковой нагрузкой |

---

## Operator Troubleshooting Matrix

| Симптом | Возможная причина | Решение |
|---|---|---|
| `❌ Proxy is not healthy` | Прокси не запущен или упал | Проверьте `docker compose logs proxy` или запустите `make run` / `./scripts/gen-ca.sh` |
| `⚠ CA cert not found` | Отсутствует MITM CA сертификат | Сгенерируйте CA командой `./scripts/gen-ca.sh` |
| Высокий Error Rate (>5%) на DNS | `dns-sinkhole` не отвечает на `:5353` | Проверьте запуск сайдкара: `./scripts/run-dns-pilot-smoke.sh` |
| Высокая задержка p95/p99 (>100ms) | Джиттер публичного upstream `httpbin.org` | Используйте локальный mock-режим: `scripts/mock-upstream-threaded.py` |
| Все запросы попадают в `sni` | Не настроена категоризация или ACL | Проверьте `POLICY_MODE=selective-mitm` и `MITM_CATEGORIES` |

---

## Results archive

Each run with `WRITE_RESULTS=1` writes:

```
docs/ops-and-dev/load-test-results/<UTC-timestamp>.md
docs/ops-and-dev/load-test-results/latest.md
```

See [load-test-results/README.md](load-test-results/README.md).

---

## CI

`.github/workflows/load-test.yml` runs:

1. Standard `scripts/run-load-test.sh` against lite + mock-upstream.
2. Hybrid profile `scripts/run-hybrid-load-test.sh` (reduced users/duration for wall-clock).

---

## Related issues

- #269 — this load-test profile
- #270 — pilot compose + acceptance criteria
