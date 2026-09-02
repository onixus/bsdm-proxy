# Pilot alerts pack (alert-worker)

Day-2+ pilot observability: rule-based findings from ClickHouse → webhook.
Not required for day-1 stand-up; enable after proxy + analytics are healthy.

Related: [alerting.md](../analytics/alerting.md) ·
[pilot-deployment.md](pilot-deployment.md) ·
Grafana dashboard `bsdm-proxy` panel **Policy Decision Sources**.

---

## What operators should see without PromQL

| Surface | What |
|---|---|
| Admin Console → **Dashboard** | Segment bar **Hybrid decision_source** (dns/sni/mitm/pin) from `/metrics` |
| Admin Console → **Logs** | Filter `decision_source` (server + client) |
| Grafana → BSDM Proxy | Time series `sum(rate(bsdm_proxy_policy_decision_source_total[5m])) by (source)` |
| Grafana → BSDM Threat Intelligence (Shadow) | Posture stats (`shadow`/`ENFORCE`), `sum(rate(bsdm_proxy_ti_shadow_matches_total[5m])) by (feed)`, ClickHouse FP-review table over `threat_shadow_match` |
| alert-worker | Webhook JSON for deny/domain bursts (pilot rule subset) |

---

## Enable alert-worker (compose)

```bash
# Lab webhook
python3 scripts/alert-worker/webhook-echo.py 9080 &

export ALERT_WEBHOOK_URL=http://host.docker.internal:9080/hooks/siem
# Or use the pilot pack defaults:
# set -a; source config/pilot-alert.env.example; set +a

docker compose -f docker-compose.yml -f deploy/compose/docker-compose.pilot.yml \
  --profile alerts up -d --build alert-worker

curl -fsS http://127.0.0.1:8090/health
```

### Pilot rule pack

Default full set is noisy for a small pilot. Prefer:

```bash
ALERT_RULES=blocked_burst,domain_burst,off_hours_threat
ALERT_BLOCKED_BURST_THRESHOLD=10
ALERT_DOMAIN_BURST_THRESHOLD=80
```

See `config/pilot-alert.env.example`. Full rule catalogue: [alerting.md](../analytics/alerting.md).

| Rule | Why for pilot |
|---|---|
| `blocked_burst` | ACL deny flood (misconfig / attack) |
| `domain_burst` | Single client hammering one domain |
| `off_hours_threat` | Threat-tagged activity outside business hours (UTC window) |

Optional later: `high_entropy_domain`, `beacon_periodic` (more ML/noise).

---

## Acceptance checklist

- [ ] Dashboard shows decision_source bar after traffic (or honest empty state)
- [ ] Logs can filter `decision_source=sni|mitm|…`
- [ ] Grafana panel «Policy Decision Sources» loads when Prometheus scrapes proxy
- [ ] Grafana dashboard «BSDM Threat Intelligence (Shadow)» shows both posture stats as `shadow` and «Enforce blocks (24h)» = 0
- [ ] `alert-worker` healthy with pilot `ALERT_RULES` and webhook receives at least a test fire or stays quiet with empty CH

```bash
# Generate ACL denies then wait for poll interval
# (depends on ACL rules + AUTH)
```

---

## Out of scope (Horizon 2 alerts)

- Full SIEM productization
- Multi-node threat-sync alerts
- ML scoring — separate day-2+ path: [pilot-ml.md](pilot-ml.md) (one model / UEBA)
