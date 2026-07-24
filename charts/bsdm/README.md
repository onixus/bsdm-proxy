# Helm chart for BSDM-Proxy on Kubernetes

```bash
# Data plane
helm install bsdm ./charts/bsdm -n bsdm-proxy --create-namespace

# Analytics plane: cache-indexer → external ClickHouse
helm upgrade --install bsdm-indexer ./charts/bsdm \
  -f charts/bsdm/values-analytics.yaml \
  -n bsdm-analytics --create-namespace
```

`values-prod.yaml` — исторический HA-профиль примерно для 5 000
пользователей, а не универсальные production defaults. Для пилота на
100 пользователей используйте
[пилотный runbook](../../docs/getting-started/pilot-deployment.md) и
перенесите его лимиты в отдельный values-файл.

Полная архитектура: [Kubernetes deployment](../../docs/ops-and-dev/k8s-architecture.md).

## Prerequisites

- Kubernetes 1.28+
- Helm 3
- (prod) Redis L2 — deploy separately or enable future redis subchart
- (prod) Kafka in `bsdm-analytics` namespace
- (prod) ClickHouse — Altinity Operator CHI (`examples/clickhouse-installation.yaml`)
  or managed / ClickHouse Cloud. **OpenSearch is not required.**
- MITM CA Secret (if `mitm.enabled`):

```bash
kubectl create secret generic bsdm-mitm-ca -n bsdm-proxy \
  --from-file=ca.crt=./certs/ca.crt \
  --from-file=ca.key=./certs/ca.key
```

Set `mitm.existingSecret: bsdm-mitm-ca` in values.

## Values

| Key | Default | Prod (`values-prod.yaml`) |
|-----|---------|--------------------------|
| `replicaCount` | 2 | 4 |
| `proxy.workerCount` | 1 | 1 |
| `proxy.cacheCapacity` | 10000 | 25000 total entries per pod |
| `proxy.redisL2Enabled` | false | true |
| `proxy.rknSyncEnabled` | false | — |
| `proxy.urlhausEnabled` | false | — |
| `proxy.phishtankEnabled` | false | — |
| `acl.autoReload` | false | — |
| `spill.sizeLimit` | 20Gi | 30Gi |
| `indexer.enabled` | false | see `values-analytics.yaml` |
| `alertWorker.enabled` | false | — |
| `mlWorker.enabled` | false | — |
| `dnsSinkhole.enabled` | false | — |

## Templates

| File | Resource |
|------|----------|
| `deployment.yaml` | proxy Deployment (`replicaCount > 0`) |
| `service.yaml` | ClusterIP :1488, :9090 |
| `configmap-env.yaml` | proxy non-secret env |
| `indexer-*.yaml` | cache-indexer when `indexer.enabled` |
| `alert-worker-*.yaml` | alert-worker when `alertWorker.enabled` |
| `ml-worker-*.yaml` | ml-worker when `mlWorker.enabled` |
| `dns-sinkhole-*.yaml` | dns-sinkhole when `dnsSinkhole.enabled` |
| `hpa.yaml` | optional HPA |
| `pdb.yaml` | PodDisruptionBudget |
| `networkpolicy.yaml` | optional NetworkPolicy |
| `servicemonitor.yaml` | Prometheus Operator |

## Examples

| Path | Description |
|------|-------------|
| `examples/clickhouse-installation.yaml` | Altinity `ClickHouseInstallation` CR |
| `values-analytics.yaml` | Indexer-only release (`replicaCount: 0`) |

Build images:
```bash
docker build --target proxy         -t ghcr.io/onixus/bsdm-proxy:0.6.1-1 .
docker build --target cache-indexer -t ghcr.io/onixus/bsdm-cache-indexer:0.6.1-1 .
docker build --target alert-worker  -t ghcr.io/onixus/bsdm-alert-worker:0.6.1-1 .
docker build --target ml-worker     -t ghcr.io/onixus/bsdm-ml-worker:0.6.1-1 .
docker build --target dns-sinkhole  -t ghcr.io/onixus/bsdm-dns-sinkhole:0.6.1-1 .
```

## Not included (deploy separately)

- Redis / Sentinel
- Kafka (Strimzi / Bitnami)
- ClickHouse Operator itself (install Altinity chart once per cluster)
- Ingress / Gateway API
- cert-manager Issuer

See `docker-compose.yml` for local full stack without k8s.
