# Helm chart skeleton for BSDM-Proxy on Kubernetes.
#
# Install (data plane):
#   helm install bsdm ./charts/bsdm -n bsdm-proxy --create-namespace
#
# Production profile:
#   helm install bsdm ./charts/bsdm -f values-prod.yaml -n bsdm-proxy --create-namespace
#
# Analytics plane (cache-indexer → ClickHouse):
#   helm upgrade --install bsdm-indexer ./charts/bsdm \
#     -f values-analytics.yaml -n bsdm-analytics --create-namespace
#
# Full architecture: docs/k8s-architecture.md

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
|-----|---------|-------------------------|
| `replicaCount` | 2 | 4 |
| `proxy.workerCount` | 1 | 1 |
| `proxy.cacheCapacity` | 10000 | 25000 per pod |
| `proxy.redisL2Enabled` | false | true |
| `spill.sizeLimit` | 20Gi | 30Gi |
| `indexer.enabled` | false | see `values-analytics.yaml` |

## Templates

| File | Resource |
|------|----------|
| `deployment.yaml` | proxy Deployment (`replicaCount > 0`) |
| `service.yaml` | ClusterIP :1488, :9090 |
| `configmap-env.yaml` | proxy non-secret env |
| `indexer-*.yaml` | cache-indexer when `indexer.enabled` |
| `hpa.yaml` | optional HPA |
| `pdb.yaml` | PodDisruptionBudget |
| `networkpolicy.yaml` | optional NetworkPolicy |
| `servicemonitor.yaml` | Prometheus Operator |

## Examples

| Path | Description |
|------|-------------|
| `examples/clickhouse-installation.yaml` | Altinity `ClickHouseInstallation` CR |
| `values-analytics.yaml` | Indexer-only release (`replicaCount: 0`) |

Build indexer image: `docker build --target cache-indexer -t ghcr.io/onixus/bsdm-cache-indexer:0.3.2 .`

## Not included (deploy separately)

- Redis / Sentinel
- Kafka (Strimzi / Bitnami)
- ClickHouse Operator itself (install Altinity chart once per cluster)
- Ingress / Gateway API
- cert-manager Issuer

See `docker-compose.yml` for local full stack without k8s.
