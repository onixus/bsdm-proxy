# Helm chart skeleton for BSDM-Proxy on Kubernetes.
#
# Install:
#   helm install bsdm ./charts/bsdm -n bsdm-proxy --create-namespace
#
# Production profile:
#   helm install bsdm ./charts/bsdm -f values-prod.yaml -n bsdm-proxy --create-namespace
#
# Full architecture: docs/k8s-architecture.md

## Prerequisites

- Kubernetes 1.28+
- Helm 3
- (prod) Redis L2 — deploy separately or enable future redis subchart
- (prod) Kafka in `bsdm-analytics` namespace
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

## Templates

| File | Resource |
|------|----------|
| `deployment.yaml` | proxy Deployment |
| `service.yaml` | ClusterIP :1488, :9090 |
| `configmap-env.yaml` | non-secret env |
| `hpa.yaml` | optional HPA |
| `pdb.yaml` | PodDisruptionBudget |
| `networkpolicy.yaml` | optional NetworkPolicy |
| `servicemonitor.yaml` | Prometheus Operator |

## Not included (deploy separately)

- Redis / Sentinel
- Kafka, OpenSearch, cache-indexer
- Ingress / Gateway API
- cert-manager Issuer

See `docker-compose.ha.yml` for local HA demo without k8s.
