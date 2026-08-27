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
The chart mounts Secret files read-only with mode `0440`; the pod `fsGroup` grants
the non-root proxy process access without making CA material world-readable. See
the [CA lifecycle and rotation guide](../../docs/ops-and-dev/ca-lifecycle.md).

## Security contract (breaking since 0.6.2)

The chart is now installable under Pod Security Standards **restricted**
(`seccompProfile: RuntimeDefault`, `runAsGroup`, `automountServiceAccountToken:
false` on the ServiceAccount and all six pod specs). Four things that used to be
accepted are now render-time errors, because each of them put a credential into
an object that is not a Secret or gave pods more access than they need:

| Removed / now required | What to do |
|---|---|
| `indexer.clickhouse.password` (was rendered into the Deployment spec) | `kubectl create secret generic bsdm-clickhouse --from-literal=username=<u> --from-literal=password=<p>` → `indexer.clickhouse.existingSecret` |
| `threatIntel.apiToken` (was rendered into the Deployment spec) | `kubectl create secret generic bsdm-ti --from-literal=ti-api-token=<t>` → `threatIntel.existingSecret`. Leaving it unset is fine: SOAR mutations stay fail-closed |
| `indexer.searchApi.token` in the env ConfigMap | `indexer.searchApi.existingSecret` (+ `existingSecretKey`), or keep `token` — the chart now writes it to a Secret and injects it with `secretKeyRef` |
| `proxy.phishtankApiKey` in the env ConfigMap | `proxy.phishtankExistingSecret` (+ `proxy.phishtankExistingSecretKey`), or keep the inline key — it lands in a chart-managed Secret |
| `serviceAccount.create: false` with an empty `serviceAccount.name` | Set `serviceAccount.name`. The chart no longer silently binds pods to the namespace `default` ServiceAccount |

`networkPolicy.enabled` now defaults to **true** and `networkPolicy.proxyIngressCidrs`
defaults to **empty**. The old default `10.0.0.0/8` also covered the pod CIDR, i.e.
every pod in the cluster could use the forward proxy for egress. Allowed proxy
clients are now: pods of the release namespace (always), `networkPolicy.proxyClientNamespaces`,
and `networkPolicy.proxyIngressCidrs` — **set at least one of the latter two if your
clients live outside the release namespace, or they will be cut off.**

Other policy changes: every workload (indexer/Search API, alert-worker, ml-worker,
dns-sinkhole, threat-intel, proxy) now has its own policy plus a deny-all baseline
scoped to `app.kubernetes.io/instance` (co-located Redis/ClickHouse are not
affected; use `networkPolicy.defaultDenyNamespace: true` for the namespace-wide
variant). Egress to :53 is restricted to kube-dns
(`networkPolicy.dnsNamespace` / `dnsPodSelector`) instead of the whole internet.
ClickHouse/Kafka egress is port-restricted when `networkPolicy.clickhouseNamespace`
/ `kafkaNamespace` are empty, and namespace-restricted when they are set.

Container `securityContext` can be overridden per component
(`indexer.securityContext`, `mlWorker.securityContext`, …); an override *replaces*
`.Values.securityContext` for that workload only, so relaxing one component no
longer relaxes the other five.

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
| `service.yaml` | ClusterIP :3128, :9090 |
| `configmap-env.yaml` | proxy non-secret env |
| `secret-env.yaml` | proxy credentials (PhishTank key) when set inline |
| `indexer-*.yaml` | cache-indexer when `indexer.enabled` |
| `alert-worker-*.yaml` | alert-worker when `alertWorker.enabled` |
| `ml-worker-*.yaml` | ml-worker when `mlWorker.enabled` |
| `dns-sinkhole-*.yaml` | dns-sinkhole when `dnsSinkhole.enabled` |
| `hpa.yaml` | optional HPA |
| `pdb.yaml` | PodDisruptionBudget |
| `networkpolicy.yaml` | proxy NetworkPolicy + deny-all baseline |
| `*-networkpolicy.yaml` | per-workload NetworkPolicy (indexer, alert-worker, ml-worker, dns-sinkhole, threat-intel) |
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
