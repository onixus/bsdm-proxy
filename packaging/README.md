# BSDM-Proxy release package

Установка из готового release-архива. Общая документация: [README.md](../README.md) · [docs/README.md](../docs/README.md)

**Текущая версия пакета:** `0.6.1-1`. Имя архива вычисляется из версии
`proxy/Cargo.toml`; итоговое значение всегда проверяйте в `dist/`.

## Contents

| Path | Description |
|------|-------------|
| `bin/proxy` | HTTPS caching proxy |
| `bin/cache-indexer` | Kafka → ClickHouse indexer |
| `bin/alert-worker` | ClickHouse → SIEM/webhook alerts (optional) |
| `bin/ml-worker` | ClickHouse → entity features + ML scores (M5, optional) |
| `config/*.example` | Environment and ACL templates |
| `systemd/` | systemd unit files |
| `install.sh` | Installer script |
| `VERSION` | Package version string |
| `SHA256SUMS` | Binary checksums |

## Quick start

```bash
tar xzf bsdm-proxy-0.6.1-1-linux-x86_64.tar.gz
cd bsdm-proxy-0.6.1-1-linux-x86_64
sudo ./install.sh --create-user --systemd
```

Place MITM CA certificates before starting:

```bash
sudo cp ca.key ca.crt /certs/
sudo chown bsdm-proxy:bsdm-proxy /certs/ca.*
sudo chmod 600 /certs/ca.key
sudo systemctl start bsdm-proxy
```

Optional SIEM alerts: configure `config/alert-worker.env.example` → `/etc/bsdm-proxy/alert-worker.env`, then `systemctl enable --now bsdm-alert-worker`.

Optional M5 ML worker: apply `scripts/clickhouse/ml_features.sql`, configure `ml-worker.env`, then `systemctl enable --now bsdm-ml-worker` (see [ML security](../docs/analytics/ml-security.md)).

## Manual run

```bash
set -a
source config/bsdm-proxy.env.example
set +a
./bin/proxy
```

## Ports

| Service | Default port |
|---------|--------------|
| Proxy HTTP/HTTPS | 1488 |
| ICP (UDP, if `HIERARCHY_ENABLED=true`) | 3130 |
| Metrics / health | 9090 |
| cache-indexer admin / Search API | 8080 |
| alert-worker metrics | 8090 |
| ml-worker metrics | 8091 |

## Verify

```bash
curl http://127.0.0.1:9090/health
curl http://127.0.0.1:9090/ready
curl http://127.0.0.1:9090/metrics | head
cat VERSION
```

Логи: `journalctl -u bsdm-proxy -f` или см. [Logging and metrics](../docs/ops-and-dev/logging.md) (`RUST_LOG` в `config/*.env.example`).

## Build package from source

```bash
./scripts/build-package.sh
# → dist/bsdm-proxy-0.6.1-1-linux-<arch>.tar.gz
```

См. также [Development guide](../docs/ops-and-dev/development.md).
