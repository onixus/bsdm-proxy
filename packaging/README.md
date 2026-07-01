# BSDM-Proxy release package

Установка из готового release-архива. Общая документация: [README.md](../README.md) · [docs/README.md](../docs/README.md)

**Текущая версия пакета:** `0.3.0` — [release notes](../docs/releases/v0.3.0.md) · [CHANGELOG](../CHANGELOG.md)

## Contents

| Path | Description |
|------|-------------|
| `bin/proxy` | HTTPS caching proxy |
| `bin/cache-indexer` | Kafka → ClickHouse indexer |
| `config/*.example` | Environment and ACL templates |
| `systemd/` | systemd unit files |
| `install.sh` | Installer script |
| `VERSION` | Package version string |
| `SHA256SUMS` | Binary checksums |

## Quick start

```bash
tar xzf bsdm-proxy-0.3.0-linux-x86_64.tar.gz
cd bsdm-proxy-0.3.0-linux-x86_64
sudo ./install.sh --create-user --systemd
```

Place MITM CA certificates before starting:

```bash
sudo cp ca.key ca.crt /certs/
sudo chown bsdm-proxy:bsdm-proxy /certs/ca.*
sudo chmod 600 /certs/ca.key
sudo systemctl start bsdm-proxy
```

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

## Verify

```bash
curl http://127.0.0.1:9090/health
curl http://127.0.0.1:9090/ready
curl http://127.0.0.1:9090/metrics | head
cat VERSION
```

Логи: `journalctl -u bsdm-proxy -f` или см. [docs/logging.md](../docs/logging.md) (`RUST_LOG` в `config/*.env.example`).

## Build package from source

```bash
./scripts/build-package.sh
# → dist/bsdm-proxy-0.3.0-linux-<arch>.tar.gz
```

См. также [docs/development.md](../docs/development.md).
