# BSDM-Proxy release package

The package version is derived from `proxy/Cargo.toml`; operational procedures
should not hardcode a stale version.

## Contents

| Path | Description |
|------|-------------|
| `bin/proxy` | HTTPS caching proxy and control plane |
| `bin/cache-indexer` | Kafka to ClickHouse indexer |
| `bin/alert-worker` | ClickHouse to SIEM/webhook alerts |
| `bin/ml-worker` | Feature and ML score worker |
| `bin/dns-sinkhole` | RPZ DNS sinkhole sidecar |
| `bin/threat-intel` | Threat intelligence feed collector |
| `config/*.example` | Environment and ACL templates |
| `systemd/` | systemd unit files |
| `install.sh` | Installer script |
| `VERSION` | Package version string |
| `SHA256SUMS` | Checksums for packaged binaries |

The release publishes `<archive>.sha256` beside every tarball.

## Quick start

```bash
VERSION=0.9.14
ARCH=x86_64
sha256sum -c bsdm-proxy-${VERSION}-linux-${ARCH}.tar.gz.sha256
tar xzf bsdm-proxy-${VERSION}-linux-${ARCH}.tar.gz
cd bsdm-proxy-${VERSION}-linux-${ARCH}
sudo ./install.sh --create-user --systemd
```

## Verify

```bash
curl --fail http://127.0.0.1:9090/health
curl --fail http://127.0.0.1:9090/ready
curl --fail http://127.0.0.1:9090/admin/ >/dev/null
cat VERSION
```

Default ports: proxy `3128`, control/metrics `9090`, cache-indexer `8080`,
alert-worker `8090`, ML worker `8091`, DNS sinkhole metrics `8092`,
threat-intel metrics `8093`.
