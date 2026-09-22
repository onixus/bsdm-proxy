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
| `share/admin-console/` | Admin Console SPA, served by the proxy at `/admin/` |
| `config/*.example` | Environment and ACL templates |
| `systemd/` | systemd unit files |
| `install.sh` | Installer script |
| `VERSION` | Package version string |
| `SHA256SUMS` | Checksums for packaged binaries |

The release publishes `<archive>.sha256` beside every tarball.

Binaries are static (musl, `crt-static`): they run on any Linux of the same
architecture (x86_64, aarch64) with no compiler, no Rust or Node toolchain and
no shared-library requirements on the target host. They are exported from the
`artifacts` stage of the repository `Dockerfile`
(`scripts/build-package.sh --docker`), so a native install runs exactly the
binaries the container images ship.

## Quick start

One command, no checkout needed. It resolves the latest GitHub Release (or
`--version X.Y.Z`), downloads the tarball for this host, verifies the checksum
and runs the packaged `install.sh`:

```bash
curl -fsSL https://raw.githubusercontent.com/onixus/bsdm-proxy/main/scripts/install-release.sh \
  | sudo bash -s -- --version 0.9.15
```

Or by hand, from a downloaded tarball:

```bash
VERSION=0.9.15
ARCH=x86_64
sha256sum -c bsdm-proxy-${VERSION}-linux-${ARCH}.tar.gz.sha256
tar xzf bsdm-proxy-${VERSION}-linux-${ARCH}.tar.gz
cd bsdm-proxy-${VERSION}-linux-${ARCH}
sudo ./install.sh --create-user --systemd
```

Both paths leave the service installed but stopped: put the MITM CA in
`/etc/bsdm-proxy/certs` (or run `scripts/gen-ca.sh`), review
`/etc/bsdm-proxy/bsdm-proxy.env`, then `systemctl enable --now bsdm-proxy`.
The interactive wizard (`./install.sh` in a checkout, mode 2) does those steps
on top of the same fetcher.

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
