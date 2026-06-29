# BSDM-Proxy release package

## Contents

| Path | Description |
|------|-------------|
| `bin/proxy` | HTTPS caching proxy |
| `bin/cache-indexer` | Kafka → OpenSearch indexer |
| `config/*.example` | Environment and ACL templates |
| `systemd/` | systemd unit files |
| `install.sh` | Installer script |
| `SHA256SUMS` | Binary checksums |

## Quick start

```bash
tar xzf bsdm-proxy-0.2.2b-linux-amd64.tar.gz
cd bsdm-proxy-0.2.2b-linux-amd64
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
export $(grep -v '^#' config/bsdm-proxy.env.example | xargs)
./bin/proxy
```

## Ports

| Service | Default port |
|---------|--------------|
| Proxy HTTP/HTTPS | 1488 |
| Metrics / health | 9090 |

## Verify

```bash
curl http://127.0.0.1:9090/health
curl http://127.0.0.1:9090/ready
```
