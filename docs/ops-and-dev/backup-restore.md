# Backup & restore (ClickHouse + MITM CA)

Phase B ops drill for a single-node pilot. This is **not** a multi-AZ disaster
recovery design — it is a reproducible runbook so backup/restore is not tribal
knowledge.

Related: [CA lifecycle](ca-lifecycle.md) · [Pilot deployment](../getting-started/pilot-deployment.md) ·
[control-plane security](control-plane-security.md).

---

## What to back up

| Asset | Path / component | Criticality |
|---|---|---|
| MITM CA private key + cert | `certs/ca.key`, `certs/ca.crt` (+ rotation archive) | **Critical** — key compromise = MITM forgery |
| Pinning exceptions + audit | `config/pinning-exceptions*.json`, audit JSONL | High |
| ACL rules | `ACL_RULES_PATH` / `config/acl-rules*.json` | High |
| Proxy env secrets | `bsdm-proxy.env` / compose secrets | High (tokens, not only config) |
| ClickHouse analytics DB | volume `clickhouse-data`, database `bsdm` | Medium (history / search) |
| Kafka logs | compose volume | Low for pilot (short retention) |
| Prometheus TSDB | compose volume | Low |

RPO/RTO **assumptions for pilot** (adjust per site):

| | Pilot assumption |
|---|---|
| RPO analytics | ≤ 24 h (daily CH dump) |
| RPO CA | 0 — key stored in encrypted vault with dual control |
| RTO proxy | ≤ 1 h (reinstall package + restore certs/env) |
| RTO analytics | ≤ 4 h (restore Native dumps + re-index if needed) |

---

## MITM CA

### Backup

```bash
# Encrypted archive for vault (example)
umask 077
tar czf "ca-backup-$(date -u +%Y%m%d).tgz" -C certs ca.key ca.crt
# encrypt with age/gpg before leaving the host
./scripts/rotate-ca.sh verify
```

Also retain `certs/archive/<timestamp>/` after rotations (see
[ca-lifecycle.md](ca-lifecycle.md)).

### Restore / rollback after failed rotation

```bash
# Stop proxy first
cp certs/archive/<timestamp>/ca.key certs/ca.key
cp certs/archive/<timestamp>/ca.crt certs/ca.crt
chmod 600 certs/ca.key
./scripts/rotate-ca.sh verify
# Start proxy; verify:
curl --cacert certs/ca.crt -x http://127.0.0.1:3128 https://httpbin.org/uuid
```

### Automated drill

```bash
make rotate-ca-drill
# or full ops drill (CA + optional CH):
./scripts/drill-backup-restore.sh
```

---

## ClickHouse

### Prerequisites

- Compose stack with healthy `clickhouse` service, **or**
- `USE_COMPOSE=0` and `CLICKHOUSE_URL` (backup only; restore script is compose-oriented).

Schema must exist before restore (init SQL under `scripts/clickhouse/`).

### Backup

```bash
./scripts/backup-clickhouse.sh
# → backups/clickhouse/<UTC-timestamp>/{*.native,MANIFEST.txt,COUNTS.txt}
```

Environment:

| Variable | Default |
|---|---|
| `BACKUP_DIR` | `./backups/clickhouse` |
| `CLICKHOUSE_DATABASE` | `bsdm` |
| `COMPOSE_FILES` | `-f docker-compose.yml` |
| `CLICKHOUSE_SERVICE` | `clickhouse` |

### Restore

```bash
# Prefer empty or truncated tables for drill
RESTORE_TRUNCATE=1 ./scripts/restore-clickhouse.sh backups/clickhouse/<timestamp>
```

Production: restore into a new volume or maintenance window; Native `INSERT`
**appends** unless `RESTORE_TRUNCATE=1`.

### Verification

```bash
docker compose exec clickhouse clickhouse-client --database bsdm \
  --query "SELECT count() FROM http_cache"
curl -fsS "http://127.0.0.1:8080/api/search?limit=5" \
  -H "Authorization: Bearer ${SEARCH_API_TOKEN}"
```

---

## Full pilot acceptance (backup drill)

- [ ] CA: `make rotate-ca-drill` green
- [ ] CA: archive restore rolls back fingerprint (covered by `drill-backup-restore.sh`)
- [ ] CH: `backup-clickhouse.sh` produces MANIFEST + at least one `.native` (or empty note)
- [ ] CH: restore on clean/truncated tables; counts match drill seed
- [ ] Proxy health after CA rollback path documented in change record
- [ ] Secrets (tokens, CA) **not** stored in git; backup media encrypted

```bash
# One-shot when compose clickhouse is up:
./scripts/drill-backup-restore.sh

# CA-only (no docker):
SKIP_CLICKHOUSE=1 ./scripts/drill-backup-restore.sh
```

---

## What this does **not** cover

- Cross-region replication, ClickHouse Keeper HA, Kafka mirror
- Automated offsite lifecycle policies
- Point-in-time recovery finer than last dump
- Application-consistent multi-service snapshots in one freeze

Promote to a formal DR plan when leaving single-node pilot.
