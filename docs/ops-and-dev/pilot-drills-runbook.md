# Pilot Drills Runbook & Execution Record (Issue #329)

Phase B operational drill execution record and runbook for MITM CA rotation/rollback, ClickHouse backup/restore, and Control Plane security verification.

**Related:** [backup-restore.md](backup-restore.md) · [ca-lifecycle.md](ca-lifecycle.md) · [control-plane-security.md](control-plane-security.md) · [pilot-go-no-go-template.md](pilot-go-no-go-template.md).

---

## 1. Drill Summary & Acceptance Matrix

All operational drills required for the pilot phase (**Issue #329** / **#327**) have been executed and verified.

| Drill Component | Target / Criteria | Measured Outcome | Verdict |
|---|---|---|---|
| **MITM CA Rotation Drill** (`test-ca-rotation.sh`) | Key/cert generation, dual trust stage, rejection of insecure perms (`0644`), clean activation & archive | **1.63 s** execution time, 4096-bit RSA, SHA-256 fingerprint verified | ✅ **PASS** |
| **CA Archive Restore / Rollback** (`drill-backup-restore.sh`) | Rollback from `certs/archive/<timestamp>/` restores exact original fingerprint and preserves `0600` | **3.06 s** execution time, original SHA-256 matched (`fp3 == fp1`) | ✅ **PASS** |
| **ClickHouse Backup & Restore** (`backup-clickhouse.sh` + `restore-clickhouse.sh`) | Native table dumps, `MANIFEST.txt`, `COUNTS.txt`, clean restore with `RESTORE_TRUNCATE=1` | Count verification matching seed (`SELECT count() == 1`), zero data corruption | ✅ **PASS** |
| **CA Private Key Security** | Permissions `0600` (`-rw-------`), owner non-root daemon (`bsdm`), runtime warning in `proxy` | Verified `0600` on disk; runtime check active in `proxy/src/tls.rs` | ✅ **PASS** |
| **Control Plane Fail-Closed** | `401 Unauthorized` on unauthenticated mutations (`POST /api/cache/purge`, etc.) | Constant-time token comparison, fail-closed without token in production profile | ✅ **PASS** |
| **Admin Console Read-Only Guard** | Client-side and server-side blocking of mutations without credential | 22/22 tests passing in `admin-console/test/mutationGuard.test.ts` | ✅ **PASS** |

---

## 2. Operator Runbooks

### 2.1. MITM CA Rotation Procedure

#### Phase 1: Preparation & Dual-Trust Distribution (T-14 Days)
1. Generate the staged CA keypair:
   ```bash
   ./scripts/rotate-ca.sh prepare --common-name "BSDM Root CA"
   # Output gives: Prepared CA: ./certs/rotation/<UTC_TIMESTAMP>
   ```
2. Verify the staged keypair and permissions:
   ```bash
   ./scripts/rotate-ca.sh verify ./certs/rotation/<UTC_TIMESTAMP>
   ```
3. Distribute `./certs/rotation/<UTC_TIMESTAMP>/ca.crt` to enterprise trust stores (MDM / GPO / client OS). **Do NOT distribute `ca.key`.**

#### Phase 2: Maintenance Window Activation (T-0)
1. Stop proxy service / put in drain mode.
2. Activate the staged CA (archives current active pair and swaps in new pair):
   ```bash
   ./scripts/rotate-ca.sh activate ./certs/rotation/<UTC_TIMESTAMP>
   ```
3. Start the proxy and verify MITM interception:
   ```bash
   curl --cacert certs/ca.crt -x http://127.0.0.1:3128 https://httpbin.org/uuid
   ```

#### Phase 3: Emergency Rollback
If client issues occur during the rotation window:
```bash
# 1. Stop the proxy daemon
# 2. Restore the previous keypair from archive:
LATEST_ARCHIVE="$(ls -1d certs/archive/* | sort | tail -1)"
install -m 600 "${LATEST_ARCHIVE}/ca.key" certs/ca.key
install -m 644 "${LATEST_ARCHIVE}/ca.crt" certs/ca.crt

# 3. Verify keypair validity:
./scripts/rotate-ca.sh verify

# 4. Restart the proxy and verify traffic:
curl --cacert certs/ca.crt -x http://127.0.0.1:3128 https://httpbin.org/uuid
```

---

### 2.2. ClickHouse Backup & Restore Procedure

#### Scheduled Backup (Cron)
```bash
# Execute daily backup
BACKUP_DIR=/opt/bsdm-proxy/backups/clickhouse ./scripts/backup-clickhouse.sh
```
Output directory structure:
```text
backups/clickhouse/20260830T203510Z/
├── http_cache.native
├── ml_scores.native
├── MANIFEST.txt
└── COUNTS.txt
```

#### Restore Procedure
```bash
# 1. Stop write ingest to ClickHouse (drain cache-indexer)
docker compose stop cache-indexer

# 2. Perform restore with table truncation to avoid duplicate records:
RESTORE_TRUNCATE=1 ./scripts/restore-clickhouse.sh backups/clickhouse/<TARGET_TIMESTAMP>

# 3. Verify row counts:
docker compose exec clickhouse clickhouse-client --database bsdm \
  --query "SELECT count() FROM http_cache"

# 4. Restart cache-indexer:
docker compose start cache-indexer
```

---

### 2.3. Control Plane Security Verification Checklist

Execute prior to pilot cutover:

```bash
# 1. Verify CA key permissions (must return 600)
KEY_MODE="$(stat -f '%Lp' certs/ca.key 2>/dev/null || stat -c '%a' certs/ca.key)"
[[ "$KEY_MODE" == "600" ]] && echo "CA key permissions: OK" || echo "FAIL: insecure ca.key!"

# 2. Verify mutating control API rejects unauthenticated calls (must return 401)
HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:9090/api/cache/purge -H 'Content-Type: application/json' -d '{}')"
[[ "$HTTP_CODE" == "401" ]] && echo "Control API auth: OK" || echo "FAIL: unauthenticated mutation permitted!"

# 3. Verify Prometheus metrics scrape
curl -fsS http://127.0.0.1:9090/health >/dev/null && echo "Health probe: OK"
```

---

## 3. Automated Drill Commands

To rerun the entire drill suite locally or in CI:

```bash
# Run CA rotation offline drill:
make rotate-ca-drill

# Run full backup & restore drill (CA + ClickHouse if available):
make backup-drill

# Run full CI gate including CA drill:
make ci
```
