# CA lifecycle and rotation

BSDM-Proxy uses a private root CA when TLS interception is enabled. Treat its
private key as a production signing key: possession of `ca.key` permits issuing
certificates trusted by every enrolled client.

## Generation and storage requirements

Generate the initial pair with:

```bash
./scripts/gen-ca.sh
./scripts/rotate-ca.sh verify
```

Local generation creates `certs/ca.key` with mode `0600`, `certs/ca.crt` with
mode `0644`, and the containing directory with mode `0700`.

### Parameters of newly issued CAs

Every issuance path (`scripts/gen-ca.sh`, `scripts/rotate-ca.sh prepare`,
`scripts/installer/common.sh`, `scripts/install-binaries.sh`) produces the same
certificate profile:

| Parameter | Value |
| --- | --- |
| Key | RSA 4096, no passphrase (loaded unattended at proxy startup) |
| Validity | **730 days (2 years)**; override with `--days N` or `CA_DAYS=N` |
| `basicConstraints` | `critical, CA:TRUE, pathlen:0` — may sign leaf certificates only, never a sub-CA |
| `keyUsage` | `critical, keyCertSign, cRLSign` — signing certificates and CRLs only |
| `subjectKeyIdentifier` | hash |

Extensions are supplied through a generated OpenSSL config file rather than
`-addext`, so issuance also works on OpenSSL 1.0.2 (RHEL 7 / older SLES).

Two years instead of the previous ten bounds the window in which a leaked
`ca.key` remains trusted and makes rotation a routine, rehearsed operation
rather than a once-a-decade event. **Plan a rotation every two years** using
`scripts/rotate-ca.sh` (procedure below); the mechanism already exists and is
exercised by `scripts/test-ca-rotation.sh` in CI.

These parameters apply only to newly issued CAs. Already deployed CAs keep
their original validity and extensions and continue to work unchanged; they are
migrated to the new profile the next time they are rotated.

- Never commit the key, bake it into an image, attach it to a ticket, or copy it
  into a world-readable/shared volume.
- The private key must have no permissions for `other`. Local files should be
  `0600`; a Kubernetes Secret may be `0440` when a dedicated pod `fsGroup` needs
  read access. The Helm chart enforces `0440` and a read-only mount.
- Restrict Secret/Vault read access to the proxy service identity and the small
  operator group responsible for CA rotation. Enable access audit logs.
- Keep backups encrypted, access-controlled, and separate from application
  backups. Record every export and restore.
- Do not place CA material on RWX or generally shared storage. Mount it read-only
  in the proxy container.

Clients must trust only the public `ca.crt`. Distribute it through the managed
trust channel for the platform (MDM/GPO/configuration management), never by
distributing `ca.key`.

## Planned two-phase rotation

Rotate every two years at the latest — CAs issued by current scripts are valid
730 days — and always well before certificate expiry (start at least one month
ahead so dual trust can be established), or immediately after suspected key
compromise. `openssl x509 -in certs/ca.crt -noout -enddate` shows the deadline;
there is currently no automatic expiry alert, so keep the date in the change
calendar.

### 1. Prepare and establish dual trust

```bash
./scripts/rotate-ca.sh prepare --common-name "BSDM Root CA 2027"
./scripts/rotate-ca.sh verify certs/rotation/<timestamp>
```

The command prints the staged directory and SHA-256 fingerprint. Store that
fingerprint in the change record. Distribute only the staged `ca.crt` to clients,
while keeping the current root installed. Confirm both fingerprints are present
on a representative client sample.

### 2. Activate during a maintenance window

Stop or drain the proxy first; CA files are loaded at process startup.

```bash
./scripts/rotate-ca.sh activate certs/rotation/<timestamp>
# restart the proxy using the deployment-specific command
curl --cacert certs/ca.crt -x http://127.0.0.1:3128 https://httpbin.org/uuid
```

Activation validates the key/certificate match, CA constraint, expiry, and key
permissions. It archives the previous pair under `certs/archive/<timestamp>/`,
installs the new pair, and removes the duplicate staged private key.

Verify HTTPS interception from each managed client class and check proxy TLS
errors. If verification fails, stop the proxy, restore the archived pair as
`certs/ca.key` and `certs/ca.crt`, enforce `0600` on the key, and restart.

### 3. Retire the old root

After the agreed observation window:

1. Remove the old public root from all client trust profiles.
2. Confirm unmanaged copies are not trusted on the representative client sample.
3. Move the archived private key to the approved encrypted backup or destroy it
   according to the organisation's key-destruction policy.
4. Close the change record with old/new fingerprints, client coverage, operator,
   timestamps, and verification evidence.

## Automated rotation drill

Run the offline drill without touching the active `certs/` directory:

```bash
make rotate-ca-drill
# Combined CA + optional ClickHouse backup/restore drill:
./scripts/drill-backup-restore.sh
# CA-only:
SKIP_CLICKHOUSE=1 ./scripts/drill-backup-restore.sh
```

Analytics backup/restore (ClickHouse Native dumps) is documented in
[backup-restore.md](backup-restore.md).

The drill creates a temporary initial CA, prepares and validates a new CA,
confirms that a world-readable key is rejected, activates the new pair, verifies
that the fingerprint changed, checks the archive, and deletes the temporary data.
CI runs the same drill for every pull request.

Successful baseline drill recorded on **2026-08-04**:

```text
CA rotation drill passed
Old SHA-256: C6:97:F7:2F:FF:20:99:B7:22:1B:5E:08:28:74:49:5E:E8:60:4C:26:C4:5A:EF:E4:7A:4C:63:50:55:0D:C2:DE
New SHA-256: 78:94:90:FE:07:3C:4E:F9:92:A5:B6:D1:13:9C:9A:DD:20:02:2B:0E:AB:B9:08:70:34:69:8F:47:D7:FD:F6:53
```

The fingerprints belong only to disposable drill keys, not production material.

## Emergency revocation checklist

When compromise is suspected, preserve incident evidence but prioritise stopping
new certificate issuance:

- [ ] Declare the incident, record time/scope, and identify the exposed CA fingerprint.
- [ ] Immediately disable TLS interception on every node (`POLICY_MODE=sni`) and
      restart/roll out the proxy fleet.
- [ ] Remove the compromised public root from MDM/GPO trust profiles; force an
      urgent client policy refresh and verify removal on representative clients.
- [ ] Revoke the compromised Secret/Vault version and deny further reads. Preserve
      relevant access/audit logs under incident-retention controls.
- [ ] Generate a new CA in a clean, approved environment. Never reuse the key.
- [ ] Distribute the new public root, rotate proxy nodes, and verify fingerprints
      and HTTPS service per the planned procedure above.
- [ ] Search for certificates issued by the compromised CA and investigate misuse.
- [ ] Destroy unapproved copies, rotate credentials that could access CA storage,
      document client coverage, and obtain incident-owner sign-off before closure.
