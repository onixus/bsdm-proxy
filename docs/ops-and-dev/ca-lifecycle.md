# CA Lifecycle Management & Security Policy

This document details the generation, distribution, rotation, audit, and revocation procedures for BSDM-Proxy TLS MITM Certificate Authority (CA) keypairs (Issue #252).

---

## 1. Generation & Storage

### 1.1 Private Key Generation
The root CA keypair must be generated using RSA 4096 or ECDSA P-384:
```bash
./scripts/gen-ca.sh
```
Keys are generated at `./certs/ca.key` (Private Key) and `./certs/ca.crt` (Public Certificate).

### 1.2 Access Control & Protection
- `ca.key` MUST be mode `0600` owned by the proxy service user.
- In production Kubernetes environments, `ca.key` MUST be loaded via Kubernetes Secret or HashiCorp Vault integration, never stored in container images or Git.

---

## 2. Client Certificate Distribution

Clients (browsers, desktop OS, mobile MDM) must trust `ca.crt`:
- **Windows**: Store in `Cert:\LocalMachine\Root`
- **macOS**: `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt`
- **Linux**: `/usr/local/share/ca-certificates/` followed by `update-ca-certificates`

---

## 3. Rotation Protocol

CA rotation must be executed annually or immediately upon suspected key compromise.

1. **Phase 1 (Dual-Trust)**: Push new CA certificate `ca_v2.crt` to all client endpoints via MDM while retaining `ca_v1.crt`.
2. **Phase 2 (Proxy Key Swap)**: Update proxy `certs/ca.key` and `certs/ca.crt` to `v2`.
3. **Phase 3 (Cleanup)**: After verification, remove `ca_v1.crt` from client endpoints.

---

## 4. Emergency Revocation

If `ca.key` is compromised:
1. Immediately set `POLICY_MODE=sni` to halt TLS decryption across all nodes.
2. Revoke and remove `ca.crt` from MDM profiles on client devices.
3. Generate fresh CA keypair and restart rotation procedure.
