# Security Policy

## Supported Versions

Security updates and critical patches are actively provided for the following versions of BSDM-Proxy:

| Version | Supported          | Security Patches |
| ------- | ------------------ | ---------------- |
| 0.9.x   | :white_check_mark: | Active           |
| < 0.9.0 | :x:                | EOL              |

---

## Reporting a Vulnerability

The BSDM-Proxy team takes security and data confidentiality seriously. If you discover a vulnerability or security issue, please follow responsible disclosure guidelines:

1. **Do NOT** create a public GitHub issue.
2. Report the vulnerability privately by opening a [GitHub Security Advisory](https://github.com/onixus/bsdm-proxy/security/advisories/new) or contacting the maintainers directly.
3. Include detailed steps to reproduce, sample payloads, system configuration, and impact assessment.

### Expected Response Times
- **Initial Acknowledgement**: Within 24 hours.
- **Triage & Assessment**: Within 48 hours.
- **Fix & Disclosure Plan**: Within 7 business days for high/critical severity issues.

---

## Security Architecture & Core Guarantees

### 1. Fail-Safe Threat Intelligence (Triple-Gate Architecture)
- Threat intelligence feed blocking requires three independent conditions:
  1. `TI_ENFORCEMENT_MODE=enforce` set explicitly in the environment.
  2. Artifact path contains no `.shadow` suffix.
  3. Feed payload explicitly includes `"mode": "enforce"`.
- Business-critical allowlists (`AclAction::Allow`) unconditionally supersede third-party threat feeds.

### 2. Authentication, Authorization & Timing Protection
- All management and SOAR endpoints (`/api/v1/soar/*`, `/api/v1/rpz/*`, `/api/v1/agent/*`) validate Bearer tokens.
- Secret tokens are compared using constant-time comparison (`constant_time_eq`) to mitigate timing attacks.
- Passwords and credentials are stored using salted `Argon2id` password hashing with automatic upgrade on verification.

### 3. Key Management & File Permissions
- Root CA private keys (`ca.key`) and WireGuard private configurations are strictly verified for `0600` (Owner read/write only) file permissions at startup.
- Key and configuration deployments enforce atomic filesystem replacement to prevent transient permission exposure.

### 4. Container & Pod Security (CIS Benchmarks)
- **Container Hardening**: All containers execute as unprivileged user `bsdm` (UID 10001).
- **Capability Drop**: `cap_drop: ALL` and `no-new-privileges: true` across all Docker Compose and Kubernetes Helm charts.
- **Kubernetes Pod Security**: `seccompProfile: RuntimeDefault`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`.

---

## Automated Security Audits

To run the full suite of security and compliance checks locally:

```bash
# CIS Benchmark Compliance Audit (Docker, K8s, Systemd, Linux, NGINX)
python3 scripts/cis-benchmark-audit.py

# Rust Code Quality & Static Analysis
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Unit, Integration & E2E Threat Intel Harness
cargo test --workspace
cargo test -p bsdm-proxy-e2e --test threat_intel_e2e
```
