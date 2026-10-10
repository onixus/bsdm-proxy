# Security Policy

Текущая версия кода — `1.0.0-rc.1` (release candidate); статус функций и
ограничения: [project-status](docs/project-status.md). Таблица ниже сохраняет
политику поддержки предыдущей линейки и не объявляет RC стабильным GA.

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
- An explicit matched ACL allow-rule (`AclAction::Allow` with a rule ID) takes precedence over the proxy TI domain matcher; a default allow action is not an allowlist.
- Collector and proxy have independent process environments. Returning only the collector to shadow does not roll back proxy enforcement; see [ADR 0008](docs/adr/0008-threat-intel-shadow-mode.md).

### 2. Authentication, Authorization & Timing Protection
- Production control mutations require a Bearer token, except intentionally public OCSP status requests. Public monitoring routes include `/api/stats`, `/api/hierarchy/peers` and `/api/upstream/tls`; health/ready remain public and metrics auth is configurable. Agent enrollment/device tokens have separate contracts; lab routes default to 404.
- Collector SOAR endpoints and RPZ rollback require `TI_API_TOKEN`; RPZ status and ML/health/metrics remain public inside the management boundary.
- Control REST uses one administrative token; RBAC and complete mutation audit are planned for 1.1. See [control-plane security](docs/ops-and-dev/control-plane-security.md).
- Secret tokens are compared using constant-time comparison (`constant_time_eq`) to mitigate timing attacks.
- Passwords and credentials are stored using salted `Argon2id` password hashing with automatic upgrade on verification.

### 3. Key Management & File Permissions
- In production the MITM CA is loaded only from `MITM_CA_DIR`, with key/certificate, validity and permission checks. Native CA keys use `0600`; a dedicated read-only Kubernetes Secret mount may use `0440`. AmneziaWG is a separate lab surface, not a GA guarantee. See [CA lifecycle](docs/ops-and-dev/ca-lifecycle.md).
- Key and configuration deployments enforce atomic filesystem replacement to prevent transient permission exposure.

### 4. Container & Pod Security (CIS Benchmarks)
- **Container Hardening**: Repository-built service images use unprivileged `bsdm` (UID/GID 1000). Third-party infrastructure images have their own users; deployment-specific security settings must be checked separately.
- **Capability Drop**: Production profiles drop capabilities and forbid privilege escalation. Lab network sidecars need explicitly scoped network capabilities; they are outside the GA deployment scope.
- **Kubernetes Pod Security**: `seccompProfile: RuntimeDefault`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`.

---

## Automated Security Audits

Run these scoped checks locally; they do not establish full runtime compliance or deployment acceptance:

```bash
# CIS Benchmark Compliance Audit (Docker, K8s, Systemd, Linux, NGINX)
python3 scripts/cis-benchmark-audit.py

# Rust Code Quality & Static Analysis
cargo clippy --workspace --all-targets -- -D warnings
# Default graph: blocking license/advisory policy used by GitHub CI
cargo deny --locked check
# Optional feature graph: report separately, known failures must stay visible
cargo deny --locked --all-features check

# Unit, Integration & E2E Threat Intel Harness
cargo test --workspace
cargo test -p bsdm-proxy-e2e --test threat_intel_e2e
```
