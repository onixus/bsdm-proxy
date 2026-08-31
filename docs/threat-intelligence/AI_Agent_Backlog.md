# Threat Intelligence AI Agent Backlog

> **Shadow Mode is the current posture.** BSDM-Proxy performs threat
> *monitoring* from these feeds; enforcement is in development and is off by
> default (`TI_ENFORCEMENT_MODE=shadow`). Everything described below as blocking
> or enforcement is the target design and may only be enabled per installation
> under the transition criteria in
> [ADR 0008](../adr/0008-threat-intel-shadow-mode.md).

## Goal

Implement automated Threat Intelligence pipeline integrated with BSDM Proxy.

---

# Phase 1 - MVP Collector

## TASK-TI-001 Feed Collector Framework

**Status: implemented** — `threat-intel` crate,
[docs/features/threat-intel-collector.md](../features/threat-intel-collector.md).

Create modular feed collector architecture.

Requirements:

- plugin-based sources
- scheduled execution
- error handling
- metrics

Sources:

- PhishStats
- OpenPhish
- Phishing.Database
- URLhaus

---

## TASK-TI-002 IOC Storage

**Status: implemented** — `threat_intel::storage::SqliteStorage`, SQLite persistence with indexes, TTL expiration and run history.

Implement database layer.

Support:

- SQLite (bundled WAL)
- PostgreSQL (planned)

Entities:

- indicators
- sources
- history

---

## TASK-TI-003 IOC Normalization

**Status: implemented** — `threat_intel::normalizer`, canonical URL formatting, FQDN extraction, Punycode handling, and bogon IP filtering.

Implement:

- URL normalization
- domain extraction
- punycode handling
- IP validation
- duplicate removal

---

# Phase 2 - Risk Engine

## TASK-TI-010 Confidence Scoring

**Status: implemented** — `threat_intel::scorer`, weighted calculation with multi-source correlation bonus, tag bonuses, and freshness decay.

Implement scoring engine:

- source reputation
- multiple source correlation
- freshness bonus
- confidence calculation

---

# Phase 3 - Enforcement

## TASK-TI-020 ACL Integration

**Status: implemented** — `threat_intel::rpz::export_proxy_acl_feed`, structured JSON threat lists for Proxy policy engine.

Integrate IOC decisions into BSDM Proxy policies.

Support:

- domain blocking
- URL blocking
- policy audit

---

## TASK-TI-021 DNS RPZ Generator

**Status: implemented** — `threat_intel::rpz`, automated standards-compliant DNS RPZ zone compilation (`YYYYMMDDNN` monotonic BIND serials), zone backup retention (`.bak`), and atomic rollback (`rollback_rpz_zone`).

Implement:

- RPZ generation
- monotonic serial management (`YYYYMMDDNN`)
- validation
- atomic rollback & zone backup

---

# Phase 4 - Enterprise Features

## TASK-TI-030 SIEM Integration

**Status: implemented** — `threat_intel::siem`, event formatting (CEF, ECS JSON, Syslog RFC 5424) and unified multi-transport delivery (`SyslogTransport` UDP/TCP, `FileSiemTransport`, `SiemDispatcher`).

Support:

- events
- alerts
- IOC lifecycle
- delivery transports (UDP/TCP/File/Dispatcher)

---

## TASK-TI-031 SOAR Integration

**Status: implemented** — `threat_intel::soar`, automated response API (`/api/v1/soar/block`, `/api/v1/soar/unblock`, `/api/v1/soar/investigate`) with real-time containment and audit.

Support automated response:

- block domain
- unblock domain
- investigate IOC

---

# Phase 5 - AI Enhancement

## TASK-TI-040 ML Reputation Model

**Status: implemented** — `threat_intel::ml_reputation`, visual homoglyph / Unicode confusable normalization, Damerau-Levenshtein brand distance, phishing campaign clustering (`cluster_phishing_campaigns`), and Shannon entropy/lexical anomaly detection (`detect_domain_anomalies`, `/api/v1/ml/*`).

Implement:

- domain similarity detection
- phishing campaign clustering
- algorithmic anomaly detection (entropy, digit ratios, deep subdomains)


---

# Definition of Done

Feature is complete when:

- tests exist
- documentation updated
- metrics available
- Docker deployment works
- security review completed
