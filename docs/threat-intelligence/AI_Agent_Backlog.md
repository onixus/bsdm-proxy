# Threat Intelligence AI Agent Backlog

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

Implement database layer.

Support:

- PostgreSQL
- SQLite

Entities:

- indicators
- sources
- history

---

## TASK-TI-003 IOC Normalization

Implement:

- URL normalization
- domain extraction
- punycode handling
- IP validation
- duplicate removal

---

# Phase 2 - Risk Engine

## TASK-TI-010 Confidence Scoring

Implement scoring engine:

- source reputation
- multiple source correlation
- freshness bonus
- confidence calculation

---

# Phase 3 - Enforcement

## TASK-TI-020 ACL Integration

Integrate IOC decisions into BSDM Proxy policies.

Support:

- domain blocking
- URL blocking
- policy audit

---

## TASK-TI-021 DNS RPZ Generator

Implement:

- RPZ generation
- serial management
- validation
- rollback

---

# Phase 4 - Enterprise Features

## TASK-TI-030 SIEM Integration

Support:

- events
- alerts
- IOC lifecycle

---

## TASK-TI-031 SOAR Integration

Support automated response:

- block domain
- unblock domain
- investigate IOC

---

# Phase 5 - AI Enhancement

## TASK-TI-040 ML Reputation Model

Implement:

- domain similarity detection
- phishing campaign clustering
- anomaly detection

---

# Definition of Done

Feature is complete when:

- tests exist
- documentation updated
- metrics available
- Docker deployment works
- security review completed
