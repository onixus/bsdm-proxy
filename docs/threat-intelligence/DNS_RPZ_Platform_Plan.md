# DNS RPZ Threat Intelligence Platform

> **Shadow Mode is the default posture** (`TI_ENFORCEMENT_MODE=shadow`).
> Proxy domain enforcement is implemented as beta in `ti_enforce.rs`, with
> Triple-Gate checks and explicit ACL allow-rule precedence. Enable collector
> and proxy enforcement only after the installation meets
> [ADR 0008](../adr/0008-threat-intel-shadow-mode.md). DNS publication is a
> separate operator action. Current implementation and limits:
> [collector guide](../features/threat-intel-collector.md).

## Purpose

Automatic DNS blocking platform based on Threat Intelligence IOC feeds.

## Architecture

```
Threat Intelligence
        |
IOC Database
        |
RPZ Generator
        |
RPZ Distribution
        |
DNS Servers
```

## Target DNS integrations (not verified support)

- BIND
- Unbound
- PowerDNS
- Windows DNS
- Infoblox

## RPZ Rules

Block:

```
malicious-domain.com CNAME .
```

Redirect:

```
malicious-domain.com CNAME block.company.local
```

Allowlist:

```
trusted-domain.com CNAME rpz-passthru.
```

## Publishing Rules

Add IOC when:

```
confidence >= 80
```

or:

```
multiple trusted sources
```

## Components

- RPZ Generator
- Distribution Service
- DNS Integration Layer
- Monitoring
- Rollback System

## Export

Generate:

- rpz.zone
- statistics.json
- audit logs

## Security

Requirements:

- signed changes
- audit trail
- rollback support
- validation before publish

## Proposed deployment (not the implemented stack)

The implemented collector uses Rust/Tokio and SQLite, with the bundled
`dns-sinkhole` integration. The following stack is an alternative design,
not an installation prerequisite:


- Docker
- PostgreSQL
- Redis
- FastAPI
- APScheduler/Celery

## Validation

Before publishing:

- DNS syntax check
- duplicate detection
- allowlist validation
- change volume analysis
