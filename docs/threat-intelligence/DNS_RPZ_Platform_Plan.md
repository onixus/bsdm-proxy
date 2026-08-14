# DNS RPZ Threat Intelligence Platform

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

## Supported DNS

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

## Deployment

Recommended stack:

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
