# RPZ Deployment Plan

> **Shadow Mode is the default posture** (`TI_ENFORCEMENT_MODE=shadow`).
> Proxy domain enforcement is implemented as beta in `ti_enforce.rs`, with
> Triple-Gate checks and explicit ACL allow-rule precedence. Enable collector
> and proxy enforcement only after the installation meets
> [ADR 0008](../adr/0008-threat-intel-shadow-mode.md). DNS publication is a
> separate operator action. Current implementation and limits:
> [collector guide](../features/threat-intel-collector.md).

## Purpose

Deploy DNS Response Policy Zone blocking based on BSDM Proxy Threat Intelligence.
Publishing a generated zone **is** the enforcement step: it is not part of the
default deployment and requires the ADR 0008 transition criteria plus a signed
go/no-go record ([pilot-go-no-go-template.md](../ops-and-dev/pilot-go-no-go-template.md)).

## Components

- RPZ Generator
- DNS Distribution Service
- DNS Servers

## Target platforms (require separate compatibility acceptance)

- BIND
- Unbound
- PowerDNS
- Windows DNS
- Infoblox

## Workflow

```
IOC Database
     |
RPZ Generator
     |
Validation
     |
DNS Publish
```

## Rules

Block:

```
malicious-domain.com CNAME .
```

Redirect:

```
malicious-domain.com CNAME block.local
```

Allowlist:

```
trusted-domain.com CNAME rpz-passthru.
```

## Validation

Before publish:

- syntax check
- duplicate detection
- allowlist verification
- change volume analysis

## Rollback

Store every generated zone version and allow restoring previous serial.
