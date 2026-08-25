# RPZ Deployment Plan

> **Shadow Mode is the current posture.** BSDM-Proxy performs threat
> *monitoring* from these feeds; enforcement is in development and is off by
> default (`TI_ENFORCEMENT_MODE=shadow`). Everything described below as blocking
> or enforcement is the target design and may only be enabled per installation
> under the transition criteria in
> [ADR 0008](../adr/0008-threat-intel-shadow-mode.md).

## Purpose

Deploy DNS Response Policy Zone blocking based on BSDM Proxy Threat Intelligence.
Publishing a generated zone **is** the enforcement step: it is not part of the
default deployment and requires the ADR 0008 transition criteria plus a signed
go/no-go record ([pilot-go-no-go-template.md](../ops-and-dev/pilot-go-no-go-template.md)).

## Components

- RPZ Generator
- DNS Distribution Service
- DNS Servers

## Supported Platforms

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
