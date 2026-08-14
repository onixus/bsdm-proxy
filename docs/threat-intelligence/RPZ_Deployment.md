# RPZ Deployment Plan

## Purpose

Deploy DNS Response Policy Zone blocking based on BSDM Proxy Threat Intelligence.

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
