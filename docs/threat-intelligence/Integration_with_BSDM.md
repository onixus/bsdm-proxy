# Threat Intelligence Integration with BSDM Proxy

> **Shadow Mode is the current posture.** BSDM-Proxy performs threat
> *monitoring* from these feeds; enforcement is in development and is off by
> default (`TI_ENFORCEMENT_MODE=shadow`). Everything described below as blocking
> or enforcement is the target design and may only be enabled per installation
> under the transition criteria in
> [ADR 0008](../adr/0008-threat-intel-shadow-mode.md).

## Goal

Integrate IOC-based threat intelligence into BSDM Proxy filtering pipeline.

## Processing Flow

```
Threat Feed
   |
IOC Collector
   |
Validation
   |
Policy Decision
   |
BSDM Proxy ACL
   |
User Request Filtering
```

## Integration Points

### Proxy Layer

In `shadow` (default) the proxy uses IOC data for observation only: a match emits
the `threat_shadow_match` field on the event and increments `bsdm_proxy_ti_shadow_matches_total{feed}`, and
the allow/deny path is unchanged.

In `enforce` (explicit opt-in, [ADR 0008](../adr/0008-threat-intel-shadow-mode.md))
the same data is used for:

- domain blocking
- URL filtering
- malicious destination prevention

### DNS Layer

Support:

- RPZ export (always generated as a file when `TI_RPZ_ENABLED=true`)
- local DNS enforcement — only after the generated zone is deliberately published
  to `dns-sinkhole` (`DNS_SINKHOLE_ZONE_PATH`), which is not done by default

### SIEM

Send:

- blocked requests
- matched IOC
- source information
- confidence score

## Requirements

- low latency lookup
- cache support
- audit logging
- policy rollback
