# Threat Intelligence Integration with BSDM Proxy

> **Shadow Mode is the default posture** (`TI_ENFORCEMENT_MODE=shadow`).
> Proxy domain enforcement is implemented as beta in `ti_enforce.rs`, with
> Triple-Gate checks and explicit ACL allow-rule precedence. Enable collector
> and proxy enforcement only after the installation meets
> [ADR 0008](../adr/0008-threat-intel-shadow-mode.md). DNS publication is a
> separate operator action. Current implementation and limits:
> [collector guide](../features/threat-intel-collector.md).

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

- exact-domain and subdomain blocking via `ti_enforce.rs`
- explicit ACL allow-rule precedence

URL/IP normalization in the collector does not imply URL-path or destination-IP
enforcement by the proxy TI matcher. Its hot-path lookup is domain-based.

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
