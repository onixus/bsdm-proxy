# Threat Intelligence Architecture

> **Shadow Mode is the default posture** (`TI_ENFORCEMENT_MODE=shadow`).
> Proxy domain enforcement is implemented as beta in `ti_enforce.rs`, with
> Triple-Gate checks and explicit ACL allow-rule precedence. Enable collector
> and proxy enforcement only after the installation meets
> [ADR 0008](../adr/0008-threat-intel-shadow-mode.md). DNS publication is a
> separate operator action. Current implementation and limits:
> [collector guide](../features/threat-intel-collector.md).

## Overview

Threat Intelligence module extends BSDM Proxy with automated threat feed ingestion, scoring and
observation. Enforcement is a separate, explicitly enabled stage (`TI_ENFORCEMENT_MODE=enforce`);
in the default `shadow` posture the pipeline stops at telemetry.

## Architecture

```
Threat Feeds
    |
Collector
    |
IOC Processing
    |
Risk Engine
    |
Policy Engine
    |
    +-- shadow (default): threat_shadow_match field on the event + bsdm_proxy_ti_shadow_matches_total{feed}
    |
    +-- enforce (explicit opt-in, ADR 0008): DNS RPZ / ACL
    |
SIEM
```

## Components

- Feed collectors
- IOC database
- Normalization engine
- Scoring engine
- Export services
- Monitoring

## Integration

The module provides security decisions for:

- proxy filtering
- DNS blocking
- security analytics
- incident response
