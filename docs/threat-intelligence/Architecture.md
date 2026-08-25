# Threat Intelligence Architecture

> **Shadow Mode is the current posture.** BSDM-Proxy performs threat
> *monitoring* from these feeds; enforcement is in development and is off by
> default (`TI_ENFORCEMENT_MODE=shadow`). Everything described below as blocking
> or enforcement is the target design and may only be enabled per installation
> under the transition criteria in
> [ADR 0008](../adr/0008-threat-intel-shadow-mode.md).

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
    +-- shadow (default): threat_shadow_match event + ti_shadow_matches_total{feed}
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
