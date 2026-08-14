# Threat Intelligence Architecture

## Overview

Threat Intelligence module extends BSDM Proxy with automated threat feed ingestion and enforcement.

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
BSDM Proxy Enforcement
    |
DNS RPZ / ACL / SIEM
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
