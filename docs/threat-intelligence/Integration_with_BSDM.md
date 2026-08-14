# Threat Intelligence Integration with BSDM Proxy

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

Use IOC data for:

- domain blocking
- URL filtering
- malicious destination prevention

### DNS Layer

Support:

- RPZ export
- local DNS enforcement

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
