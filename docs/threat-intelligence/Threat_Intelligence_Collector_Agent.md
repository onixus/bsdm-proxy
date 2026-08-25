# Threat Intelligence Collector Agent

> **Shadow Mode is the current posture.** BSDM-Proxy performs threat
> *monitoring* from these feeds; enforcement is in development and is off by
> default (`TI_ENFORCEMENT_MODE=shadow`). Everything described below as blocking
> or enforcement is the target design and may only be enabled per installation
> under the transition criteria in
> [ADR 0008](../adr/0008-threat-intel-shadow-mode.md).

## Purpose

AI-agent specification for automated collection, normalization and processing of phishing IOC.

## Data Sources

Supported feeds:

- PhishStats API
- OpenPhish feed
- Phishing.Database feeds
- URLhaus API/feeds

## Pipeline

```
Threat Feeds
    |
Collector
    |
Parser
    |
Normalizer
    |
Deduplication
    |
Risk Scoring
    |
IOC Database
    |
ACL / RPZ / SIEM / SOAR
```

## IOC Types

- URL
- Domain
- IP address

## Processing Rules

- normalize URL and domains
- remove duplicates
- merge sources
- track first_seen and last_seen
- calculate confidence score

## Risk Score

Default source weights:

| Source | Score |
|---|---:|
| OpenPhish | 90 |
| PhishStats | 80 |
| Phishing.Database | 75 |
| URLhaus | 70 |

## Blocking Policy

High risk:

```
confidence >= 80
```

Export to:

- ACL
- DNS RPZ
- SIEM

## Storage

Recommended:

- PostgreSQL production
- SQLite standalone

## Output

Generate:

- domains.txt
- urls.txt
- ips.txt
- indicators.json
- report.json

## Security Requirements

Agent must not execute phishing URLs or download payloads. Processing is metadata-only.
