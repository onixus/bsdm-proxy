# Certificate Pinning Exceptions

Certificate-pinning exceptions bypass TLS termination for explicitly approved
domains. Treat every exception as a reduction in inspection coverage: use the
narrowest hostname, record an owner and ticket, and set an expiry whenever
possible.

## Managed file

Set:

```bash
PINNING_EXCEPTIONS_PATH=/etc/bsdm-proxy/pinning-exceptions.json
PINNING_AUDIT_LOG_PATH=/var/log/bsdm-proxy/pinning-audit.jsonl
CONTROL_API_TOKEN='replace-with-a-secret'
```

The file format is:

```json
{
  "version": 1,
  "exceptions": [
    {
      "domain": "api.vendor.example",
      "reason": "Vendor-documented certificate pinning",
      "owner": "network-security",
      "ticket": "SEC-1234",
      "expires_at_unix": 1798761600
    }
  ]
}
```

An exact hostname such as `api.vendor.example` matches only that hostname. A
leading-dot suffix such as `.vendor.example` also matches subdomains. Wildcards,
URLs, ports, non-ASCII names, duplicates, and malformed labels are rejected.
Expired entries remain visible through the API but no longer bypass MITM.

`PINNING_EXCEPTIONS` remains available as a legacy comma-separated startup
fallback, but it cannot be hot-reloaded or audited. Production and pilot
deployments should use the managed file.

## Safe change procedure

1. Confirm the failure is caused by certificate pinning and not by an invalid CA
   deployment.
2. Create a change ticket with the application owner, justification, exact
   hostname, and intended expiry.
3. Edit a temporary copy and validate it with `jq`.
4. Atomically replace the managed file.
5. Reload it through the authenticated Control API:

```bash
curl -fsS -X POST \
  http://127.0.0.1:9090/api/pinning/exceptions/reload \
  -H "Authorization: Bearer $CONTROL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"actor":"alice@example.com","reason":"SEC-1234 approved by application owner"}'
```

Review the active registry:

```bash
curl -fsS http://127.0.0.1:9090/api/pinning/exceptions \
  -H "Authorization: Bearer $CONTROL_API_TOKEN" | jq .
```

Reload validates the complete replacement file before changing live traffic.
Every added, removed, or modified entry is appended to the JSONL audit log with
the actor, timestamp, reason, source path, and full exception metadata. If the
audit record cannot be persisted, the live registry is not replaced.

## Observability

Each bypass emits a structured log with
`decision_source="pinning-bypass"` and
`bypass_reason="certificate_pinning_exception"`. Prometheus exposes the same
decision through:

```promql
bsdm_proxy_policy_decision_source_total{source="pinning-bypass"}
```

The proxy analytics event also preserves `decision_source` and `bypass_reason`
for Search API and ClickHouse investigations.
