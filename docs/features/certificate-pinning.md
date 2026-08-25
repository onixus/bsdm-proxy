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

## MITM circuit breaker: detection and operator reset

The circuit breaker ([ADR 0007](../adr/0007-mitm-circuit-breaker.md),
`proxy/src/mitm_breaker.rs`) trips automatically when the TLS failure rate for a
domain crosses the configured threshold, and keeps that domain on blind
`CONNECT` until an operator resets it (with the default
`MITM_CIRCUIT_BREAKER_COOLDOWN_SECS=0` there is no automatic recovery). Tuning
variables are documented in
[configuration.md](../ops-and-dev/configuration.md#mitm-circuit-breaker).

### 1. Recognise that the breaker tripped

| Signal | Where |
|---|---|
| Structured log with `decision_source="pinning-bypass"`, `bypass_reason="circuit_breaker_tripped"` | proxy log |
| `bsdm_proxy_policy_decision_source_total{source="pinning-bypass"}` rising | Prometheus |
| Audit record `"action":"circuit_breaker_tripped"` with `actor":"system:circuit-breaker"`, failure rate and sample counts | `PINNING_AUDIT_LOG_PATH` (JSONL) |
| Authoritative state: tripped domain list | `GET /api/mitm/circuit-breaker` |

```bash
curl -fsS http://127.0.0.1:9090/api/mitm/circuit-breaker \
  -H "Authorization: Bearer $CONTROL_API_TOKEN" | jq .
```

The response carries the effective settings (`enabled`, `failure_rate_threshold`,
`min_samples`, `window_secs`, `cooldown_secs`, `max_domains`, `audit_path`),
`tripped_count`, and per-domain `tripped_domains[]` entries with
`tripped_at_unix`, `failure_rate`, `failure_count`, `total_samples` and `reason`
(`proxy/src/mitm_breaker.rs`).

It also reports the size of the tracker map: `tracked_domains`,
`tracked_wildcards` and `evicted_domains_total`. The map is capped by
`MITM_CIRCUIT_BREAKER_MAX_DOMAINS` so that a client looping `CONNECT` on random
hostnames cannot grow proxy memory; the least recently used **closed** trackers
are evicted first and tripped domains are never evicted. A steadily rising
`evicted_domains_total` means the cap is being hit — either raise it for a large
client population, or treat it as a signal of `CONNECT` scanning.

Note that `decision_source="pinning-bypass"` covers **both** a registry exception
(`bypass_reason="certificate_pinning_exception"`) and a tripped breaker
(`bypass_reason="circuit_breaker_tripped"`) — always confirm the reason before
acting.

### 2. Check before resetting

A reset re-enables interception for the domain. If the cause is still present,
the breaker will simply trip again and users see another round of failures.

1. Read the `reason` on the tripped entry (e.g. `cert_gen_error: …` recorded by
   `record_attempt`) and the surrounding proxy logs.
2. Rule out a local cause first: MITM CA validity and trust on clients, disk /
   permissions for the CA key, clock skew, upstream outage.
3. If the client application genuinely pins its certificate, **do not reset** —
   add a pinning exception (below) and leave the breaker to the availability
   role it was designed for.
4. Have the ticket / change reason ready: it is written to the audit trail and
   cannot be edited afterwards.

### 3. Reset

`POST /api/mitm/circuit-breaker/reset` requires a Bearer token and a JSON body
with **all three** fields (`proxy/src/control_api.rs`, handler
`circuit_breaker_reset`); the payload is parsed with `deny_unknown_fields`, so a
misspelled key returns `400`:

| Field | Rule |
|---|---|
| `domain` | Exact domain, or `*` to reset every tripped domain. Optional — defaults to `*` |
| `actor` | Who performs the reset. 1–128 printable characters |
| `reason` | Why. 1–512 printable characters |

```bash
# One domain
curl -fsS -X POST \
  http://127.0.0.1:9090/api/mitm/circuit-breaker/reset \
  -H "Authorization: Bearer $CONTROL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"api.vendor.example","actor":"alice@example.com","reason":"SEC-1234 upstream cert fixed, verified in staging"}'

# Every tripped domain (use deliberately)
curl -fsS -X POST \
  http://127.0.0.1:9090/api/mitm/circuit-breaker/reset \
  -H "Authorization: Bearer $CONTROL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"*","actor":"alice@example.com","reason":"SEC-1234 post-incident bulk reset"}'
```

The response reports `status`, the list of `reset_domains`, the `actor`, the
`reason` and `audited_at` (the audit file the record went to). A domain that was
not tripped is simply absent from `reset_domains` — the call still succeeds.
`POST /api/pinning/circuit-breaker/reset` and `GET /api/pinning/circuit-breaker`
are accepted as aliases.

### 4. Verify and record

1. Re-read `GET /api/mitm/circuit-breaker` — `tripped_count` must have dropped.
2. Confirm an `"action":"circuit_breaker_reset"` line with your actor and reason
   in `PINNING_AUDIT_LOG_PATH` (append-only JSONL, `0600`).
3. Watch `bsdm_proxy_policy_decision_source_total{source="pinning-bypass"}` and
   the domain's traffic for a few minutes. A second trip within the same window
   means the root cause is unresolved — stop resetting and open an exception or
   an upstream ticket.

### Reset or exception?

| Situation | Action |
|---|---|
| Transient upstream / certificate failure, now fixed | **Reset** |
| Application pins its certificate — inspection cannot work | **Pinning exception** (Safe change procedure above), then reset |
| Cause unknown, users blocked | Leave bypassed (availability first, ADR 0007), investigate, then decide |
| Breaker trips repeatedly across many domains | Suspect the local CA / cert generation path, not the domains |

Resets and exceptions are separate controls: an exception is a durable, reviewed
policy record with an owner and expiry; a reset is a one-off operational action.
Do not use repeated resets as a substitute for an exception.

## Observability

Each bypass emits a structured log with `decision_source="pinning-bypass"` and a
`bypass_reason` that distinguishes the cause —
`certificate_pinning_exception` (registry match) or `circuit_breaker_tripped`
(breaker). Other non-MITM decisions carry `mitm_disabled`, `policy_mode_sni`,
`category_not_selected_for_mitm` or `non_mitm_port`
(`proxy/src/proxy_service.rs`). Prometheus exposes the same decision through:

```promql
bsdm_proxy_policy_decision_source_total{source="pinning-bypass"}
```

The proxy analytics event also preserves `decision_source` and `bypass_reason`
for Search API and ClickHouse investigations.
