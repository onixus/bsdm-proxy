# ADR 0006: One supported operator console

- **Status**: Accepted
- **Date**: 2026-08-04
- **Deciders**: BSDM Core Architecture Team
- **Issues**: #275, #280

## Context

The repository contains two React applications with overlapping monitoring and
security concepts:

- Admin Console, historically served at `/admin/`;
- Trust-UI, historically served at `/trust/` or on port `3001`.

They use different navigation, deployment paths, and API assumptions. Maintaining
both as supported operator surfaces makes it unclear where an operator should
inspect current posture, traffic decisions, and threat signals.

## Decision

Admin Console is the only supported operator interface. Its canonical embedded
entry point is `/admin/` on the proxy control origin. `/` and every legacy
`/trust` path permanently redirect to `/admin/`.

The Admin Console build and client router both use `/admin/` as their base path,
so direct links, refreshes, and static assets share the same deployment contract.

The existing `trust-ui/` source remains temporarily as an experimental design
reference for endpoint posture concepts. It is not started by default, does not
define a production security boundary, and receives no new operator features.
Its Compose service is available only through the `experimental-trust-ui`
profile while remaining in CI to prevent accidental source decay.

Admin Console owns the supported overlapping workflows:

| Operator need | Canonical Admin Console path |
|---|---|
| Node health and security counters | Dashboard `/` inside the SPA |
| Recent traffic and policy decisions | `/logs` |
| ML threat posture and drill-down | `/threat-scores` |
| Runtime policy and configuration | `/policies`, `/settings` |

Endpoint inventory/posture from the experimental Trust-UI is not presented as a
supported feature until the local Agent and its authenticated device contract
leave deferred scope. If that happens, the workflow will be implemented inside
Admin Console using its router, auth model, and shared API client.

## Consequences

### Positive

- Operators have one entry point, navigation model, and credential flow.
- Existing `/trust` bookmarks converge safely through a compatibility redirect.
- Compose no longer starts a second overlapping UI by default.
- Future posture work has an explicit destination and cannot silently create a
  third API/base-URL contract.

### Negative

- Trust-UI-specific layouts are no longer a supported deployment surface.
- Consumers embedding `/trust/` must follow the redirect or move links to
  `/admin/`.

## Reconsider when

Revisit this decision only if a separately authenticated end-user portal has a
documented audience and security boundary distinct from operator administration.
That portal must not duplicate operator controls and needs its own ADR.
