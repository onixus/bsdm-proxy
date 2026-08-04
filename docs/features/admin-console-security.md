# Admin Console security model

The Admin Console is an operator UI, not an authentication provider. It does
not establish a user identity, role, or browser login session. The shell must
therefore identify itself as a local, unauthenticated console even when an API
token is attached.

## Assets and trust boundaries

- Policy, user, DNS, cache, and runtime configuration mutations are privileged.
- API tokens entered in the console authorize individual backend requests.
- Tokens remain in JavaScript memory for the current browser tab and are not
  written to `localStorage`.
- The browser, the network path, the gateway serving `/admin`, and each backend
  API are separate trust boundaries.

## Threats and controls

| Threat | Control |
|---|---|
| An unauthenticated visitor opens the SPA and triggers a mutation | The shared API client rejects POST, PUT, PATCH, and DELETE locally when no token is attached. |
| The UI implies a verified operator identity | The shell displays `Local console` and `Unauthenticated`; no fabricated username or directory role is shown. |
| A token is recovered from persistent browser storage | API tokens are session-memory only and disappear on reload or tab close. |
| The console or Control API is reachable from an untrusted network | Deploy an authenticated access gateway, restrict the metrics/control listener, and configure `CONTROL_API_TOKEN`/`ACL_API_TOKEN`. |
| A caller bypasses the UI and invokes the backend directly | Backend token checks and network policy remain mandatory; the browser guard is defense in depth, not an API security boundary. |

## Safe deployment requirements

1. Do not expose `/admin` or `METRICS_PORT` directly to an untrusted network.
2. Configure strong `CONTROL_API_TOKEN` and `ACL_API_TOKEN` values for every
   deployment that enables mutating endpoints.
3. Terminate operator authentication at a trusted gateway until the Admin
   Console has a backend session contract and route guards.
4. Treat a configured API token as request authorization only, never as proof
   of a named user or role.
5. Use the read-only monitoring routes without credentials only when their
   backing endpoints are intentionally public inside the trusted operator
   network.

## Residual risk

The short-term guard prevents accidental or UI-driven unauthenticated
mutations. It does not protect an otherwise unauthenticated Control API from a
direct HTTP client, provide CSRF/session semantics, or create audit attribution
for a human operator. Those controls require backend authentication and an
operator session contract.
