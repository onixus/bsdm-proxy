# Trust-UI (experimental legacy reference)

Trust-UI is no longer a supported operator surface. BSDM Admin Console is the
single supported interface, available at `/admin/`; the proxy redirects legacy
`/trust` links there. The architectural decision is recorded in
[ADR 0006](../docs/adr/0006-single-operator-console.md).

This source tree is retained temporarily as a design reference for future
endpoint identity/posture work. It is not a security boundary, is not included
in default deployments, and should not receive new operator features. Current
posture APIs depend on deferred Agent functionality and may return unsupported.

## Reference development only

```bash
cd trust-ui
npm install
npm run dev
```

The reference development server listens on `http://127.0.0.1:3001`. It uses
same-origin browser paths and its Vite-only development proxy sends health,
stats, metrics, and device requests to `127.0.0.1:9090`, plus search requests to
`127.0.0.1:8080`. It does not use the forward-proxy port.

To inspect the legacy container explicitly:

```bash
docker compose --profile experimental-trust-ui up trust-ui
```

The dedicated CI workflow still builds this source to catch accidental
breakage. A passing build does not promote it beyond Experimental status.
