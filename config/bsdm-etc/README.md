# Writable proxy config mount (`/etc/bsdm-proxy`)

Compose mounts this directory into the proxy container so Admin Console
**Policies → Persist** and Settings Apply can create sibling `*.tmp` files.

Seeded from examples:

- `acl-rules.json`
- `pinning-exceptions.json`

Do not commit secrets here. Tokens live in project `.env` / runtime env.
