# APEX deployment contract 1.0 — bsdm-proxy

The root `apex-deploy.json` declares the installation method and required parameter names.
The common schema is `apex-contract/deployment/apex-deploy.schema.json`.
APEX reserves one dedicated server for one product, archives the selected Git SHA,
and only reports Docker readiness after the declared service's real healthcheck.

Mode: **docker**. Required parameters: BSDM_IMAGE_TAG, PROXY_BIND, BSDM_SECRETS_DIR, BSDM_CERTS_DIR.
Also provide `APEX_GATEWAY_URL` and `APEX_SERVICE_URL`. They declare the integration
addresses; domain-specific adapters and credentials still require operator configuration.
Secrets must never be committed. The platform's `deployment/install.py` asks for SSH
key paths and lets OpenSSH request passwords/passphrases in the terminal.
Environment values are entered with hidden input and written to a protected
`/etc/apex/bsdm-proxy.env` on the target only on explicit first-time setup.

Recipe: `deploy/compose/docker-compose.apex.yml`; readiness service: `proxy`.
Run `docker compose --env-file /etc/apex/bsdm-proxy.env -p apex-bsdm-proxy -f deploy/compose/docker-compose.apex.yml config --quiet` before installation.
Published images should be verified and selected by digest. Build/healthcheck validation
is not physical-server acceptance. Root or prepared `/opt/apex` and Docker permissions
are required. A host reverse proxy with trusted TLS must expose loopback-bound APIs
to APEX; do not publish unauthenticated management ports.

The recipe preserves the existing GA production profile. Prepare the five secret files, CA, ownership and ACL described in docker-compose.prod.yml first. BSDM_SECRETS_DIR and BSDM_CERTS_DIR must be absolute paths outside the version archive. This script does not manufacture MITM CA or client credentials.
