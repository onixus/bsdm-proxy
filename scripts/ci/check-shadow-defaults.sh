#!/usr/bin/env bash
# Regression gate for the fail-safe Threat-Intel Shadow Mode (issue #330).
#
# The Rust tests pin the *code* default (threat-intel/src/config.rs). Nothing
# stopped a deployment default from drifting: one `TI_ENFORCEMENT_MODE=enforce`
# in docker-compose.yml or `enforcementMode: enforce` in values.yaml and a pilot
# starts blocking traffic from feed data without a decision. This gate fails the
# build on that drift and on the neighbouring safety properties: the observe-only
# `.shadow` artifact path, the read-only mount into the proxy, and the admin/SOAR
# API not being published to the host.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

fail=0
check() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf '  ok   %s\n' "$description"
  else
    printf '  FAIL %s\n' "$description" >&2
    fail=1
  fi
}

not() { ! "$@"; }

printf '\n==> Threat-intel Shadow Mode defaults\n'

check "Dockerfile threat-intel stage defaults to shadow" \
  grep -qE '^\s*TI_ENFORCEMENT_MODE=shadow' Dockerfile

check "docker-compose.yml defaults TI_ENFORCEMENT_MODE to shadow" \
  grep -qE 'TI_ENFORCEMENT_MODE=\$\{TI_ENFORCEMENT_MODE:-shadow\}' docker-compose.yml

check "helm values default enforcementMode to shadow" \
  grep -qE '^\s*enforcementMode:\s*shadow\s*$' charts/bsdm/values.yaml

check "helm template falls back to shadow when the value is empty" \
  grep -qE 'enforcementMode \| default "shadow"' charts/bsdm/templates/threat-intel-deployment.yaml

check "packaging env example ships TI_ENFORCEMENT_MODE=shadow" \
  grep -qE '^TI_ENFORCEMENT_MODE=shadow$' packaging/config/threat-intel.env.example

check "no deployment file hardcodes enforce as a default" \
  not grep -rInE '^[^#]*TI_ENFORCEMENT_MODE[=:][[:space:]]*"?enforce' \
    --exclude="check-shadow-defaults.sh" \
    Dockerfile docker-compose.yml docker-compose.override.yml deploy charts packaging config scripts

check "proxy reads the observe-only .shadow artifact (compose)" \
  grep -qE 'TI_SHADOW_FEED_PATH=.*\.shadow' docker-compose.yml

check "proxy reads the observe-only .shadow artifact (env reference)" \
  grep -qE '^TI_SHADOW_FEED_PATH=.*\.shadow$' bsdm-proxy.env

check "threat-intel snapshots are mounted read-only into the proxy" \
  grep -qE 'threat-intel-data:/var/lib/bsdm-proxy/threat-intel:ro' docker-compose.yml

check "admin/SOAR port 8093 is not published to the host" \
  not grep -rInE '^[^#]*"[0-9]+:8093"' docker-compose.yml docker-compose.override.yml deploy 2>/dev/null

check "no deployment file enables TI_API_ALLOW_INSECURE" \
  not grep -rInE '^[^#]*TI_API_ALLOW_INSECURE[=:][[:space:]]*"?(1|true|yes)' \
    --exclude="check-shadow-defaults.sh" \
    Dockerfile docker-compose.yml docker-compose.override.yml deploy charts packaging config scripts

check "threat-intel scrape job exists so shadow metrics are collected" \
  grep -q "job_name: 'threat-intel'" prometheus/prometheus.yml

check "an alert fires when threat-intel starts enforcing" \
  grep -q 'BsdmTiEnforcementActive' prometheus/alerts/ti_shadow.yml

if (( fail )); then
  cat >&2 <<'MSG'

Shadow Mode defaults regressed. Enforcement must stay an explicit, per-deployment
opt-in (TI_ENFORCEMENT_MODE=enforce set by the operator), never a shipped default.
See docs ADR-0008 and issue #330.
MSG
  exit 1
fi

printf 'Shadow Mode defaults intact.\n'
