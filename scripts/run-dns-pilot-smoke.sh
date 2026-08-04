#!/usr/bin/env bash
# Smoke: DNS sinkhole health + block/allow dig checks (Hybrid first hop).
#
# Prerequisites: dns-sinkhole container healthy (compose default service).
#
# Usage:
#   ./scripts/run-dns-pilot-smoke.sh
#   DNS_HOST=127.0.0.1 DNS_PORT=5353 ./scripts/run-dns-pilot-smoke.sh
set -euo pipefail

DNS_HOST="${DNS_HOST:-127.0.0.1}"
DNS_PORT="${DNS_PORT:-5353}"
METRICS_URL="${DNS_METRICS_URL:-http://127.0.0.1:8092}"
BLOCKED_QNAME="${DNS_BLOCKED_QNAME:-blocked.test}"
ALLOWED_QNAME="${DNS_ALLOWED_QNAME:-example.com}"
SINKHOLE_A="${DNS_SINKHOLE_A:-127.0.0.1}"
TIMEOUT="${TIMEOUT:-5}"

echo "============================================================"
echo " DNS sinkhole pilot smoke"
echo " Resolver:  ${DNS_HOST}:${DNS_PORT}"
echo " Metrics:   ${METRICS_URL}"
echo " Blocked:   ${BLOCKED_QNAME} → expect ${SINKHOLE_A}"
echo " Allowed:   ${ALLOWED_QNAME} → expect non-empty forward"
echo "============================================================"

if ! command -v dig >/dev/null 2>&1; then
  echo "❌ dig not found (install bind-tools / dnsutils)" >&2
  exit 1
fi

if ! curl -fsS --max-time "$TIMEOUT" "${METRICS_URL}/health" >/dev/null 2>&1; then
  echo "❌ dns-sinkhole not healthy at ${METRICS_URL}/health" >&2
  echo "   Start: docker compose up -d dns-sinkhole" >&2
  echo "   Or:    docker compose -f docker-compose.yml -f docker-compose.pilot.yml up -d dns-sinkhole" >&2
  exit 1
fi
echo "✅ Health OK"

blocked="$(
  dig @"${DNS_HOST}" -p "${DNS_PORT}" "${BLOCKED_QNAME}" A +short +time="${TIMEOUT}" +tries=1 2>/dev/null \
    | head -1 | tr -d '[:space:]' || true
)"
if [[ "$blocked" != "$SINKHOLE_A" ]]; then
  # NXDOMAIN path: empty short + status NXDOMAIN
  status="$(
    dig @"${DNS_HOST}" -p "${DNS_PORT}" "${BLOCKED_QNAME}" A +time="${TIMEOUT}" +tries=1 2>/dev/null \
      | awk '/status:/{print $6}' | tr -d ',' || true
  )"
  if [[ "${status}" == "NXDOMAIN" ]]; then
    echo "✅ Blocked ${BLOCKED_QNAME} → NXDOMAIN"
  else
    echo "❌ Blocked ${BLOCKED_QNAME}: expected ${SINKHOLE_A} or NXDOMAIN, got '${blocked}' status='${status}'" >&2
    exit 1
  fi
else
  echo "✅ Blocked ${BLOCKED_QNAME} → ${blocked}"
fi

# Hybrid load-test default qname
if [[ "${BLOCKED_QNAME}" != "badsite.test" ]]; then
  badsite="$(
    dig @"${DNS_HOST}" -p "${DNS_PORT}" badsite.test A +short +time="${TIMEOUT}" +tries=1 2>/dev/null \
      | head -1 | tr -d '[:space:]' || true
  )"
  if [[ "$badsite" == "$SINKHOLE_A" || -z "$badsite" ]]; then
    echo "✅ badsite.test (load-test qname) blocked/empty-ok: '${badsite}'"
  else
    echo "⚠ badsite.test returned '${badsite}' (add to zone if you need load-test DNS share)"
  fi
fi

allowed="$(
  dig @"${DNS_HOST}" -p "${DNS_PORT}" "${ALLOWED_QNAME}" A +short +time="${TIMEOUT}" +tries=2 2>/dev/null \
    | head -1 | tr -d '[:space:]' || true
)"
if [[ -z "$allowed" ]]; then
  echo "❌ Allowed ${ALLOWED_QNAME}: empty answer (upstream ${DNS_HOST} forward failed?)" >&2
  exit 1
fi
if [[ "$allowed" == "$SINKHOLE_A" ]]; then
  echo "❌ Allowed ${ALLOWED_QNAME} incorrectly sinkholed to ${SINKHOLE_A}" >&2
  exit 1
fi
echo "✅ Allowed ${ALLOWED_QNAME} → ${allowed}"

metrics="$(curl -fsS --max-time "$TIMEOUT" "${METRICS_URL}/metrics" 2>/dev/null || true)"
if echo "$metrics" | grep -q 'dns\|sinkhole\|query\|bsdm'; then
  echo "✅ Metrics endpoint returns data"
else
  echo "⚠ Metrics body has no dns-like series (still OK if /health works)"
fi

echo "============================================================"
echo " DNS pilot smoke PASSED"
echo "============================================================"
echo "Load-test DNS share:"
echo "  DNS_HOST=${DNS_HOST} DNS_PORT=${DNS_PORT} DNS_QNAME=badsite.test \\"
echo "    ./scripts/run-hybrid-load-test.sh"
