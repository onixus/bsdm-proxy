#!/usr/bin/env bash
set -euo pipefail
PREFIX="${PREFIX:-/opt/bsdm-agent}"
if [[ "$(id -u)" -ne 0 ]]; then echo "run as root" >&2; exit 1; fi
systemctl disable --now bsdm-agent 2>/dev/null || true
rm -f /etc/systemd/system/bsdm-agent.service
systemctl daemon-reload 2>/dev/null || true
if [[ -x "${PREFIX}/bin/bsdm-agent" ]]; then
  "${PREFIX}/bin/bsdm-agent" --clear-system-proxy 2>/dev/null || true
fi
rm -rf "${PREFIX}"
echo "bsdm-agent removed (config in /etc/bsdm-agent left in place)"
