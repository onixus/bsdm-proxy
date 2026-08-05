#!/usr/bin/env bash
set -euo pipefail
PREFIX="${PREFIX:-/usr/local/bsdm-agent}"
if [[ "$(id -u)" -ne 0 ]]; then echo "run as root" >&2; exit 1; fi
launchctl bootout system/com.bsdm.agent 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.bsdm.agent.plist
if [[ -x "${PREFIX}/bin/bsdm-agent" ]]; then
  "${PREFIX}/bin/bsdm-agent" --clear-system-proxy 2>/dev/null || true
fi
rm -rf "${PREFIX}"
echo "bsdm-agent removed (config under /usr/local/etc/bsdm-agent left in place)"
