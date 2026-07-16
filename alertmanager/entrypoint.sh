#!/bin/sh
# Render alertmanager.yml from template; attach webhook only when ALERT_WEBHOOK_URL is set.
set -eu
TPL=/etc/alertmanager/alertmanager.yml.tpl
OUT=/tmp/alertmanager.yml

if [ -n "${ALERT_WEBHOOK_URL:-}" ]; then
  WEBHOOK_BLOCK=$(cat <<EOF
    webhook_configs:
      - url: '${ALERT_WEBHOOK_URL}'
        send_resolved: true
        http_config:
          follow_redirects: true
EOF
)
else
  # No SIEM URL: keep receiver name so routes resolve; notifications are dropped.
  WEBHOOK_BLOCK="    # ALERT_WEBHOOK_URL unset — notifications discarded"
fi

# shellcheck disable=SC2016
awk -v block="$WEBHOOK_BLOCK" '
  /__WEBHOOK_BLOCK__/ { print block; next }
  { print }
' "$TPL" >"$OUT"

exec /bin/alertmanager \
  --config.file="$OUT" \
  --storage.path=/alertmanager \
  --web.listen-address=:9093
