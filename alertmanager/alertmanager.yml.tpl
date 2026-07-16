# Generated at container start from alertmanager.yml.tpl — do not edit the runtime file.
global:
  resolve_timeout: 5m

route:
  receiver: default
  group_by: [alertname, severity, team]
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  routes:
    - matchers:
        - team = "bsdm-m4"
      receiver: siem-webhook

receivers:
  - name: default
  - name: siem-webhook
__WEBHOOK_BLOCK__

inhibit_rules:
  - source_matchers:
      - severity = "critical"
    target_matchers:
      - severity = "warning"
    equal: [alertname, team]
