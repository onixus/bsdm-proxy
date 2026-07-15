//! Built-in ClickHouse alerting rules (M4 starters).

use crate::config::Config;
use crate::payload::Finding;
use serde_json::Value;
use std::collections::BTreeMap;

pub fn build_queries(config: &Config) -> Vec<(String, String)> {
    let table = config.fq_table();
    let lookback = config.lookback.as_secs();
    let mut out = Vec::new();

    for rule in &config.rules {
        let sql = match rule.as_str() {
            "blocked_burst" => Some(format!(
                r#"SELECT
  coalesce(username, '') AS username,
  toString(client_ip) AS client_ip,
  count() AS value
FROM {table}
WHERE ts >= now() - INTERVAL {lookback} SECOND
  AND (acl_action = 'deny' OR cache_status = 'DENY')
GROUP BY username, client_ip
HAVING value >= {threshold}
ORDER BY value DESC
LIMIT 100
FORMAT JSONEachRow"#,
                threshold = config.blocked_burst_threshold
            )),
            "domain_burst" => Some(format!(
                r#"SELECT
  toString(client_ip) AS client_ip,
  domain,
  count() AS value
FROM {table}
WHERE ts >= now() - INTERVAL {lookback} SECOND
  AND domain != ''
GROUP BY client_ip, domain
HAVING value >= {threshold}
ORDER BY value DESC
LIMIT 100
FORMAT JSONEachRow"#,
                threshold = config.domain_burst_threshold
            )),
            "off_hours_threat" => Some(format!(
                r#"SELECT
  coalesce(username, '') AS username,
  toString(client_ip) AS client_ip,
  domain,
  count() AS value
FROM {table}
WHERE ts >= now() - INTERVAL {lookback} SECOND
  AND (toHour(ts) >= 22 OR toHour(ts) < 6)
  AND length(threat_sources) > 0
GROUP BY username, client_ip, domain
HAVING value >= {threshold}
ORDER BY value DESC
LIMIT 100
FORMAT JSONEachRow"#,
                threshold = config.off_hours_min_events
            )),
            "high_entropy_domain" => Some(format!(
                r#"SELECT
  domain,
  count() AS value,
  uniqExact(client_ip) AS clients
FROM {table}
WHERE ts >= now() - INTERVAL {lookback} SECOND
  AND length(domain) >= 25
  AND match(domain, '[0-9]{{4,}}')
GROUP BY domain
HAVING value >= {threshold}
ORDER BY value DESC
LIMIT 50
FORMAT JSONEachRow"#,
                threshold = config.high_entropy_min_requests
            )),
            other => {
                tracing::warn!("unknown ALERT_RULES entry ignored: {other}");
                None
            }
        };
        if let Some(sql) = sql {
            out.push((rule.clone(), sql));
        }
    }
    out
}

pub fn findings_from_rows(rule: &str, rows: &[Value]) -> Vec<Finding> {
    rows.iter()
        .filter_map(|row| find_from_row(rule, row))
        .collect()
}

fn find_from_row(rule: &str, row: &Value) -> Option<Finding> {
    let value = json_number(row.get("value")?)?;
    let mut labels = BTreeMap::new();
    for key in ["username", "client_ip", "domain"] {
        if let Some(v) = row.get(key).and_then(|x| x.as_str()) {
            if !v.is_empty() {
                labels.insert(key.to_string(), v.to_string());
            }
        }
    }
    if let Some(clients) = row.get("clients").and_then(json_number) {
        labels.insert("clients".into(), clients.to_string());
    }

    let (severity, title, description) = match rule {
        "blocked_burst" => (
            "critical",
            "ACL deny burst".to_string(),
            format!(
                "Client hit {value} blocked requests in the lookback window (user/IP threshold exceeded)"
            ),
        ),
        "domain_burst" => (
            "warning",
            "Domain request burst".to_string(),
            format!("Same client issued {value} requests to one domain in the lookback window"),
        ),
        "off_hours_threat" => (
            "warning",
            "Off-hours threat traffic".to_string(),
            format!(
                "{value} threat-tagged request(s) between 22:00–06:00 UTC in the lookback window"
            ),
        ),
        "high_entropy_domain" => (
            "warning",
            "Suspicious high-entropy domain".to_string(),
            format!(
                "Domain matched long/numeric heuristic with {value} request(s) in the lookback window"
            ),
        ),
        _ => return None,
    };

    Some(Finding {
        rule: rule.to_string(),
        severity: severity.to_string(),
        title,
        description,
        value,
        labels,
    })
}

fn json_number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sample_config(rules: &[&str]) -> Config {
        Config {
            webhook_url: "http://example.test/hook".into(),
            webhook_timeout: Duration::from_secs(5),
            webhook_headers: Default::default(),
            clickhouse_url: "http://ch:8123".into(),
            clickhouse_database: "bsdm".into(),
            clickhouse_table: "http_cache".into(),
            clickhouse_user: None,
            clickhouse_password: None,
            poll_interval: Duration::from_secs(60),
            lookback: Duration::from_secs(300),
            dedupe_ttl: Duration::from_secs(3600),
            metrics_port: 8090,
            source: "test".into(),
            rules: rules.iter().map(|s| (*s).to_string()).collect(),
            blocked_burst_threshold: 10,
            domain_burst_threshold: 50,
            high_entropy_min_requests: 5,
            off_hours_min_events: 1,
        }
    }

    #[test]
    fn builds_known_rules() {
        let q = build_queries(&sample_config(&[
            "blocked_burst",
            "domain_burst",
            "off_hours_threat",
            "high_entropy_domain",
            "nope",
        ]));
        assert_eq!(q.len(), 4);
        assert!(q[0].1.contains("acl_action = 'deny'"));
        assert!(q[1].1.contains("HAVING value >= 50"));
        assert!(q[2].1.contains("toHour(ts)"));
        assert!(q[3].1.contains("length(domain) >= 25"));
    }

    #[test]
    fn maps_blocked_burst_row() {
        let row = serde_json::json!({
            "username": "alice",
            "client_ip": "10.0.0.1",
            "value": 15
        });
        let findings = findings_from_rows("blocked_burst", &[row]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "critical");
        assert_eq!(
            findings[0].labels.get("username").map(String::as_str),
            Some("alice")
        );
        assert_eq!(findings[0].value, 15.0);
    }
}
