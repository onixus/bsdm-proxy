//! Built-in ClickHouse alerting rules (M4 starters + C&C beacon).

use crate::config::Config;
use crate::entropy::matches_high_entropy;
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
  AND length(domain) >= {min_len}
GROUP BY domain
HAVING value >= {threshold}
ORDER BY value DESC
LIMIT 200
FORMAT JSONEachRow"#,
                threshold = config.high_entropy_min_requests,
                min_len = config.high_entropy_min_domain_len
            )),
            "beacon_periodic" => {
                let beacon_lb = config.beacon_lookback.as_secs();
                Some(format!(
                    r#"WITH ordered AS (
  SELECT
    toString(client_ip) AS client_ip,
    domain,
    ts,
    dateDiff(
      'second',
      lagInFrame(ts) OVER (PARTITION BY client_ip, domain ORDER BY ts),
      ts
    ) AS gap_sec
  FROM {table}
  WHERE ts >= now() - INTERVAL {beacon_lb} SECOND
    AND domain != ''
)
SELECT
  client_ip,
  domain,
  count() AS value,
  avg(gap_sec) AS avg_gap,
  if(avg(gap_sec) = 0, 1, stddevPop(gap_sec) / avg(gap_sec)) AS gap_cv
FROM ordered
WHERE gap_sec IS NOT NULL
  AND gap_sec BETWEEN {min_gap} AND {max_gap}
GROUP BY client_ip, domain
HAVING value >= {min_hits}
  AND gap_cv <= {max_cv}
ORDER BY value DESC
LIMIT 100
FORMAT JSONEachRow"#,
                    min_gap = config.beacon_min_interval_secs,
                    max_gap = config.beacon_max_interval_secs,
                    min_hits = config.beacon_min_hits,
                    max_cv = config.beacon_max_gap_cv,
                ))
            }
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

pub fn findings_from_rows(rule: &str, rows: &[Value], config: &Config) -> Vec<Finding> {
    rows.iter()
        .filter_map(|row| find_from_row(rule, row, config))
        .collect()
}

fn find_from_row(rule: &str, row: &Value, config: &Config) -> Option<Finding> {
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
    if let Some(avg_gap) = row.get("avg_gap").and_then(json_number) {
        labels.insert("avg_gap_secs".into(), format!("{avg_gap:.1}"));
    }
    if let Some(gap_cv) = row.get("gap_cv").and_then(json_number) {
        labels.insert("gap_cv".into(), format!("{gap_cv:.3}"));
    }

    // Shannon / legacy post-filter for high_entropy_domain
    if rule == "high_entropy_domain" {
        let domain = labels.get("domain")?.clone();
        let m = matches_high_entropy(
            &domain,
            config.high_entropy_mode,
            config.shannon_min_bits,
            config.shannon_min_label_len as usize,
            config.high_entropy_legacy_min_domain_len as usize,
        )?;
        labels.insert("shannon_bits".into(), format!("{:.3}", m.entropy));
        labels.insert("entropy_match".into(), m.kind_label().into());
    }

    let (severity, title, description, window_secs) = match rule {
        "blocked_burst" => (
            "critical",
            "ACL deny burst".to_string(),
            format!(
                "Client hit {value} blocked requests in the lookback window (user/IP threshold exceeded)"
            ),
            config.lookback.as_secs(),
        ),
        "domain_burst" => (
            "warning",
            "Domain request burst".to_string(),
            format!("Same client issued {value} requests to one domain in the lookback window"),
            config.lookback.as_secs(),
        ),
        "off_hours_threat" => (
            "warning",
            "Off-hours threat traffic".to_string(),
            format!(
                "{value} threat-tagged request(s) between 22:00–06:00 UTC in the lookback window"
            ),
            config.lookback.as_secs(),
        ),
        "high_entropy_domain" => {
            let bits = labels
                .get("shannon_bits")
                .cloned()
                .unwrap_or_else(|| "?".into());
            let kind = labels
                .get("entropy_match")
                .cloned()
                .unwrap_or_else(|| "shannon".into());
            (
                "warning",
                "Suspicious high-entropy domain".to_string(),
                format!(
                    "Domain matched {kind} heuristic (shannon={bits} bits/char) with {value} request(s) in the lookback window"
                ),
                config.lookback.as_secs(),
            )
        }
        "beacon_periodic" => {
            let avg = labels
                .get("avg_gap_secs")
                .cloned()
                .unwrap_or_else(|| "?".into());
            let cv = labels.get("gap_cv").cloned().unwrap_or_else(|| "?".into());
            (
                "warning",
                "Periodic C&C beacon candidate".to_string(),
                format!(
                    "Client→domain shows {value} regular intervals (avg_gap={avg}s, cv={cv}) — possible beacon"
                ),
                config.beacon_lookback.as_secs(),
            )
        }
        _ => return None,
    };

    Some(Finding {
        rule: rule.to_string(),
        severity: severity.to_string(),
        title,
        description,
        value,
        labels,
        window_secs,
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
            high_entropy_min_domain_len: 16,
            shannon_min_label_len: 12,
            shannon_min_bits: 3.5,
            high_entropy_mode: crate::entropy::HighEntropyMode::Either,
            high_entropy_legacy_min_domain_len: 25,
            off_hours_min_events: 1,
            beacon_lookback: Duration::from_secs(3600),
            beacon_min_hits: 5,
            beacon_min_interval_secs: 45,
            beacon_max_interval_secs: 900,
            beacon_max_gap_cv: 0.25,
        }
    }

    #[test]
    fn builds_known_rules() {
        let q = build_queries(&sample_config(&[
            "blocked_burst",
            "domain_burst",
            "off_hours_threat",
            "high_entropy_domain",
            "beacon_periodic",
            "nope",
        ]));
        assert_eq!(q.len(), 5);
        assert!(q[0].1.contains("acl_action = 'deny'"));
        assert!(q[1].1.contains("HAVING value >= 50"));
        assert!(q[2].1.contains("toHour(ts)"));
        assert!(q[3].1.contains("length(domain) >= 16"));
        assert!(!q[3].1.contains("match(domain"));
        assert!(q[4].1.contains("lagInFrame"));
        assert!(q[4].1.contains("gap_cv"));
        assert!(q[4].1.contains("INTERVAL 3600 SECOND"));
    }

    #[test]
    fn maps_blocked_burst_row() {
        let cfg = sample_config(&["blocked_burst"]);
        let row = serde_json::json!({
            "username": "alice",
            "client_ip": "10.0.0.1",
            "value": 15
        });
        let findings = findings_from_rows("blocked_burst", &[row], &cfg);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "critical");
        assert_eq!(
            findings[0].labels.get("username").map(String::as_str),
            Some("alice")
        );
        assert_eq!(findings[0].value, 15.0);
        assert_eq!(findings[0].window_secs, 300);
    }

    #[test]
    fn maps_beacon_row() {
        let cfg = sample_config(&["beacon_periodic"]);
        let row = serde_json::json!({
            "client_ip": "10.0.0.9",
            "domain": "c2.example",
            "value": 8,
            "avg_gap": 60.2,
            "gap_cv": 0.12
        });
        let findings = findings_from_rows("beacon_periodic", &[row], &cfg);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "beacon_periodic");
        assert_eq!(findings[0].window_secs, 3600);
        assert_eq!(
            findings[0].labels.get("domain").map(String::as_str),
            Some("c2.example")
        );
        assert!(findings[0].description.contains("beacon"));
    }

    #[test]
    fn high_entropy_requires_shannon_or_legacy() {
        let cfg = sample_config(&["high_entropy_domain"]);
        let dga = serde_json::json!({
            "domain": "xk9m2qp7wzb4cd.evil.net",
            "value": 9,
            "clients": 1
        });
        let findings = findings_from_rows("high_entropy_domain", &[dga], &cfg);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].labels.contains_key("shannon_bits"));
        assert!(findings[0].description.contains("shannon"));

        let boring = serde_json::json!({
            "domain": "cdn.example.com",
            "value": 20,
            "clients": 3
        });
        assert!(findings_from_rows("high_entropy_domain", &[boring], &cfg).is_empty());
    }
}
