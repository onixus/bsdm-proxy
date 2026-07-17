//! Feature extraction SQL and row parsing.

use crate::config::Config;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityFeatures {
    pub window_start: DateTime<Utc>,
    pub window_secs: u32,
    pub entity_type: String,
    pub entity_id: String,
    pub request_count: u64,
    pub unique_domains: u64,
    pub unique_urls: u64,
    pub deny_count: u64,
    pub threat_hit_count: u64,
    pub avg_response_size: f64,
    pub avg_duration_ms: f64,
    pub gap_cv: f64,
    pub max_domain_len: u64,
    pub extracted_at: DateTime<Utc>,
}

impl EntityFeatures {
    pub fn to_insert_json(&self) -> serde_json::Value {
        serde_json::json!({
            "window_start": self.window_start.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            "window_secs": self.window_secs,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "request_count": self.request_count,
            "unique_domains": self.unique_domains,
            "unique_urls": self.unique_urls,
            "deny_count": self.deny_count,
            "threat_hit_count": self.threat_hit_count,
            "avg_response_size": self.avg_response_size,
            "avg_duration_ms": self.avg_duration_ms,
            "gap_cv": self.gap_cv,
            "max_domain_len": self.max_domain_len,
            "extracted_at": self.extracted_at.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
        })
    }
}

/// Build aggregation SQL for one entity type over the lookback window.
pub fn extract_sql(config: &Config, entity_type: &str) -> String {
    let entity_expr = match entity_type {
        "client_ip" => "toString(client_ip)",
        "username" => "ifNull(username, '')",
        "domain" => "domain",
        other => panic!("unsupported entity_type: {other}"),
    };
    let lookback = config.lookback.as_secs();
    let min_req = config.min_requests;
    let table = config.fq_source();

    // gap_cv: coefficient of variation of inter-arrival times (0 if <2 events).
    format!(
        r#"
SELECT
  min(ts) AS window_start,
  toUInt32({lookback}) AS window_secs,
  '{entity_type}' AS entity_type,
  {entity_expr} AS entity_id,
  count() AS request_count,
  uniqExact(domain) AS unique_domains,
  uniqExact(url) AS unique_urls,
  countIf(acl_action = 'deny' OR cache_status = 'DENY') AS deny_count,
  countIf(length(threat_sources) > 0) AS threat_hit_count,
  avg(response_size) AS avg_response_size,
  avg(request_duration_ms) AS avg_duration_ms,
  if(
    count() < 3,
    0.0,
    ifNull(
      arrayReduce(
        'stddevPop',
        arrayDifference(arraySort(groupArray(toUnixTimestamp64Milli(ts))))
      )
      / nullIf(
        arrayReduce(
          'avg',
          arrayDifference(arraySort(groupArray(toUnixTimestamp64Milli(ts))))
        ),
        0
      ),
      0.0
    )
  ) AS gap_cv,
  max(length(domain)) AS max_domain_len,
  now64(3) AS extracted_at
FROM {table}
WHERE ts >= now() - INTERVAL {lookback} SECOND
  AND {entity_expr} != ''
GROUP BY entity_id
HAVING request_count >= {min_req}
FORMAT JSONEachRow
"#
    )
}

pub fn features_from_row(
    row: &serde_json::Value,
) -> Result<EntityFeatures, Box<dyn std::error::Error>> {
    let window_start = parse_ch_datetime(row.get("window_start"))?;
    let extracted_at = parse_ch_datetime(row.get("extracted_at")).unwrap_or_else(|_| Utc::now());
    Ok(EntityFeatures {
        window_start,
        window_secs: as_u64(row.get("window_secs"))? as u32,
        entity_type: as_string(row.get("entity_type"))?,
        entity_id: as_string(row.get("entity_id"))?,
        request_count: as_u64(row.get("request_count"))?,
        unique_domains: as_u64(row.get("unique_domains"))?,
        unique_urls: as_u64(row.get("unique_urls"))?,
        deny_count: as_u64(row.get("deny_count"))?,
        threat_hit_count: as_u64(row.get("threat_hit_count"))?,
        avg_response_size: as_f64(row.get("avg_response_size"))?,
        avg_duration_ms: as_f64(row.get("avg_duration_ms"))?,
        gap_cv: as_f64(row.get("gap_cv")).unwrap_or(0.0),
        max_domain_len: as_u64(row.get("max_domain_len"))?,
        extracted_at,
    })
}

fn parse_ch_datetime(v: Option<&serde_json::Value>) -> Result<DateTime<Utc>, String> {
    let s = v
        .and_then(|x| x.as_str())
        .ok_or_else(|| "missing datetime".to_string())?;
    // ClickHouse JSONEachRow: "2026-07-16 12:00:00.000"
    let normalized = if s.contains('T') {
        s.to_string()
    } else {
        s.replace(' ', "T") + "Z"
    };
    DateTime::parse_from_rfc3339(&normalized)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.3f")
                .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S"))
                .map(|ndt| ndt.and_utc())
                .map_err(|e| e.to_string())
        })
}

fn as_string(v: Option<&serde_json::Value>) -> Result<String, String> {
    v.and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "expected string".into())
}

fn as_u64(v: Option<&serde_json::Value>) -> Result<u64, String> {
    match v {
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .or_else(|| n.as_f64().map(|f| f as u64))
            .ok_or_else(|| "bad number".into()),
        Some(serde_json::Value::String(s)) => s.parse().map_err(|e| format!("{e}")),
        _ => Err("expected u64".into()),
    }
}

fn as_f64(v: Option<&serde_json::Value>) -> Result<f64, String> {
    match v {
        Some(serde_json::Value::Number(n)) => n.as_f64().ok_or_else(|| "bad float".into()),
        Some(serde_json::Value::String(s)) => s.parse().map_err(|e| format!("{e}")),
        _ => Err("expected f64".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_sql_mentions_entity_and_table() {
        let cfg = Config {
            clickhouse_url: "http://x".into(),
            clickhouse_database: "bsdm".into(),
            clickhouse_table: "http_cache".into(),
            features_table: "entity_features".into(),
            scores_table: "ml_scores".into(),
            phishing_features_table: "domain_phishing_features".into(),
            beacon_features_table: "beacon_pair_features".into(),
            score_cache_table: "threat_score_cache".into(),
            clickhouse_user: None,
            clickhouse_password: None,
            poll_interval: std::time::Duration::from_secs(60),
            lookback: std::time::Duration::from_secs(300),
            entity_types: vec!["client_ip".into()],
            min_requests: 10,
            model: "ueba_zscore_v0".into(),
            score_threshold: 0.8,
            baseline_lookback: std::time::Duration::from_secs(86400),
            baseline_min_samples: 30,
            z_clip: 4.0,
            baseline_path: None,
            beacon_lookback: std::time::Duration::from_secs(3600),
            beacon_min_hits: 5,
            beacon_min_interval_secs: 45,
            beacon_max_interval_secs: 900,
            beacon_max_gap_cv: 0.25,
            writeback_enabled: true,
            writeback_min_score: 0.5,
            writeback_ttl: std::time::Duration::from_secs(3600),
            webhook_url: None,
            webhook_timeout: std::time::Duration::from_secs(10),
            metrics_port: 8091,
            source: "test".into(),
        };
        let sql = extract_sql(&cfg, "client_ip");
        assert!(sql.contains("bsdm.http_cache"));
        assert!(sql.contains("toString(client_ip)"));
        assert!(sql.contains("HAVING request_count >= 10"));
    }

    #[test]
    fn parses_feature_row() {
        let row = serde_json::json!({
            "window_start": "2026-07-16 12:00:00.000",
            "window_secs": 300,
            "entity_type": "client_ip",
            "entity_id": "10.0.0.1",
            "request_count": 42,
            "unique_domains": 5,
            "unique_urls": 10,
            "deny_count": 2,
            "threat_hit_count": 1,
            "avg_response_size": 1024.5,
            "avg_duration_ms": 12.0,
            "gap_cv": 0.1,
            "max_domain_len": 24,
            "extracted_at": "2026-07-16 12:05:00.000"
        });
        let f = features_from_row(&row).unwrap();
        assert_eq!(f.entity_id, "10.0.0.1");
        assert_eq!(f.request_count, 42);
    }
}
