//! M5.4 C&C beacon ML scoring — augments alert-worker `beacon_periodic`.
//!
//! Scores `(client_ip, domain)` pairs with regular inter-arrival gaps plus
//! behavioral signals (small payloads, POST ratio, off-hours traffic).

use crate::config::Config;
use crate::scoring::{severity_for, ScoreResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const MODEL_CC_BEACON: &str = "cc_beacon_v0";

/// Aggregated client→domain beacon window from ClickHouse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconPairFeatures {
    pub window_start: DateTime<Utc>,
    pub window_secs: u32,
    pub client_ip: String,
    pub domain: String,
    pub request_count: u64,
    pub gap_count: u64,
    pub avg_gap_secs: f64,
    pub gap_cv: f64,
    pub stddev_gap_secs: f64,
    pub post_count: u64,
    pub avg_response_size: f64,
    pub off_hours_count: u64,
    pub threat_hit_count: u64,
    pub unique_urls: u64,
    pub extracted_at: DateTime<Utc>,
}

impl BeaconPairFeatures {
    pub fn entity_id(&self) -> String {
        format!("{}|{}", self.client_ip, self.domain)
    }

    pub fn to_insert_json(&self) -> serde_json::Value {
        serde_json::json!({
            "window_start": self.window_start.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            "window_secs": self.window_secs,
            "client_ip": self.client_ip,
            "domain": self.domain,
            "request_count": self.request_count,
            "gap_count": self.gap_count,
            "avg_gap_secs": self.avg_gap_secs,
            "gap_cv": self.gap_cv,
            "stddev_gap_secs": self.stddev_gap_secs,
            "post_count": self.post_count,
            "avg_response_size": self.avg_response_size,
            "off_hours_count": self.off_hours_count,
            "threat_hit_count": self.threat_hit_count,
            "unique_urls": self.unique_urls,
            "extracted_at": self.extracted_at.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
        })
    }

    pub fn score_payload(&self, passes_periodic: bool) -> serde_json::Value {
        serde_json::json!({
            "client_ip": self.client_ip,
            "domain": self.domain,
            "gap_count": self.gap_count,
            "avg_gap_secs": self.avg_gap_secs,
            "gap_cv": self.gap_cv,
            "request_count": self.request_count,
            "post_ratio": post_ratio(self),
            "off_hours_ratio": ratio(self.off_hours_count, self.request_count),
            "avg_response_size": self.avg_response_size,
            "unique_urls": self.unique_urls,
            "threat_hit_count": self.threat_hit_count,
            "beacon_periodic_match": passes_periodic,
        })
    }
}

fn ratio(num: u64, den: u64) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64
    }
}

fn post_ratio(f: &BeaconPairFeatures) -> f64 {
    ratio(f.post_count, f.request_count)
}

/// Whether this pair passes M4 `beacon_periodic` thresholds (weak label).
pub fn passes_beacon_periodic(f: &BeaconPairFeatures, cfg: &Config) -> bool {
    f.gap_count >= cfg.beacon_min_hits
        && f.gap_cv <= cfg.beacon_max_gap_cv
        && f.avg_gap_secs >= cfg.beacon_min_interval_secs as f64
        && f.avg_gap_secs <= cfg.beacon_max_interval_secs as f64
}

/// C&C beacon score in \[0, 1\] — augments periodic heuristic with behavioral signals.
pub fn cc_beacon_v0(f: &BeaconPairFeatures, cfg: &Config) -> f64 {
    let periodic = passes_beacon_periodic(f, cfg);

    // Regularity: low gap_cv → high score (inverse mapping, cap at max_cv).
    let cv_cap = cfg.beacon_max_gap_cv.max(0.01);
    let regularity = if f.gap_count >= 2 {
        (1.0 - (f.gap_cv / cv_cap).min(1.0)).max(0.0)
    } else {
        0.0
    };

    // Volume: more regular gaps → higher confidence (saturates at 2× min_hits).
    let hit_norm = (f.gap_count as f64 / (cfg.beacon_min_hits as f64 * 2.0)).min(1.0);

    // Small fixed-size payloads typical of C&C beacons.
    let small_payload = if f.avg_response_size > 0.0 && f.avg_response_size < 512.0 {
        0.15
    } else if f.avg_response_size < 2048.0 {
        0.08
    } else {
        0.0
    };

    let post = post_ratio(f) * 0.12;
    let off_hours = ratio(f.off_hours_count, f.request_count) * 0.10;
    let low_url_diversity = if f.unique_urls <= 2 && f.request_count >= cfg.beacon_min_hits {
        0.12
    } else {
        0.0
    };
    let threat = if f.threat_hit_count > 0 { 0.15 } else { 0.0 };

    let behavioral = small_payload + post + off_hours + low_url_diversity + threat;
    let raw = 0.45 * regularity + 0.25 * hit_norm + behavioral;

    if periodic {
        // M4 beacon_periodic match is a strong weak label — floor the score.
        (0.55 * raw + 0.45 * 0.92).clamp(0.78, 1.0)
    } else {
        raw.clamp(0.0, 0.72)
    }
}

pub fn score_beacon_pair(f: &BeaconPairFeatures, cfg: &Config) -> ScoreResult {
    let periodic = passes_beacon_periodic(f, cfg);
    let score = cc_beacon_v0(f, cfg);
    let features_json =
        serde_json::to_string(&f.score_payload(periodic)).unwrap_or_else(|_| "{}".into());

    ScoreResult {
        scored_at: Utc::now(),
        entity_type: "client_domain".to_string(),
        entity_id: f.entity_id(),
        window_start: f.window_start,
        model: MODEL_CC_BEACON.to_string(),
        score,
        severity: severity_for(score, cfg.score_threshold).to_string(),
        features_json,
    }
}

/// SQL aligned with alert-worker `beacon_periodic` + enriched behavioral aggregates.
pub fn extract_sql(config: &Config) -> String {
    let lookback = config.beacon_lookback.as_secs();
    let min_gap = config.beacon_min_interval_secs;
    let max_gap = config.beacon_max_interval_secs;
    let min_hits = config.beacon_min_hits;
    let table = config.fq_source();

    format!(
        r#"
WITH ordered AS (
  SELECT
    toString(client_ip) AS client_ip,
    domain,
    ts,
    method,
    response_size,
    threat_sources,
    dateDiff(
      'second',
      lagInFrame(ts) OVER (PARTITION BY client_ip, domain ORDER BY ts),
      ts
    ) AS gap_sec
  FROM {table}
  WHERE ts >= now() - INTERVAL {lookback} SECOND
    AND domain != ''
),
gaps AS (
  SELECT
    client_ip,
    domain,
    gap_sec,
    method,
    response_size,
    threat_sources,
    ts
  FROM ordered
  WHERE gap_sec IS NOT NULL
    AND gap_sec BETWEEN {min_gap} AND {max_gap}
),
pair_stats AS (
  SELECT
    client_ip,
    domain,
    count() AS gap_count,
    avg(gap_sec) AS avg_gap_secs,
    if(avg(gap_sec) = 0, 1, stddevPop(gap_sec) / avg(gap_sec)) AS gap_cv,
    stddevPop(gap_sec) AS stddev_gap_secs
  FROM gaps
  GROUP BY client_ip, domain
  HAVING gap_count >= {min_hits}
),
req_stats AS (
  SELECT
    toString(client_ip) AS client_ip,
    domain,
    min(ts) AS window_start,
    count() AS request_count,
    countIf(method = 'POST') AS post_count,
    avg(response_size) AS avg_response_size,
    countIf(toHour(ts) >= 22 OR toHour(ts) < 6) AS off_hours_count,
    countIf(length(threat_sources) > 0) AS threat_hit_count,
    uniqExact(url) AS unique_urls
  FROM {table}
  WHERE ts >= now() - INTERVAL {lookback} SECOND
    AND domain != ''
  GROUP BY client_ip, domain
)
SELECT
  r.window_start AS window_start,
  toUInt32({lookback}) AS window_secs,
  p.client_ip AS client_ip,
  p.domain AS domain,
  r.request_count AS request_count,
  p.gap_count AS gap_count,
  p.avg_gap_secs AS avg_gap_secs,
  p.gap_cv AS gap_cv,
  p.stddev_gap_secs AS stddev_gap_secs,
  r.post_count AS post_count,
  r.avg_response_size AS avg_response_size,
  r.off_hours_count AS off_hours_count,
  r.threat_hit_count AS threat_hit_count,
  r.unique_urls AS unique_urls,
  now64(3) AS extracted_at
FROM pair_stats p
INNER JOIN req_stats r ON p.client_ip = r.client_ip AND p.domain = r.domain
ORDER BY p.gap_cv ASC, p.gap_count DESC
LIMIT 500
FORMAT JSONEachRow
"#
    )
}

pub fn features_from_row(
    row: &serde_json::Value,
) -> Result<BeaconPairFeatures, Box<dyn std::error::Error>> {
    Ok(BeaconPairFeatures {
        window_start: parse_ch_datetime(row.get("window_start"))?,
        window_secs: as_u64(row.get("window_secs"))? as u32,
        client_ip: as_string(row.get("client_ip"))?,
        domain: as_string(row.get("domain"))?,
        request_count: as_u64(row.get("request_count"))?,
        gap_count: as_u64(row.get("gap_count"))?,
        avg_gap_secs: as_f64(row.get("avg_gap_secs"))?,
        gap_cv: as_f64(row.get("gap_cv"))?,
        stddev_gap_secs: as_f64(row.get("stddev_gap_secs")).unwrap_or(0.0),
        post_count: as_u64(row.get("post_count"))?,
        avg_response_size: as_f64(row.get("avg_response_size")).unwrap_or(0.0),
        off_hours_count: as_u64(row.get("off_hours_count"))?,
        threat_hit_count: as_u64(row.get("threat_hit_count"))?,
        unique_urls: as_u64(row.get("unique_urls"))?,
        extracted_at: parse_ch_datetime(row.get("extracted_at")).unwrap_or_else(|_| Utc::now()),
    })
}

fn parse_ch_datetime(v: Option<&serde_json::Value>) -> Result<DateTime<Utc>, String> {
    let s = v
        .and_then(|x| x.as_str())
        .ok_or_else(|| "missing datetime".to_string())?;
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
    use chrono::TimeZone;
    use std::time::Duration;

    fn sample_cfg() -> Config {
        Config {
            clickhouse_url: "http://x".into(),
            clickhouse_database: "bsdm".into(),
            clickhouse_table: "http_cache".into(),
            features_table: "entity_features".into(),
            scores_table: "ml_scores".into(),
            phishing_features_table: "domain_phishing_features".into(),
            beacon_features_table: "beacon_pair_features".into(),
            clickhouse_user: None,
            clickhouse_password: None,
            poll_interval: Duration::from_secs(120),
            lookback: Duration::from_secs(300),
            entity_types: vec!["client_ip".into()],
            min_requests: 10,
            model: MODEL_CC_BEACON.into(),
            score_threshold: 0.8,
            baseline_lookback: Duration::from_secs(86400),
            baseline_min_samples: 30,
            z_clip: 4.0,
            baseline_path: None,
            beacon_lookback: Duration::from_secs(3600),
            beacon_min_hits: 5,
            beacon_min_interval_secs: 45,
            beacon_max_interval_secs: 900,
            beacon_max_gap_cv: 0.25,
            webhook_url: None,
            webhook_timeout: Duration::from_secs(10),
            metrics_port: 8091,
            source: "test".into(),
        }
    }

    fn sample_pair(gap_count: u64, gap_cv: f64, avg_gap: f64) -> BeaconPairFeatures {
        BeaconPairFeatures {
            window_start: Utc.with_ymd_and_hms(2026, 7, 17, 12, 0, 0).unwrap(),
            window_secs: 3600,
            client_ip: "10.0.0.42".into(),
            domain: "c2.example".into(),
            request_count: gap_count + 1,
            gap_count,
            avg_gap_secs: avg_gap,
            gap_cv,
            stddev_gap_secs: gap_cv * avg_gap,
            post_count: gap_count,
            avg_response_size: 128.0,
            off_hours_count: gap_count,
            threat_hit_count: 0,
            unique_urls: 1,
            extracted_at: Utc::now(),
        }
    }

    #[test]
    fn periodic_beacon_scores_high() {
        let cfg = sample_cfg();
        let f = sample_pair(8, 0.12, 120.0);
        assert!(passes_beacon_periodic(&f, &cfg));
        let s = cc_beacon_v0(&f, &cfg);
        assert!(s >= 0.78, "score={s}");
    }

    #[test]
    fn irregular_gaps_score_lower() {
        let cfg = sample_cfg();
        let f = sample_pair(8, 0.8, 120.0);
        assert!(!passes_beacon_periodic(&f, &cfg));
        let s = cc_beacon_v0(&f, &cfg);
        assert!(s < 0.72, "score={s}");
    }

    #[test]
    fn entity_id_format() {
        let f = sample_pair(5, 0.1, 60.0);
        assert_eq!(f.entity_id(), "10.0.0.42|c2.example");
    }

    #[test]
    fn extract_sql_mentions_beacon_fields() {
        let sql = extract_sql(&sample_cfg());
        assert!(sql.contains("gap_cv"));
        assert!(sql.contains("off_hours_count"));
        assert!(sql.contains("BETWEEN"));
    }
}
