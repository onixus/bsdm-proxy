//! Population baseline for unsupervised UEBA (M5.2).
//!
//! Stats are computed from historical `entity_features` rows in ClickHouse
//! (or loaded from a JSON artifact via `ML_BASELINE_PATH`).

use crate::config::Config;
use crate::features::EntityFeatures;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Per-feature mean/stddev for one `entity_type`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeatureMoments {
    pub mean: f64,
    pub std: f64,
}

impl FeatureMoments {
    pub fn z(&self, value: f64, eps: f64) -> f64 {
        let denom = if self.std.abs() < eps { eps } else { self.std };
        (value - self.mean) / denom
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntityTypeBaseline {
    pub entity_type: String,
    pub sample_count: u64,
    pub request_count: FeatureMoments,
    pub unique_domains: FeatureMoments,
    pub unique_urls: FeatureMoments,
    pub deny_count: FeatureMoments,
    pub threat_hit_count: FeatureMoments,
    pub job_search_count: FeatureMoments,
    pub avg_response_size: FeatureMoments,
    pub avg_duration_ms: FeatureMoments,
    pub gap_cv: FeatureMoments,
    pub max_domain_len: FeatureMoments,
    pub deny_ratio: FeatureMoments,
    pub threat_ratio: FeatureMoments,
    pub job_search_ratio: FeatureMoments,
}

impl EntityTypeBaseline {
    /// Mean absolute z-score clipped to `z_clip`, mapped to \[0, 1\].
    pub fn score(&self, features: &EntityFeatures, z_clip: f64) -> f64 {
        let clip = z_clip.max(1.0);
        let eps = 1e-6;
        let deny_ratio = ratio(features.deny_count, features.request_count);
        let threat_ratio = ratio(features.threat_hit_count, features.request_count);

        let zs = [
            self.request_count.z(features.request_count as f64, eps),
            self.unique_domains.z(features.unique_domains as f64, eps),
            self.unique_urls.z(features.unique_urls as f64, eps),
            self.deny_count.z(features.deny_count as f64, eps),
            self.threat_hit_count
                .z(features.threat_hit_count as f64, eps),
            self.avg_response_size.z(features.avg_response_size, eps),
            self.avg_duration_ms.z(features.avg_duration_ms, eps),
            self.gap_cv.z(features.gap_cv, eps),
            self.max_domain_len.z(features.max_domain_len as f64, eps),
            self.deny_ratio.z(deny_ratio, eps),
            self.threat_ratio.z(threat_ratio, eps),
        ];

        // Blend mean and max of clipped |z| so a few extreme features still surface.
        let clipped: Vec<f64> = zs.iter().map(|z| z.abs().min(clip) / clip).collect();
        let mean = clipped.iter().sum::<f64>() / clipped.len() as f64;
        let max = clipped.iter().cloned().fold(0.0_f64, f64::max);
        (0.4 * mean + 0.6 * max).clamp(0.0, 1.0)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineSet {
    pub baselines: HashMap<String, EntityTypeBaseline>,
    pub source: String,
}

impl BaselineSet {
    pub fn get(&self, entity_type: &str) -> Option<&EntityTypeBaseline> {
        self.baselines.get(entity_type)
    }

    pub fn is_empty(&self) -> bool {
        self.baselines.is_empty()
    }

    pub fn load_json_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let raw = std::fs::read_to_string(path)?;
        let set: BaselineSet = serde_json::from_str(&raw)?;
        Ok(set)
    }
}

pub fn baseline_sql(config: &Config) -> String {
    let table = config.fq_features();
    let lookback = config.baseline_lookback.as_secs();
    let min_n = config.baseline_min_samples;
    format!(
        r#"
SELECT
  entity_type,
  count() AS sample_count,
  avg(request_count) AS mean_request_count,
  ifNull(stddevSamp(request_count), 0) AS std_request_count,
  avg(unique_domains) AS mean_unique_domains,
  ifNull(stddevSamp(unique_domains), 0) AS std_unique_domains,
  avg(unique_urls) AS mean_unique_urls,
  ifNull(stddevSamp(unique_urls), 0) AS std_unique_urls,
  avg(deny_count) AS mean_deny_count,
  ifNull(stddevSamp(deny_count), 0) AS std_deny_count,
  avg(threat_hit_count) AS mean_threat_hit_count,
  ifNull(stddevSamp(threat_hit_count), 0) AS std_threat_hit_count,
  avg(job_search_count) AS mean_job_search_count,
  ifNull(stddevSamp(job_search_count), 0) AS std_job_search_count,
  avg(avg_response_size) AS mean_avg_response_size,
  ifNull(stddevSamp(avg_response_size), 0) AS std_avg_response_size,
  avg(avg_duration_ms) AS mean_avg_duration_ms,
  ifNull(stddevSamp(avg_duration_ms), 0) AS std_avg_duration_ms,
  avg(gap_cv) AS mean_gap_cv,
  ifNull(stddevSamp(gap_cv), 0) AS std_gap_cv,
  avg(max_domain_len) AS mean_max_domain_len,
  ifNull(stddevSamp(max_domain_len), 0) AS std_max_domain_len,
  avg(if(request_count = 0, 0, deny_count / request_count)) AS mean_deny_ratio,
  ifNull(stddevSamp(if(request_count = 0, 0, deny_count / request_count)), 0) AS std_deny_ratio,
  avg(if(request_count = 0, 0, threat_hit_count / request_count)) AS mean_threat_ratio,
  ifNull(stddevSamp(if(request_count = 0, 0, threat_hit_count / request_count)), 0) AS std_threat_ratio,
  avg(if(request_count = 0, 0, job_search_count / request_count)) AS mean_job_search_ratio,
  ifNull(stddevSamp(if(request_count = 0, 0, job_search_count / request_count)), 0) AS std_job_search_ratio
FROM {table}
WHERE extracted_at >= now() - INTERVAL {lookback} SECOND
GROUP BY entity_type
HAVING sample_count >= {min_n}
FORMAT JSONEachRow
"#
    )
}

pub fn baseline_from_row(
    row: &serde_json::Value,
) -> Result<EntityTypeBaseline, Box<dyn std::error::Error>> {
    Ok(EntityTypeBaseline {
        entity_type: as_string(row.get("entity_type"))?,
        sample_count: as_u64(row.get("sample_count"))?,
        request_count: moments(row, "request_count")?,
        unique_domains: moments(row, "unique_domains")?,
        unique_urls: moments(row, "unique_urls")?,
        deny_count: moments(row, "deny_count")?,
        threat_hit_count: moments(row, "threat_hit_count")?,
        job_search_count: moments(row, "job_search_count").unwrap_or(FeatureMoments {
            mean: 0.0,
            std: 0.0,
        }),
        avg_response_size: moments(row, "avg_response_size")?,
        avg_duration_ms: moments(row, "avg_duration_ms")?,
        gap_cv: moments(row, "gap_cv")?,
        max_domain_len: moments(row, "max_domain_len")?,
        deny_ratio: moments(row, "deny_ratio")?,
        threat_ratio: moments(row, "threat_ratio")?,
        job_search_ratio: moments(row, "job_search_ratio").unwrap_or(FeatureMoments {
            mean: 0.0,
            std: 0.0,
        }),
    })
}

pub fn baselines_from_rows(
    rows: &[serde_json::Value],
    source: &str,
) -> Result<BaselineSet, Box<dyn std::error::Error>> {
    let mut set = BaselineSet {
        baselines: HashMap::new(),
        source: source.to_string(),
    };
    for row in rows {
        let b = baseline_from_row(row)?;
        set.baselines.insert(b.entity_type.clone(), b);
    }
    Ok(set)
}

fn moments(row: &serde_json::Value, name: &str) -> Result<FeatureMoments, String> {
    let mean_key = format!("mean_{name}");
    let std_key = format!("std_{name}");
    Ok(FeatureMoments {
        mean: as_f64(row.get(mean_key.as_str()))?,
        std: as_f64(row.get(std_key.as_str())).unwrap_or(0.0),
    })
}

fn ratio(num: u64, den: u64) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64
    }
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
    use chrono::{TimeZone, Utc};

    fn feats(requests: u64, deny: u64) -> EntityFeatures {
        EntityFeatures {
            window_start: Utc.with_ymd_and_hms(2026, 7, 16, 12, 0, 0).unwrap(),
            window_secs: 300,
            entity_type: "client_ip".into(),
            entity_id: "10.0.0.1".into(),
            request_count: requests,
            unique_domains: 3,
            unique_urls: 5,
            deny_count: deny,
            threat_hit_count: 0,
            job_search_count: 0,
            avg_response_size: 100.0,
            avg_duration_ms: 10.0,
            gap_cv: 0.5,
            max_domain_len: 12,
            extracted_at: Utc::now(),
        }
    }

    fn normal_baseline() -> EntityTypeBaseline {
        let m = |mean: f64, std: f64| FeatureMoments { mean, std };
        EntityTypeBaseline {
            entity_type: "client_ip".into(),
            sample_count: 100,
            request_count: m(20.0, 5.0),
            unique_domains: m(3.0, 1.0),
            unique_urls: m(5.0, 2.0),
            deny_count: m(1.0, 1.0),
            threat_hit_count: m(0.0, 0.5),
            avg_response_size: m(100.0, 20.0),
            avg_duration_ms: m(10.0, 3.0),
            gap_cv: m(0.5, 0.2),
            max_domain_len: m(12.0, 4.0),
            deny_ratio: m(0.05, 0.05),
            threat_ratio: m(0.0, 0.05),
            job_search_count: m(0.0, 0.1),
            job_search_ratio: m(0.0, 0.01),
        }
    }

    #[test]
    fn typical_entity_scores_low() {
        let s = normal_baseline().score(&feats(20, 1), 4.0);
        assert!(s < 0.35, "score={s}");
    }

    #[test]
    fn burst_entity_scores_high() {
        let s = normal_baseline().score(&feats(200, 150), 4.0);
        assert!(s >= 0.5, "score={s}");
    }

    #[test]
    fn parses_baseline_row() {
        let row = serde_json::json!({
            "entity_type": "client_ip",
            "sample_count": 50,
            "mean_request_count": 20.0,
            "std_request_count": 5.0,
            "mean_unique_domains": 3.0,
            "std_unique_domains": 1.0,
            "mean_unique_urls": 5.0,
            "std_unique_urls": 2.0,
            "mean_deny_count": 1.0,
            "std_deny_count": 1.0,
            "mean_threat_hit_count": 0.0,
            "std_threat_hit_count": 0.5,
            "mean_avg_response_size": 100.0,
            "std_avg_response_size": 20.0,
            "mean_avg_duration_ms": 10.0,
            "std_avg_duration_ms": 3.0,
            "mean_gap_cv": 0.5,
            "std_gap_cv": 0.2,
            "mean_max_domain_len": 12.0,
            "std_max_domain_len": 4.0,
            "mean_deny_ratio": 0.05,
            "std_deny_ratio": 0.05,
            "mean_threat_ratio": 0.0,
            "std_threat_ratio": 0.05
        });
        let b = baseline_from_row(&row).unwrap();
        assert_eq!(b.sample_count, 50);
        assert!((b.request_count.mean - 20.0).abs() < 1e-9);
    }
}
