//! Scoring models: stub (M5.1) + UEBA z-score (M5.2).

use crate::baseline::{BaselineSet, EntityTypeBaseline};
use crate::features::EntityFeatures;
use chrono::{DateTime, Utc};
use serde::Serialize;

pub const MODEL_STUB: &str = "anomaly_stub_v0";
pub const MODEL_UEBA: &str = "ueba_zscore_v0";

#[derive(Debug, Clone, Serialize)]
pub struct ScoreResult {
    pub scored_at: DateTime<Utc>,
    pub entity_type: String,
    pub entity_id: String,
    pub window_start: DateTime<Utc>,
    pub model: String,
    pub score: f64,
    pub severity: String,
    pub features_json: String,
}

impl ScoreResult {
    pub fn to_insert_json(&self) -> serde_json::Value {
        serde_json::json!({
            "scored_at": self.scored_at.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "window_start": self.window_start.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            "model": self.model,
            "score": self.score,
            "severity": self.severity,
            "features_json": self.features_json,
        })
    }
}

/// Heuristic anomaly score in \[0, 1\] (M5.1 baseline / fallback).
pub fn anomaly_stub_v0(features: &EntityFeatures, min_requests: u64) -> f64 {
    let min_r = min_requests.max(1) as f64;
    let rate_component = ((features.request_count as f64) / (min_r * 5.0)).min(1.0);
    let deny_ratio = if features.request_count == 0 {
        0.0
    } else {
        features.deny_count as f64 / features.request_count as f64
    };
    let threat_ratio = if features.request_count == 0 {
        0.0
    } else {
        features.threat_hit_count as f64 / features.request_count as f64
    };
    let domain_spread = ((features.unique_domains as f64) / 20.0).min(1.0);
    let beacon_hint =
        if features.request_count >= 5 && features.gap_cv > 0.0 && features.gap_cv < 0.25 {
            0.15
        } else {
            0.0
        };

    let raw = 0.35 * rate_component
        + 0.30 * deny_ratio
        + 0.20 * threat_ratio
        + 0.10 * domain_spread
        + beacon_hint;
    raw.clamp(0.0, 1.0)
}

pub fn ueba_zscore_v0(
    features: &EntityFeatures,
    baseline: &EntityTypeBaseline,
    z_clip: f64,
) -> f64 {
    baseline.score(features, z_clip)
}

pub fn severity_for(score: f64, threshold: f64) -> &'static str {
    if score >= threshold.max(0.9) {
        "critical"
    } else if score >= threshold {
        "high"
    } else if score >= threshold * 0.6 {
        "medium"
    } else {
        "low"
    }
}

pub struct ScoreContext<'a> {
    pub model: &'a str,
    pub min_requests: u64,
    pub threshold: f64,
    pub z_clip: f64,
    pub baselines: Option<&'a BaselineSet>,
}

/// Score one entity. For `ueba_zscore_v0`, falls back to stub when baseline missing.
pub fn score_features(features: &EntityFeatures, ctx: &ScoreContext<'_>) -> ScoreResult {
    let (score, model_used) = match ctx.model {
        MODEL_UEBA => {
            if let Some(set) = ctx.baselines {
                if let Some(b) = set.get(&features.entity_type) {
                    (
                        ueba_zscore_v0(features, b, ctx.z_clip),
                        MODEL_UEBA.to_string(),
                    )
                } else {
                    (
                        anomaly_stub_v0(features, ctx.min_requests),
                        format!("{MODEL_STUB}+fallback_no_baseline"),
                    )
                }
            } else {
                (
                    anomaly_stub_v0(features, ctx.min_requests),
                    format!("{MODEL_STUB}+fallback_no_baseline"),
                )
            }
        }
        other => (
            anomaly_stub_v0(features, ctx.min_requests),
            if other.is_empty() {
                MODEL_STUB.to_string()
            } else {
                other.to_string()
            },
        ),
    };

    let features_json = serde_json::to_string(features).unwrap_or_else(|_| "{}".into());
    ScoreResult {
        scored_at: Utc::now(),
        entity_type: features.entity_type.clone(),
        entity_id: features.entity_id.clone(),
        window_start: features.window_start,
        model: model_used,
        score,
        severity: severity_for(score, ctx.threshold).to_string(),
        features_json,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::{EntityTypeBaseline, FeatureMoments};
    use chrono::TimeZone;

    fn sample(requests: u64, deny: u64, threat: u64) -> EntityFeatures {
        EntityFeatures {
            window_start: Utc.with_ymd_and_hms(2026, 7, 16, 12, 0, 0).unwrap(),
            window_secs: 300,
            entity_type: "client_ip".into(),
            entity_id: "10.0.0.1".into(),
            request_count: requests,
            unique_domains: 3,
            unique_urls: 5,
            deny_count: deny,
            threat_hit_count: threat,
            avg_response_size: 100.0,
            avg_duration_ms: 10.0,
            gap_cv: 0.5,
            max_domain_len: 12,
            extracted_at: Utc::now(),
        }
    }

    #[test]
    fn quiet_entity_scores_low() {
        let s = anomaly_stub_v0(&sample(10, 0, 0), 10);
        assert!(s < 0.5, "score={s}");
    }

    #[test]
    fn burst_deny_scores_high() {
        let s = anomaly_stub_v0(&sample(100, 80, 40), 10);
        assert!(s >= 0.65, "score={s}");
    }

    #[test]
    fn ueba_uses_baseline() {
        let m = |mean: f64, std: f64| FeatureMoments { mean, std };
        let b = EntityTypeBaseline {
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
        };
        let mut set = BaselineSet::default();
        set.baselines.insert("client_ip".into(), b);
        let ctx = ScoreContext {
            model: MODEL_UEBA,
            min_requests: 10,
            threshold: 0.8,
            z_clip: 4.0,
            baselines: Some(&set),
        };
        let scored = score_features(&sample(200, 150, 0), &ctx);
        assert_eq!(scored.model, MODEL_UEBA);
        assert!(scored.score >= 0.5, "score={}", scored.score);
    }
}
