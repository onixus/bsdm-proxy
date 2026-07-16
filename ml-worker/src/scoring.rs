//! Scoring models. M5.1 ships `anomaly_stub_v0` only.

use crate::features::EntityFeatures;
use chrono::{DateTime, Utc};
use serde::Serialize;

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

/// Heuristic anomaly score in \[0, 1\].
///
/// Combines request intensity (relative to min_requests), deny ratio, and threat hits.
/// Not a trained model — baseline for M5.1 scaffolding and Grafana wiring.
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
    // Low gap_cv with high rate can hint periodicity (beacon-like); mild contribution.
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

pub fn score_features(
    features: &EntityFeatures,
    model: &str,
    min_requests: u64,
    threshold: f64,
) -> ScoreResult {
    let score = if model == "anomaly_stub_v0" || model.is_empty() {
        anomaly_stub_v0(features, min_requests)
    } else {
        // Unknown model ids fall back to stub until M5.2+ loaders land.
        anomaly_stub_v0(features, min_requests)
    };
    let features_json = serde_json::to_string(features).unwrap_or_else(|_| "{}".into());
    ScoreResult {
        scored_at: Utc::now(),
        entity_type: features.entity_type.clone(),
        entity_id: features.entity_id.clone(),
        window_start: features.window_start,
        model: model.to_string(),
        score,
        severity: severity_for(score, threshold).to_string(),
        features_json,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
