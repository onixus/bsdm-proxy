//! M5.5 threat score write-back for proxy hot-path cache lookup.
//!
//! After each scoring cycle, publishes latest scores to ClickHouse `threat_score_cache`
//! and an in-memory snapshot served at `GET /api/threat-scores`.

use crate::clickhouse::ClickHouseClient;
use crate::config::Config;
use crate::scoring::ScoreResult;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

/// Row exposed to proxy poll API and stored in ClickHouse.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThreatScoreEntry {
    pub entity_type: String,
    pub entity_id: String,
    pub score: f64,
    pub severity: String,
    pub model: String,
    pub scored_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatScoreSnapshot {
    pub generated_at: String,
    pub scores: Vec<ThreatScoreEntry>,
}

pub type SnapshotStore = Arc<RwLock<ThreatScoreSnapshot>>;

pub fn new_snapshot_store() -> SnapshotStore {
    Arc::new(RwLock::new(ThreatScoreSnapshot::default()))
}

impl ScoreResult {
    fn to_cache_entry(&self, ttl_secs: u64, min_score: f64) -> Option<ThreatScoreEntry> {
        if self.score < min_score {
            return None;
        }
        let expires = self.scored_at + Duration::seconds(ttl_secs as i64);
        Some(ThreatScoreEntry {
            entity_type: self.entity_type.clone(),
            entity_id: self.entity_id.clone(),
            score: self.score,
            severity: self.severity.clone(),
            model: self.model.clone(),
            scored_at: self.scored_at.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            expires_at: expires.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
        })
    }
}

pub fn entries_from_scores(scores: &[ScoreResult], config: &Config) -> Vec<ThreatScoreEntry> {
    scores
        .iter()
        .filter_map(|s| {
            s.to_cache_entry(config.writeback_ttl.as_secs(), config.writeback_min_score)
        })
        .collect()
}

pub fn update_snapshot(store: &SnapshotStore, entries: &[ThreatScoreEntry]) {
    let mut snap = store.write().expect("snapshot lock");
    snap.generated_at = Utc::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    snap.scores = entries.to_vec();
}

pub async fn writeback_to_clickhouse(
    ch: &ClickHouseClient,
    config: &Config,
    entries: &[ThreatScoreEntry],
) -> Result<(), Box<dyn std::error::Error>> {
    if entries.is_empty() {
        return Ok(());
    }
    let table = config.fq_score_cache();
    let rows: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "entity_type": e.entity_type,
                "entity_id": e.entity_id,
                "score": e.score,
                "severity": e.severity,
                "model": e.model,
                "scored_at": e.scored_at,
                "expires_at": e.expires_at,
            })
        })
        .collect();
    ch.insert_json_each_row(&table, &rows).await?;
    Ok(())
}

pub async fn publish_writeback(
    config: &Config,
    ch: &ClickHouseClient,
    store: &SnapshotStore,
    scores: &[ScoreResult],
) -> Result<usize, Box<dyn std::error::Error>> {
    if !config.writeback_enabled {
        return Ok(0);
    }
    let entries = entries_from_scores(scores, config);
    update_snapshot(store, &entries);
    writeback_to_clickhouse(ch, config, &entries).await?;
    Ok(entries.len())
}

pub fn snapshot_json(store: &SnapshotStore) -> String {
    let snap = store.read().expect("snapshot lock");
    serde_json::to_string(&*snap).unwrap_or_else(|_| r#"{"scores":[]}"#.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_score(score: f64) -> ScoreResult {
        ScoreResult {
            scored_at: Utc.with_ymd_and_hms(2026, 7, 17, 12, 0, 0).unwrap(),
            entity_type: "domain".into(),
            entity_id: "evil.test".into(),
            window_start: Utc.with_ymd_and_hms(2026, 7, 17, 11, 0, 0).unwrap(),
            model: "phishing_lexical_v0".into(),
            score,
            severity: "high".into(),
            features_json: "{}".into(),
        }
    }

    #[test]
    fn filters_below_min_score() {
        let cfg = sample_config();
        let entries = entries_from_scores(&[sample_score(0.3)], &cfg);
        assert!(entries.is_empty());
    }

    #[test]
    fn includes_above_min_score() {
        let cfg = sample_config();
        let entries = entries_from_scores(&[sample_score(0.85)], &cfg);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entity_id, "evil.test");
    }

    #[test]
    fn snapshot_roundtrip() {
        let store = new_snapshot_store();
        let entries = vec![ThreatScoreEntry {
            entity_type: "domain".into(),
            entity_id: "x.com".into(),
            score: 0.9,
            severity: "high".into(),
            model: "test".into(),
            scored_at: "2026-07-17 12:00:00.000".into(),
            expires_at: "2026-07-17 13:00:00.000".into(),
        }];
        update_snapshot(&store, &entries);
        let json = snapshot_json(&store);
        assert!(json.contains("x.com"));
    }

    fn sample_config() -> Config {
        Config {
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
            poll_interval: std::time::Duration::from_secs(120),
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
        }
    }
}
