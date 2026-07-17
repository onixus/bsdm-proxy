//! Runtime configuration from environment variables.

use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub clickhouse_url: String,
    pub clickhouse_database: String,
    pub clickhouse_table: String,
    pub features_table: String,
    pub scores_table: String,
    /// M5.3 domain lexical feature store.
    pub phishing_features_table: String,
    /// M5.4 client→domain beacon feature store.
    pub beacon_features_table: String,
    pub clickhouse_user: Option<String>,
    pub clickhouse_password: Option<String>,
    pub poll_interval: Duration,
    pub lookback: Duration,
    pub entity_types: Vec<String>,
    pub min_requests: u64,
    pub model: String,
    pub score_threshold: f64,
    /// Lookback for population baseline over `entity_features`.
    pub baseline_lookback: Duration,
    pub baseline_min_samples: u64,
    /// Clip |z| before mapping to \[0,1\] for `ueba_zscore_v0`.
    pub z_clip: f64,
    /// Optional JSON artifact (`BaselineSet`) instead of live CH stats.
    pub baseline_path: Option<PathBuf>,
    /// M5.4 beacon lookback (defaults align with alert-worker).
    pub beacon_lookback: Duration,
    pub beacon_min_hits: u64,
    pub beacon_min_interval_secs: u64,
    pub beacon_max_interval_secs: u64,
    pub beacon_max_gap_cv: f64,
    pub webhook_url: Option<String>,
    pub webhook_timeout: Duration,
    pub metrics_port: u16,
    pub source: String,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let entity_types =
            parse_list(&std::env::var("ML_ENTITY_TYPES").unwrap_or_else(|_| "client_ip".into()));
        if entity_types.is_empty() {
            return Err(
                "ML_ENTITY_TYPES must list at least one of client_ip,username,domain".into(),
            );
        }
        for t in &entity_types {
            if !matches!(t.as_str(), "client_ip" | "username" | "domain") {
                return Err(format!("unsupported ML_ENTITY_TYPES entry: {t}"));
            }
        }

        let webhook_url = std::env::var("ML_WEBHOOK_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        Ok(Self {
            clickhouse_url: std::env::var("CLICKHOUSE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8123".into()),
            clickhouse_database: std::env::var("CLICKHOUSE_DATABASE")
                .unwrap_or_else(|_| "bsdm".into()),
            clickhouse_table: std::env::var("CLICKHOUSE_TABLE")
                .unwrap_or_else(|_| "http_cache".into()),
            features_table: std::env::var("ML_FEATURES_TABLE")
                .unwrap_or_else(|_| "entity_features".into()),
            scores_table: std::env::var("ML_SCORES_TABLE").unwrap_or_else(|_| "ml_scores".into()),
            phishing_features_table: std::env::var("ML_PHISHING_FEATURES_TABLE")
                .unwrap_or_else(|_| "domain_phishing_features".into()),
            beacon_features_table: std::env::var("ML_BEACON_FEATURES_TABLE")
                .unwrap_or_else(|_| "beacon_pair_features".into()),
            clickhouse_user: std::env::var("CLICKHOUSE_USER")
                .ok()
                .filter(|s| !s.is_empty()),
            clickhouse_password: std::env::var("CLICKHOUSE_PASSWORD")
                .ok()
                .filter(|s| !s.is_empty()),
            poll_interval: Duration::from_secs(env_u64("ML_POLL_INTERVAL_SECS", 120)),
            lookback: Duration::from_secs(env_u64("ML_LOOKBACK_SECS", 300)),
            entity_types,
            min_requests: env_u64("ML_MIN_REQUESTS", 10),
            model: std::env::var("ML_MODEL").unwrap_or_else(|_| "ueba_zscore_v0".into()),
            score_threshold: env_f64("ML_SCORE_THRESHOLD", 0.8)?,
            baseline_lookback: Duration::from_secs(env_u64("ML_BASELINE_LOOKBACK_SECS", 86400)),
            baseline_min_samples: env_u64("ML_BASELINE_MIN_SAMPLES", 30),
            z_clip: env_f64("ML_ZSCORE_CLIP", 4.0)?,
            baseline_path: std::env::var("ML_BASELINE_PATH")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .map(PathBuf::from),
            beacon_lookback: Duration::from_secs(env_u64("ML_BEACON_LOOKBACK_SECS", 3600)),
            beacon_min_hits: env_u64("ML_BEACON_MIN_HITS", 5),
            beacon_min_interval_secs: env_u64("ML_BEACON_MIN_INTERVAL_SECS", 45),
            beacon_max_interval_secs: env_u64("ML_BEACON_MAX_INTERVAL_SECS", 900),
            beacon_max_gap_cv: env_f64("ML_BEACON_MAX_GAP_CV", 0.25)?,
            webhook_url,
            webhook_timeout: Duration::from_secs(env_u64("ML_WEBHOOK_TIMEOUT_SECS", 10)),
            metrics_port: env_u64("METRICS_PORT", 8091) as u16,
            source: std::env::var("ML_SOURCE").unwrap_or_else(|_| "bsdm-proxy-ml-worker".into()),
        })
    }

    pub fn fq_source(&self) -> String {
        format!("{}.{}", self.clickhouse_database, self.clickhouse_table)
    }

    pub fn fq_features(&self) -> String {
        format!("{}.{}", self.clickhouse_database, self.features_table)
    }

    pub fn fq_scores(&self) -> String {
        format!("{}.{}", self.clickhouse_database, self.scores_table)
    }

    pub fn fq_phishing_features(&self) -> String {
        format!(
            "{}.{}",
            self.clickhouse_database, self.phishing_features_table
        )
    }

    pub fn is_phishing_model(&self) -> bool {
        self.model == "phishing_lexical_v0"
    }

    pub fn is_beacon_model(&self) -> bool {
        self.model == "cc_beacon_v0"
    }

    pub fn fq_beacon_features(&self) -> String {
        format!(
            "{}.{}",
            self.clickhouse_database, self.beacon_features_table
        )
    }
}

fn parse_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_f64(key: &str, default: f64) -> Result<f64, String> {
    match std::env::var(key) {
        Ok(v) => v
            .parse()
            .map_err(|_| format!("{key} must be a float, got {v:?}")),
        Err(_) => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_entity_list() {
        assert_eq!(
            parse_list("client_ip, username,domain"),
            vec!["client_ip", "username", "domain"]
        );
    }
}
