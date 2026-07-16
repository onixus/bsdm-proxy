//! Runtime configuration from environment variables.

use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub webhook_url: String,
    pub webhook_timeout: Duration,
    pub webhook_headers: HashMap<String, String>,
    pub clickhouse_url: String,
    pub clickhouse_database: String,
    pub clickhouse_table: String,
    pub clickhouse_user: Option<String>,
    pub clickhouse_password: Option<String>,
    pub poll_interval: Duration,
    pub lookback: Duration,
    pub dedupe_ttl: Duration,
    pub metrics_port: u16,
    pub source: String,
    pub rules: Vec<String>,
    pub blocked_burst_threshold: u64,
    pub domain_burst_threshold: u64,
    pub high_entropy_min_requests: u64,
    /// SQL prefilter: minimum full domain length before Shannon post-filter.
    pub high_entropy_min_domain_len: u64,
    /// Minimum leftmost-label length for Shannon scoring.
    pub shannon_min_label_len: u64,
    /// Minimum Shannon entropy (bits/char) on leftmost label.
    pub shannon_min_bits: f64,
    pub high_entropy_mode: crate::entropy::HighEntropyMode,
    /// Legacy digit-heuristic minimum domain length.
    pub high_entropy_legacy_min_domain_len: u64,
    pub off_hours_min_events: u64,
    pub beacon_lookback: Duration,
    pub beacon_min_hits: u64,
    pub beacon_min_interval_secs: u64,
    pub beacon_max_interval_secs: u64,
    /// Max coefficient of variation of inter-request gaps (0.0–1.0 scale as percent×100 avoided — use float via string parse).
    pub beacon_max_gap_cv: f64,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let webhook_url = std::env::var("ALERT_WEBHOOK_URL")
            .map_err(|_| "ALERT_WEBHOOK_URL is required".to_string())?;
        if webhook_url.trim().is_empty() {
            return Err("ALERT_WEBHOOK_URL must not be empty".into());
        }

        let webhook_headers = parse_headers_json(
            &std::env::var("ALERT_WEBHOOK_HEADERS").unwrap_or_else(|_| "{}".into()),
        )?;

        let rules = parse_rules_list(&std::env::var("ALERT_RULES").unwrap_or_else(|_| {
            "blocked_burst,domain_burst,off_hours_threat,high_entropy_domain,beacon_periodic".into()
        }));

        Ok(Self {
            webhook_url,
            webhook_timeout: Duration::from_secs(env_u64("ALERT_WEBHOOK_TIMEOUT_SECS", 10)),
            webhook_headers,
            clickhouse_url: std::env::var("CLICKHOUSE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8123".into()),
            clickhouse_database: std::env::var("CLICKHOUSE_DATABASE")
                .unwrap_or_else(|_| "bsdm".into()),
            clickhouse_table: std::env::var("CLICKHOUSE_TABLE")
                .unwrap_or_else(|_| "http_cache".into()),
            clickhouse_user: std::env::var("CLICKHOUSE_USER")
                .ok()
                .filter(|s| !s.is_empty()),
            clickhouse_password: std::env::var("CLICKHOUSE_PASSWORD")
                .ok()
                .filter(|s| !s.is_empty()),
            poll_interval: Duration::from_secs(env_u64("ALERT_POLL_INTERVAL_SECS", 60)),
            lookback: Duration::from_secs(env_u64("ALERT_LOOKBACK_SECS", 300)),
            dedupe_ttl: Duration::from_secs(env_u64("ALERT_DEDUPE_TTL_SECS", 3600)),
            metrics_port: env_u64("METRICS_PORT", 8090) as u16,
            source: std::env::var("ALERT_SOURCE")
                .unwrap_or_else(|_| "bsdm-proxy-alert-worker".into()),
            rules,
            blocked_burst_threshold: env_u64("ALERT_BLOCKED_BURST_THRESHOLD", 10),
            domain_burst_threshold: env_u64("ALERT_DOMAIN_BURST_THRESHOLD", 50),
            high_entropy_min_requests: env_u64("ALERT_HIGH_ENTROPY_MIN_REQUESTS", 5),
            high_entropy_min_domain_len: env_u64("ALERT_HIGH_ENTROPY_MIN_DOMAIN_LEN", 16),
            shannon_min_label_len: env_u64("ALERT_SHANNON_MIN_LABEL_LEN", 12),
            shannon_min_bits: env_f64("ALERT_SHANNON_MIN_BITS", 3.5),
            high_entropy_mode: crate::entropy::HighEntropyMode::parse(
                &std::env::var("ALERT_HIGH_ENTROPY_MODE").unwrap_or_else(|_| "either".into()),
            ),
            high_entropy_legacy_min_domain_len: env_u64(
                "ALERT_HIGH_ENTROPY_LEGACY_MIN_DOMAIN_LEN",
                25,
            ),
            off_hours_min_events: env_u64("ALERT_OFF_HOURS_MIN_EVENTS", 1),
            beacon_lookback: Duration::from_secs(env_u64("ALERT_BEACON_LOOKBACK_SECS", 3600)),
            beacon_min_hits: env_u64("ALERT_BEACON_MIN_HITS", 5),
            beacon_min_interval_secs: env_u64("ALERT_BEACON_MIN_INTERVAL_SECS", 45),
            beacon_max_interval_secs: env_u64("ALERT_BEACON_MAX_INTERVAL_SECS", 900),
            beacon_max_gap_cv: env_f64("ALERT_BEACON_MAX_GAP_CV", 0.25),
        })
    }

    pub fn fq_table(&self) -> String {
        format!("{}.{}", self.clickhouse_database, self.clickhouse_table)
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn parse_rules_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_headers_json(raw: &str) -> Result<HashMap<String, String>, String> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("ALERT_WEBHOOK_HEADERS: {e}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "ALERT_WEBHOOK_HEADERS must be a JSON object".to_string())?;
    let mut out = HashMap::new();
    for (k, v) in obj {
        let s = v
            .as_str()
            .ok_or_else(|| format!("ALERT_WEBHOOK_HEADERS[{k}] must be a string"))?;
        out.insert(k.clone(), s.to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rules_list() {
        assert_eq!(
            parse_rules_list(" blocked_burst , domain_burst "),
            vec!["blocked_burst", "domain_burst"]
        );
    }

    #[test]
    fn parses_headers_json() {
        let h = parse_headers_json(r#"{"Authorization":"Bearer x","X-Foo":"bar"}"#).unwrap();
        assert_eq!(h.get("Authorization").map(String::as_str), Some("Bearer x"));
        assert_eq!(h.get("X-Foo").map(String::as_str), Some("bar"));
    }
}
