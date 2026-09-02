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
    /// Per-query client deadline (`ALERT_CLICKHOUSE_TIMEOUT_MS`).
    pub clickhouse_timeout: Duration,
    /// Server-side `max_execution_time` sent with every rule query.
    pub clickhouse_max_execution_secs: u64,
    /// Server-side `max_result_rows` guard (`result_overflow_mode=break`).
    pub clickhouse_max_result_rows: u64,
    /// Latency above which a query is logged and counted as slow.
    pub clickhouse_slow_query: Duration,
    /// Send server-side query guards (`readonly=2`, `max_execution_time`,
    /// `max_result_rows`). Disable only when the ClickHouse user profile is
    /// already `readonly=1`, where per-query settings cannot be overridden.
    pub clickhouse_query_guards: bool,
    /// Consecutive failed rule queries before the cycle is aborted early.
    pub clickhouse_failure_threshold: u32,
    /// Upper bound of the exponential backoff applied after a degraded cycle.
    pub clickhouse_backoff_max: Duration,
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
            clickhouse_timeout: Duration::from_millis(
                env_u64("ALERT_CLICKHOUSE_TIMEOUT_MS", 15_000).clamp(500, 600_000),
            ),
            clickhouse_max_execution_secs: clickhouse_max_execution_secs(),
            clickhouse_max_result_rows: env_u64("ALERT_CLICKHOUSE_MAX_RESULT_ROWS", 50_000)
                .clamp(100, 10_000_000),
            clickhouse_slow_query: Duration::from_millis(
                env_u64("ALERT_CLICKHOUSE_SLOW_QUERY_MS", 2_000).clamp(1, 600_000),
            ),
            clickhouse_query_guards: env_bool("ALERT_CLICKHOUSE_QUERY_GUARDS", true),
            clickhouse_failure_threshold: env_u64("ALERT_CLICKHOUSE_FAILURE_THRESHOLD", 3)
                .clamp(1, 1_000) as u32,
            clickhouse_backoff_max: Duration::from_secs(
                env_u64("ALERT_CLICKHOUSE_BACKOFF_MAX_SECS", 300).clamp(1, 86_400),
            ),
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

    /// Sleep before the next cycle: `poll_interval` normally, exponentially
    /// backed off (capped by `clickhouse_backoff_max`) while ClickHouse is
    /// degraded, so a slow warehouse is not hammered by every poll tick.
    pub fn backoff_delay(&self, degraded_cycles: u32) -> Duration {
        if degraded_cycles == 0 {
            return self.poll_interval;
        }
        let factor = 1u64 << degraded_cycles.min(16);
        let scaled = self
            .poll_interval
            .as_secs()
            .max(1)
            .saturating_mul(factor)
            .min(self.clickhouse_backoff_max.as_secs());
        Duration::from_secs(scaled.max(self.poll_interval.as_secs()))
    }

    /// Deterministic defaults for unit tests (no environment access).
    #[cfg(test)]
    pub fn for_test() -> Self {
        Self {
            webhook_url: "http://127.0.0.1:9080/hooks/siem".into(),
            webhook_timeout: Duration::from_secs(10),
            webhook_headers: HashMap::new(),
            clickhouse_url: "http://127.0.0.1:8123".into(),
            clickhouse_database: "bsdm".into(),
            clickhouse_table: "http_cache".into(),
            clickhouse_user: None,
            clickhouse_password: None,
            clickhouse_timeout: Duration::from_millis(15_000),
            clickhouse_max_execution_secs: 15,
            clickhouse_max_result_rows: 50_000,
            clickhouse_slow_query: Duration::from_millis(2_000),
            clickhouse_query_guards: true,
            clickhouse_failure_threshold: 3,
            clickhouse_backoff_max: Duration::from_secs(300),
            poll_interval: Duration::from_secs(60),
            lookback: Duration::from_secs(300),
            dedupe_ttl: Duration::from_secs(3600),
            metrics_port: 8090,
            source: "bsdm-proxy-alert-worker".into(),
            rules: vec!["blocked_burst".into()],
            blocked_burst_threshold: 10,
            domain_burst_threshold: 50,
            high_entropy_min_requests: 5,
            high_entropy_min_domain_len: 16,
            shannon_min_label_len: 12,
            shannon_min_bits: 3.5,
            high_entropy_mode: crate::entropy::HighEntropyMode::parse("either"),
            high_entropy_legacy_min_domain_len: 25,
            off_hours_min_events: 1,
            beacon_lookback: Duration::from_secs(3600),
            beacon_min_hits: 5,
            beacon_min_interval_secs: 45,
            beacon_max_interval_secs: 900,
            beacon_max_gap_cv: 0.25,
        }
    }
}

/// Server-side execution bound. Defaults to the client deadline rounded up so
/// ClickHouse gives up before (or with) the HTTP client rather than keeping a
/// heavy scan running after the worker has already walked away.
fn clickhouse_max_execution_secs() -> u64 {
    if let Some(explicit) = std::env::var("ALERT_CLICKHOUSE_MAX_EXECUTION_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return explicit.clamp(1, 86_400);
    }
    let timeout_ms = env_u64("ALERT_CLICKHOUSE_TIMEOUT_MS", 15_000).clamp(500, 600_000);
    timeout_ms.div_ceil(1_000).max(1)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
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
    fn backoff_grows_and_is_capped() {
        let mut config = Config::for_test();
        config.poll_interval = Duration::from_secs(60);
        config.clickhouse_backoff_max = Duration::from_secs(300);
        assert_eq!(config.backoff_delay(0), Duration::from_secs(60));
        assert_eq!(config.backoff_delay(1), Duration::from_secs(120));
        assert_eq!(config.backoff_delay(2), Duration::from_secs(240));
        assert_eq!(config.backoff_delay(3), Duration::from_secs(300));
        assert_eq!(config.backoff_delay(64), Duration::from_secs(300));
    }

    #[test]
    fn backoff_never_drops_below_poll_interval() {
        let mut config = Config::for_test();
        config.poll_interval = Duration::from_secs(120);
        config.clickhouse_backoff_max = Duration::from_secs(30);
        assert_eq!(config.backoff_delay(4), Duration::from_secs(120));
    }

    #[test]
    fn parses_headers_json() {
        let h = parse_headers_json(r#"{"Authorization":"Bearer x","X-Foo":"bar"}"#).unwrap();
        assert_eq!(h.get("Authorization").map(String::as_str), Some("Bearer x"));
        assert_eq!(h.get("X-Foo").map(String::as_str), Some("bar"));
    }
}
