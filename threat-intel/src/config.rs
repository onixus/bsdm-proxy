//! Runtime configuration from environment variables.

use crate::sources::KNOWN_SOURCES;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    /// Enabled feed sources, in collection order.
    pub sources: Vec<String>,
    /// How often each source is refreshed.
    pub poll_interval: Duration,
    /// Per-request timeout for a feed fetch.
    pub http_timeout: Duration,
    /// Attempts per collection cycle, including the first one.
    pub max_attempts: u32,
    /// Base delay for the exponential retry backoff.
    pub retry_backoff: Duration,
    /// Hard cap on a feed response body.
    pub max_body_bytes: usize,
    /// Hard cap on indicators kept from a single fetch.
    pub max_indicators_per_fetch: usize,
    pub output_dir: PathBuf,
    pub user_agent: String,
    pub metrics_port: u16,
    /// Collect every source once and exit (CI smoke, cron-style runs).
    pub run_once: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let sources = parse_sources(
            &std::env::var("TI_SOURCES").unwrap_or_else(|_| KNOWN_SOURCES.join(",")),
        )?;

        let max_attempts = env_u64("TI_MAX_ATTEMPTS", 3).max(1) as u32;
        let poll_interval = Duration::from_secs(env_u64("TI_POLL_INTERVAL_SECS", 900).max(60));

        Ok(Self {
            sources,
            poll_interval,
            http_timeout: Duration::from_secs(env_u64("TI_HTTP_TIMEOUT_SECS", 30).max(1)),
            max_attempts,
            retry_backoff: Duration::from_secs(env_u64("TI_RETRY_BACKOFF_SECS", 5).max(1)),
            max_body_bytes: env_u64("TI_MAX_BODY_MB", 64).max(1) as usize * 1024 * 1024,
            max_indicators_per_fetch: env_u64("TI_MAX_INDICATORS_PER_FETCH", 500_000) as usize,
            output_dir: PathBuf::from(
                std::env::var("TI_OUTPUT_DIR").unwrap_or_else(|_| "./data/threat-intel".into()),
            ),
            user_agent: std::env::var("TI_USER_AGENT")
                .unwrap_or_else(|_| format!("bsdm-threat-intel/{}", env!("CARGO_PKG_VERSION"))),
            metrics_port: env_u64("METRICS_PORT", 8093) as u16,
            run_once: env_bool("TI_RUN_ONCE", false),
        })
    }

    /// Per-source endpoint override, e.g. `TI_OPENPHISH_URL`.
    pub fn source_url(name: &str) -> Option<String> {
        std::env::var(format!("TI_{}_URL", name.to_ascii_uppercase()))
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    /// Delay before attempt `attempt` (1-based), capped at ten minutes.
    pub fn backoff_for(&self, attempt: u32) -> Duration {
        let factor = 1u64 << attempt.saturating_sub(1).min(6);
        let secs = self.retry_backoff.as_secs().saturating_mul(factor);
        Duration::from_secs(secs.min(600))
    }
}

fn parse_sources(raw: &str) -> Result<Vec<String>, String> {
    let sources: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if sources.is_empty() {
        return Err("TI_SOURCES must list at least one feed source".into());
    }
    let mut seen = std::collections::HashSet::new();
    for source in &sources {
        if !seen.insert(source.clone()) {
            return Err(format!("TI_SOURCES lists '{source}' twice"));
        }
    }
    Ok(sources)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            sources: vec!["openphish".into()],
            poll_interval: Duration::from_secs(900),
            http_timeout: Duration::from_secs(30),
            max_attempts: 3,
            retry_backoff: Duration::from_secs(5),
            max_body_bytes: 1024,
            max_indicators_per_fetch: 10,
            output_dir: PathBuf::from("/tmp"),
            user_agent: "test".into(),
            metrics_port: 8093,
            run_once: true,
        }
    }

    #[test]
    fn parses_and_normalizes_source_list() {
        assert_eq!(
            parse_sources(" OpenPhish , urlhaus ").unwrap(),
            vec!["openphish", "urlhaus"]
        );
    }

    #[test]
    fn rejects_empty_and_duplicate_source_lists() {
        assert!(parse_sources("  ,  ").is_err());
        assert!(parse_sources("urlhaus,urlhaus").is_err());
    }

    #[test]
    fn backoff_grows_exponentially_and_caps() {
        let config = config();
        assert_eq!(config.backoff_for(1), Duration::from_secs(5));
        assert_eq!(config.backoff_for(2), Duration::from_secs(10));
        assert_eq!(config.backoff_for(3), Duration::from_secs(20));
        assert!(config.backoff_for(20) <= Duration::from_secs(600));
    }
}
