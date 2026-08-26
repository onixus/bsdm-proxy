//! Runtime configuration from environment variables.

use crate::sources::KNOWN_SOURCES;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::warn;

/// Suffix appended to enforcement artifacts while running in shadow mode, so
/// neither `dns-sinkhole` nor the proxy can pick them up by accident.
pub const SHADOW_SUFFIX: &str = ".shadow";

/// How threat intelligence results are allowed to affect traffic (issue #330).
///
/// `Shadow` is the fail-safe default: artifacts are still compiled, but only
/// under a `.shadow` name that no enforcement component loads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EnforcementMode {
    #[default]
    Shadow,
    Enforce,
}

impl EnforcementMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::Enforce => "enforce",
        }
    }

    pub fn is_enforce(self) -> bool {
        matches!(self, Self::Enforce)
    }

    /// Parses `TI_ENFORCEMENT_MODE`. Anything but an explicit `enforce` stays in
    /// shadow mode; an unrecognised value additionally yields a warning string.
    pub fn parse(raw: &str) -> (Self, Option<String>) {
        match raw.trim().to_ascii_lowercase().as_str() {
            "enforce" => (Self::Enforce, None),
            "" | "shadow" => (Self::Shadow, None),
            other => (
                Self::Shadow,
                Some(format!(
                    "TI_ENFORCEMENT_MODE='{other}' is not recognised, falling back to shadow"
                )),
            ),
        }
    }
}

/// Appends [`SHADOW_SUFFIX`] to a path without touching its extension.
pub fn shadow_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(SHADOW_SUFFIX);
    PathBuf::from(name)
}

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
    pub sqlite_path: PathBuf,
    pub storage_enabled: bool,
    pub ioc_ttl_secs: i64,
    pub min_confidence_score: u8,
    pub rpz_enabled: bool,
    /// Base path of the RPZ zone; see [`Config::rpz_artifact_path`].
    pub rpz_output_path: PathBuf,
    /// Base path of the proxy ACL feed; see [`Config::acl_artifact_path`].
    pub acl_export_path: PathBuf,
    /// Shadow (default, observe-only) or explicit enforcement.
    pub enforcement_mode: EnforcementMode,
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
        let output_dir = PathBuf::from(
            std::env::var("TI_OUTPUT_DIR").unwrap_or_else(|_| "./data/threat-intel".into()),
        );

        let sqlite_path = std::env::var("TI_SQLITE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| output_dir.join("ioc.db"));

        let rpz_output_path = std::env::var("TI_RPZ_OUTPUT_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| output_dir.join("threats.rpz"));

        let acl_export_path = std::env::var("TI_ACL_EXPORT_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| output_dir.join("threat_domains.json"));

        let (enforcement_mode, mode_warning) =
            EnforcementMode::parse(&std::env::var("TI_ENFORCEMENT_MODE").unwrap_or_default());
        if let Some(msg) = mode_warning {
            warn!("{msg}");
        }
        let rpz_enabled = env_bool("TI_RPZ_ENABLED", true);
        if rpz_enabled && !enforcement_mode.is_enforce() {
            warn!(
                "TI_RPZ_ENABLED=true without TI_ENFORCEMENT_MODE=enforce: threat intelligence \
                 runs in shadow mode, artifacts are written with the '{SHADOW_SUFFIX}' suffix and \
                 must not be wired into dns-sinkhole or proxy ACLs"
            );
        }

        Ok(Self {
            sources,
            poll_interval,
            http_timeout: Duration::from_secs(env_u64("TI_HTTP_TIMEOUT_SECS", 30).max(1)),
            max_attempts,
            retry_backoff: Duration::from_secs(env_u64("TI_RETRY_BACKOFF_SECS", 5).max(1)),
            max_body_bytes: env_u64("TI_MAX_BODY_MB", 64).max(1) as usize * 1024 * 1024,
            max_indicators_per_fetch: env_u64("TI_MAX_INDICATORS_PER_FETCH", 500_000) as usize,
            output_dir,
            sqlite_path,
            storage_enabled: env_bool("TI_STORAGE_ENABLED", true),
            ioc_ttl_secs: env_u64("TI_IOC_TTL_SECS", 7 * 86400) as i64,
            min_confidence_score: env_u64("TI_MIN_CONFIDENCE_SCORE", 75).clamp(1, 100) as u8,
            rpz_enabled,
            rpz_output_path,
            acl_export_path,
            enforcement_mode,
            user_agent: std::env::var("TI_USER_AGENT")
                .unwrap_or_else(|_| format!("bsdm-threat-intel/{}", env!("CARGO_PKG_VERSION"))),
            metrics_port: env_u64("METRICS_PORT", 8093) as u16,
            run_once: env_bool("TI_RUN_ONCE", false),
        })
    }

    /// Path the RPZ zone is actually written to: the plain path only in
    /// `enforce` mode, `<path>.shadow` otherwise.
    pub fn rpz_artifact_path(&self) -> PathBuf {
        self.artifact_path(&self.rpz_output_path)
    }

    /// Path the proxy ACL threat feed is actually written to.
    pub fn acl_artifact_path(&self) -> PathBuf {
        self.artifact_path(&self.acl_export_path)
    }

    fn artifact_path(&self, base: &Path) -> PathBuf {
        if self.enforcement_mode.is_enforce() {
            base.to_path_buf()
        } else {
            shadow_path(base)
        }
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
            sqlite_path: PathBuf::from("/tmp/ioc.db"),
            storage_enabled: true,
            ioc_ttl_secs: 3600,
            min_confidence_score: 75,
            rpz_enabled: true,
            rpz_output_path: PathBuf::from("/tmp/threats.rpz"),
            acl_export_path: PathBuf::from("/tmp/threat_domains.json"),
            enforcement_mode: EnforcementMode::default(),
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
    fn enforcement_mode_defaults_to_shadow() {
        assert_eq!(EnforcementMode::default(), EnforcementMode::Shadow);
        assert_eq!(EnforcementMode::parse("").0, EnforcementMode::Shadow);
        assert_eq!(EnforcementMode::parse("shadow").0, EnforcementMode::Shadow);
        assert!(!EnforcementMode::default().is_enforce());
    }

    #[test]
    fn enforcement_is_enabled_only_by_explicit_value() {
        assert_eq!(
            EnforcementMode::parse(" Enforce ").0,
            EnforcementMode::Enforce
        );
        // Anything ambiguous is fail-safe: shadow plus an operator warning.
        for raw in ["true", "1", "block", "yes", "on", "enforced"] {
            let (mode, warning) = EnforcementMode::parse(raw);
            assert_eq!(mode, EnforcementMode::Shadow, "raw = {raw}");
            assert!(warning.is_some(), "raw = {raw} must warn");
        }
    }

    fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    /// Loads a `Config` from a clean `TI_*` environment with the given raw
    /// `TI_ENFORCEMENT_MODE` value (`None` = variable unset).
    fn config_from_env_with_mode(raw: Option<&str>) -> Config {
        for var in [
            "TI_SOURCES",
            "TI_SQLITE_PATH",
            "TI_RPZ_OUTPUT_PATH",
            "TI_ACL_EXPORT_PATH",
        ] {
            std::env::remove_var(var);
        }
        std::env::set_var("TI_OUTPUT_DIR", "/tmp/ti-env-test");
        match raw {
            Some(value) => std::env::set_var("TI_ENFORCEMENT_MODE", value),
            None => std::env::remove_var("TI_ENFORCEMENT_MODE"),
        }
        let config = Config::from_env().expect("config must load");
        std::env::remove_var("TI_ENFORCEMENT_MODE");
        std::env::remove_var("TI_OUTPUT_DIR");
        config
    }

    #[test]
    fn from_env_gates_enforcement_on_the_exact_value() {
        let _guard = env_lock().lock().unwrap();

        // Variable unset: fail-safe shadow, both artifacts suffixed.
        let unset = config_from_env_with_mode(None);
        assert_eq!(unset.enforcement_mode, EnforcementMode::Shadow);
        assert_eq!(
            unset.rpz_artifact_path(),
            PathBuf::from("/tmp/ti-env-test/threats.rpz.shadow")
        );
        assert_eq!(
            unset.acl_artifact_path(),
            PathBuf::from("/tmp/ti-env-test/threat_domains.json.shadow")
        );

        // Garbage and truthy-looking values must never reach enforcement.
        for raw in ["true", "1", "yes", "block", "enforced", "ENFORCE!", "  "] {
            let config = config_from_env_with_mode(Some(raw));
            assert_eq!(
                config.enforcement_mode,
                EnforcementMode::Shadow,
                "raw = {raw}"
            );
            assert!(
                config
                    .rpz_artifact_path()
                    .to_string_lossy()
                    .ends_with(SHADOW_SUFFIX),
                "raw = {raw} must keep the RPZ zone unloadable"
            );
            assert!(
                config
                    .acl_artifact_path()
                    .to_string_lossy()
                    .ends_with(SHADOW_SUFFIX),
                "raw = {raw} must keep the ACL feed unloadable"
            );
        }

        // Only the explicit opt-in flips to enforceable artifact paths.
        let enforced = config_from_env_with_mode(Some(" ENFORCE "));
        assert!(enforced.enforcement_mode.is_enforce());
        assert_eq!(enforced.rpz_artifact_path(), enforced.rpz_output_path);
        assert_eq!(enforced.acl_artifact_path(), enforced.acl_export_path);
    }

    #[test]
    fn shadow_mode_suffixes_enforcement_artifacts() {
        let mut config = config();
        assert_eq!(config.enforcement_mode, EnforcementMode::Shadow);
        assert_eq!(
            config.rpz_artifact_path(),
            PathBuf::from("/tmp/threats.rpz.shadow")
        );
        assert_eq!(
            config.acl_artifact_path(),
            PathBuf::from("/tmp/threat_domains.json.shadow")
        );

        config.enforcement_mode = EnforcementMode::Enforce;
        assert_eq!(config.rpz_artifact_path(), config.rpz_output_path);
        assert_eq!(config.acl_artifact_path(), config.acl_export_path);
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
