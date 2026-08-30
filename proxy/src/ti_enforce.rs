//! Threat Intelligence Data-Plane ACL Enforcement Mode (Phase 2 Roadmap / ADR-0008).
//!
//! Provides lock-free domain matching on the hot path against verified threat
//! intelligence feeds. Protected by a Triple-Gate safety lock to prevent accidental
//! enforcement of unverified or shadow-only indicators.

use crate::metrics::Metrics;
use crate::policy_cache::PolicyDecisionCache;
use arc_swap::ArcSwap;
use serde::Deserialize;
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Default location of the enforcement export written by the collector.
pub const DEFAULT_FEED_PATH: &str = "/var/lib/bsdm-proxy/threat-intel/threat_domains.json";
pub const DEFAULT_RELOAD_SECS: u64 = 300;
/// Feed label used when the export carries no per-domain provenance.
pub const UNKNOWN_FEED: &str = "threat-intel";

/// Configured enforcement posture for Threat Intelligence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EnforcementPosture {
    #[default]
    Shadow,
    Enforce,
}

impl EnforcementPosture {
    pub fn is_enforce(&self) -> bool {
        matches!(self, Self::Enforce)
    }

    pub fn is_shadow(&self) -> bool {
        matches!(self, Self::Shadow)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::Enforce => "enforce",
        }
    }

    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "enforce" => Self::Enforce,
            _ => Self::Shadow,
        }
    }
}

/// Runtime effective mode resulting from Triple-Gate evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EffectiveMode {
    Disabled,
    #[default]
    ShadowOnly,
    Enforce,
}

impl EffectiveMode {
    pub fn is_enforce(&self) -> bool {
        matches!(self, Self::Enforce)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::ShadowOnly => "shadow",
            Self::Enforce => "enforce",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TiEnforceConfig {
    pub enabled: bool,
    pub configured_posture: EnforcementPosture,
    pub feed_path: PathBuf,
    pub reload_interval: Duration,
}

impl TiEnforceConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("TI_ENFORCE_ENABLED")
            .or_else(|_| std::env::var("TI_ENFORCEMENT_ENABLED"))
            .or_else(|_| std::env::var("TI_ACL_FEED_ENABLED"))
            .map(|v| {
                !matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "0" | "false" | "no" | "off"
                )
            })
            .unwrap_or(true);

        let configured_posture = std::env::var("TI_ENFORCEMENT_MODE")
            .or_else(|_| std::env::var("TI_ENFORCE_MODE"))
            .map(|v| EnforcementPosture::parse(&v))
            .unwrap_or(EnforcementPosture::Shadow);

        let feed_path = std::env::var("TI_ENFORCE_FEED_PATH")
            .or_else(|_| std::env::var("TI_FEED_PATH"))
            .or_else(|_| std::env::var("TI_ACL_FEED_PATH"))
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_FEED_PATH));

        let reload_interval = Duration::from_secs(
            std::env::var("TI_ENFORCE_RELOAD_SECS")
                .or_else(|_| std::env::var("TI_ACL_RELOAD_SECS"))
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_RELOAD_SECS)
                .max(10),
        );

        Self {
            enabled,
            configured_posture,
            feed_path,
            reload_interval,
        }
    }
}

/// A matched threat intelligence indicator and its feed source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TiEnforceMatch {
    pub feed: String,
    pub indicator: String,
}

/// On-disk shape of the threat feed export JSON.
#[derive(Debug, Deserialize)]
struct TiFeedFile {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    feeds: HashMap<String, String>,
}

/// Lookup table snapshot held behind ArcSwap for lock-free hot path reads.
#[derive(Debug, Clone, Default)]
pub struct TiEnforceTable {
    pub effective_mode: EffectiveMode,
    pub domains: HashMap<String, String>,
}

impl TiEnforceTable {
    pub fn new(effective_mode: EffectiveMode, domains: HashMap<String, String>) -> Self {
        Self {
            effective_mode,
            domains,
        }
    }
}

/// Folds a feed name to a bounded set of label values.
pub(crate) fn normalize_feed_label(raw: Option<&str>) -> String {
    match raw {
        Some(feed) if feed.starts_with("soar:") => "soar".to_string(),
        Some(feed)
            if !feed.is_empty()
                && feed.len() <= 32
                && feed
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') =>
        {
            feed.to_string()
        }
        _ => UNKNOWN_FEED.to_string(),
    }
}

/// Threat intelligence enforcement matcher on the data plane.
pub struct TiEnforceMatcher {
    config: TiEnforceConfig,
    table: ArcSwap<TiEnforceTable>,
    policy_cache: Option<Arc<PolicyDecisionCache>>,
    metrics: Option<Arc<Metrics>>,
}

impl TiEnforceMatcher {
    pub fn new(
        config: TiEnforceConfig,
        policy_cache: Option<Arc<PolicyDecisionCache>>,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        let effective_mode = if !config.enabled {
            EffectiveMode::Disabled
        } else if config.configured_posture.is_enforce() {
            EffectiveMode::Enforce
        } else {
            EffectiveMode::ShadowOnly
        };

        if let Some(m) = &metrics {
            m.record_ti_effective_mode(config.configured_posture.as_str(), effective_mode.as_str());
        }

        Self {
            config,
            table: ArcSwap::new(Arc::new(TiEnforceTable {
                effective_mode,
                domains: HashMap::new(),
            })),
            policy_cache,
            metrics,
        }
    }

    /// Builds the matcher from environment variables and attempts initial load.
    pub fn from_env(
        policy_cache: Option<Arc<PolicyDecisionCache>>,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        let config = TiEnforceConfig::from_env();
        let matcher = Self::new(config, policy_cache, metrics);
        if matcher.config.enabled {
            match matcher.reload() {
                Ok(count) => info!(
                    path = %matcher.config.feed_path.display(),
                    indicators = count,
                    posture = matcher.config.configured_posture.as_str(),
                    effective = matcher.effective_mode().as_str(),
                    "threat-intel enforce feed loaded"
                ),
                Err(e) => debug!(
                    path = %matcher.config.feed_path.display(),
                    "threat-intel enforce feed not loaded: {e}"
                ),
            }
        }
        matcher
    }

    /// Disabled matcher for tests or setups without TI enforcement.
    pub fn disabled() -> Self {
        Self {
            config: TiEnforceConfig {
                enabled: false,
                configured_posture: EnforcementPosture::Shadow,
                feed_path: PathBuf::from(DEFAULT_FEED_PATH),
                reload_interval: Duration::from_secs(DEFAULT_RELOAD_SECS),
            },
            table: ArcSwap::new(Arc::new(TiEnforceTable {
                effective_mode: EffectiveMode::Disabled,
                domains: HashMap::new(),
            })),
            policy_cache: None,
            metrics: None,
        }
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn effective_mode(&self) -> EffectiveMode {
        self.table.load().effective_mode
    }

    pub fn is_enforcing(&self) -> bool {
        self.effective_mode() == EffectiveMode::Enforce
    }

    pub fn len(&self) -> usize {
        self.table.load().domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn config(&self) -> &TiEnforceConfig {
        &self.config
    }

    /// Re-reads the export from disk.
    pub fn reload(&self) -> Result<usize, String> {
        let raw = std::fs::read_to_string(&self.config.feed_path)
            .map_err(|e| format!("{}: {e}", self.config.feed_path.display()))?;
        self.load_from_str(&raw, Some(&self.config.feed_path))
    }

    /// Parses export JSON, applies Triple-Gate verification, atomically stores the table,
    /// invalidates policy cache and updates Prometheus metric.
    pub fn load_from_str(&self, raw: &str, origin: Option<&Path>) -> Result<usize, String> {
        let parsed: TiFeedFile =
            serde_json::from_str(raw).map_err(|e| format!("invalid TI enforce feed JSON: {e}"))?;

        let is_shadow_path = origin
            .map(|p| p.to_string_lossy().ends_with(".shadow"))
            .unwrap_or_else(|| self.config.feed_path.to_string_lossy().ends_with(".shadow"));

        // Triple-Gate safety lock (ADR-0008):
        // 1. Posture configured as enforce
        // 2. Not loaded from a shadow artifact path
        // 3. Payload header explicitly marks mode as "enforce"
        let triple_gate_passed = self.config.configured_posture.is_enforce()
            && !is_shadow_path
            && parsed.mode.eq_ignore_ascii_case("enforce");

        let effective_mode = if !self.config.enabled {
            EffectiveMode::Disabled
        } else if triple_gate_passed {
            EffectiveMode::Enforce
        } else {
            warn!(
                configured_posture = %self.config.configured_posture.as_str(),
                is_shadow_path,
                feed_mode = %parsed.mode,
                origin = ?origin,
                "TI enforcement triple-gate not passed; falling back to ShadowOnly (requests will not be blocked)"
            );
            EffectiveMode::ShadowOnly
        };

        let mut domain_map = HashMap::with_capacity(parsed.domains.len());
        for domain in parsed.domains {
            let key = domain.trim().trim_end_matches('.').to_ascii_lowercase();
            if key.is_empty() {
                continue;
            }
            let feed = normalize_feed_label(parsed.feeds.get(&domain).map(String::as_str));
            domain_map.insert(key, feed);
        }

        let count = domain_map.len();
        let new_table = Arc::new(TiEnforceTable {
            effective_mode,
            domains: domain_map,
        });

        self.table.store(new_table);

        if let Some(cache) = &self.policy_cache {
            cache.invalidate();
        }

        if let Some(metrics) = &self.metrics {
            metrics.record_ti_effective_mode(
                self.config.configured_posture.as_str(),
                effective_mode.as_str(),
            );
        }

        Ok(count)
    }

    /// Hot-path lock-free domain matcher.
    ///
    /// Matches exact domain or subdomains (walking up labels, protecting bare TLDs).
    /// Returns `None` if matcher is disabled, effective mode is not `Enforce`, or table is empty.
    pub fn match_domain(&self, domain: &str) -> Option<TiEnforceMatch> {
        if !self.config.enabled {
            return None;
        }
        let host = domain
            .split(':')
            .next()
            .unwrap_or(domain)
            .trim_end_matches('.');
        if host.is_empty() {
            return None;
        }

        let table = self.table.load();
        if table.effective_mode != EffectiveMode::Enforce || table.domains.is_empty() {
            return None;
        }

        let lowered: Cow<'_, str> = if host.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(host.to_ascii_lowercase())
        } else {
            Cow::Borrowed(host)
        };

        let mut candidate: &str = lowered.as_ref();
        loop {
            if let Some(feed) = table.domains.get(candidate) {
                return Some(TiEnforceMatch {
                    feed: feed.clone(),
                    indicator: candidate.to_string(),
                });
            }
            match candidate.split_once('.') {
                // Walk up one label at a time, but never match a bare TLD.
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => return None,
            }
        }
    }

    /// Spawns background task to reload feed periodically without blocking tokio async workers.
    pub fn spawn_reload_task(self: Arc<Self>) {
        if !self.config.enabled {
            return;
        }
        let interval = self.config.reload_interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let matcher = self.clone();
                let result = tokio::task::spawn_blocking(move || matcher.reload()).await;
                match result {
                    Ok(Ok(count)) => {
                        debug!(indicators = count, "threat-intel enforce feed reloaded")
                    }
                    Ok(Err(e)) => debug!("threat-intel enforce feed reload skipped: {e}"),
                    Err(e) => warn!("threat-intel enforce feed reload task failed: {e}"),
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEED_ENFORCE: &str = r#"{
        "generated_at": "2026-08-25T00:00:00Z",
        "mode": "enforce",
        "domain_count": 2,
        "domains": ["malware-c2.com", "Phish.Example.ORG"],
        "feeds": {"malware-c2.com": "urlhaus", "Phish.Example.ORG": "openphish"}
    }"#;

    const FEED_SHADOW: &str = r#"{
        "generated_at": "2026-08-25T00:00:00Z",
        "mode": "shadow",
        "domain_count": 2,
        "domains": ["malware-c2.com", "Phish.Example.ORG"],
        "feeds": {"malware-c2.com": "urlhaus", "Phish.Example.ORG": "openphish"}
    }"#;

    fn make_matcher(posture: EnforcementPosture, feed_path: &str) -> TiEnforceMatcher {
        TiEnforceMatcher {
            config: TiEnforceConfig {
                enabled: true,
                configured_posture: posture,
                feed_path: PathBuf::from(feed_path),
                reload_interval: Duration::from_secs(300),
            },
            table: ArcSwap::new(Arc::new(TiEnforceTable::default())),
            policy_cache: None,
            metrics: None,
        }
    }

    #[test]
    fn triple_gate_success_enables_enforcement() {
        let m = make_matcher(EnforcementPosture::Enforce, "/var/lib/threat_domains.json");
        let count = m
            .load_from_str(
                FEED_ENFORCE,
                Some(Path::new("/var/lib/threat_domains.json")),
            )
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(m.effective_mode(), EffectiveMode::Enforce);
        assert!(m.is_enforcing());

        // Exact match
        assert_eq!(
            m.match_domain("malware-c2.com"),
            Some(TiEnforceMatch {
                feed: "urlhaus".into(),
                indicator: "malware-c2.com".into(),
            })
        );

        // Subdomain & casing & port
        assert_eq!(
            m.match_domain("Bot1.MALWARE-c2.COM.:8443"),
            Some(TiEnforceMatch {
                feed: "urlhaus".into(),
                indicator: "malware-c2.com".into(),
            })
        );
        assert_eq!(
            m.match_domain("phish.example.org"),
            Some(TiEnforceMatch {
                feed: "openphish".into(),
                indicator: "phish.example.org".into(),
            })
        );
    }

    #[test]
    fn triple_gate_fails_when_posture_is_shadow() {
        let m = make_matcher(EnforcementPosture::Shadow, "/var/lib/threat_domains.json");
        let count = m
            .load_from_str(
                FEED_ENFORCE,
                Some(Path::new("/var/lib/threat_domains.json")),
            )
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(m.effective_mode(), EffectiveMode::ShadowOnly);
        assert!(!m.is_enforcing());
        // Must NOT match/block in ShadowOnly
        assert!(m.match_domain("malware-c2.com").is_none());
    }

    #[test]
    fn triple_gate_fails_when_path_is_shadow() {
        let m = make_matcher(
            EnforcementPosture::Enforce,
            "/var/lib/threat_domains.json.shadow",
        );
        let count = m
            .load_from_str(
                FEED_ENFORCE,
                Some(Path::new("/var/lib/threat_domains.json.shadow")),
            )
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(m.effective_mode(), EffectiveMode::ShadowOnly);
        assert!(m.match_domain("malware-c2.com").is_none());
    }

    #[test]
    fn triple_gate_fails_when_payload_mode_is_shadow() {
        let m = make_matcher(EnforcementPosture::Enforce, "/var/lib/threat_domains.json");
        let count = m
            .load_from_str(FEED_SHADOW, Some(Path::new("/var/lib/threat_domains.json")))
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(m.effective_mode(), EffectiveMode::ShadowOnly);
        assert!(m.match_domain("malware-c2.com").is_none());
    }

    #[test]
    fn does_not_match_bare_tld_or_unrelated() {
        let m = make_matcher(EnforcementPosture::Enforce, "/var/lib/threat_domains.json");
        m.load_from_str(
            FEED_ENFORCE,
            Some(Path::new("/var/lib/threat_domains.json")),
        )
        .unwrap();

        assert!(m.match_domain("com").is_none());
        assert!(m.match_domain("org").is_none());
        assert!(m.match_domain("").is_none());
        assert!(m.match_domain("good-example.com").is_none());
        assert!(m.match_domain("notmalware-c2.com").is_none());
    }

    #[test]
    fn normalizes_feed_labels() {
        assert_eq!(normalize_feed_label(Some("soar:admin")), "soar");
        assert_eq!(normalize_feed_label(Some("urlhaus")), "urlhaus");
        assert_eq!(
            normalize_feed_label(Some("phishing-database")),
            "phishing-database"
        );
        assert_eq!(normalize_feed_label(Some("")), UNKNOWN_FEED);
        assert_eq!(normalize_feed_label(None), UNKNOWN_FEED);
        assert_eq!(normalize_feed_label(Some(&"x".repeat(33))), UNKNOWN_FEED);
    }

    #[test]
    fn disabled_matcher_never_matches() {
        let m = TiEnforceMatcher::disabled();
        assert!(!m.enabled());
        assert_eq!(m.effective_mode(), EffectiveMode::Disabled);
        assert!(m.match_domain("malware-c2.com").is_none());
    }

    #[test]
    fn policy_cache_invalidation_and_metrics() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache_config = crate::policy_cache::PolicyCacheConfig {
            ttl: Duration::from_secs(60),
            max_keys: 100,
        };
        let policy_cache = Arc::new(PolicyDecisionCache::new(cache_config));

        let m = TiEnforceMatcher::new(
            TiEnforceConfig {
                enabled: true,
                configured_posture: EnforcementPosture::Enforce,
                feed_path: PathBuf::from("/var/lib/threat_domains.json"),
                reload_interval: Duration::from_secs(300),
            },
            Some(policy_cache.clone()),
            Some(metrics.clone()),
        );

        // Pre-fill policy cache
        policy_cache.store(None, "test.com", &[], vec!["cat".into()], vec![], None);
        assert!(policy_cache.lookup(None, "test.com", &[]).is_some());

        // Load enforce feed -> should invalidate policy cache
        m.load_from_str(
            FEED_ENFORCE,
            Some(Path::new("/var/lib/threat_domains.json")),
        )
        .unwrap();
        assert!(policy_cache.lookup(None, "test.com", &[]).is_none());

        assert_eq!(
            metrics
                .ti_effective_mode
                .with_label_values(&["enforce", "enforce"])
                .get(),
            1.0
        );
    }
}
