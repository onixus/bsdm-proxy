//! Threat-intel Shadow Mode matcher (issue #330).
//!
//! Loads the observe-only IOC export produced by the `threat-intel` collector
//! while it runs with `TI_ENFORCEMENT_MODE=shadow` (`threat_domains.json.shadow`)
//! and annotates cache events with the feed that matched. This path is strictly
//! observational: it never denies, redirects or bypasses a request. Enforcement
//! stays with the ACL engine and the plain (non-`.shadow`) artifacts.

use crate::metrics::Metrics;
use bsdm_events::CacheEvent;
use serde::Deserialize;
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Default location of the shadow export written by the collector.
const DEFAULT_FEED_PATH: &str = "/var/lib/bsdm-proxy/threat-intel/threat_domains.json.shadow";
const DEFAULT_RELOAD_SECS: u64 = 300;
/// Feed label used when the export carries no per-domain provenance.
const UNKNOWN_FEED: &str = "threat-intel";

#[derive(Debug, Clone)]
pub struct TiShadowConfig {
    pub enabled: bool,
    pub feed_path: PathBuf,
    pub reload_interval: Duration,
}

impl TiShadowConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("TI_SHADOW_MATCH_ENABLED")
            .map(|v| {
                !matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "0" | "false" | "no" | "off"
                )
            })
            .unwrap_or(true);
        let feed_path = std::env::var("TI_SHADOW_FEED_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_FEED_PATH));
        let reload_interval = Duration::from_secs(
            std::env::var("TI_SHADOW_RELOAD_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_RELOAD_SECS)
                .max(10),
        );
        Self {
            enabled,
            feed_path,
            reload_interval,
        }
    }
}

/// A single observe-only match: which feed reported the matched indicator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowMatch {
    pub feed: String,
    pub indicator: String,
}

/// On-disk shape of the collector's shadow export (`threat_intel::rpz::ProxyThreatFeed`).
#[derive(Debug, Deserialize)]
struct ShadowFeedFile {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    feeds: HashMap<String, String>,
}

/// Domain → feed lookup table, hot-path read only.
pub struct TiShadowMatcher {
    config: TiShadowConfig,
    domains: RwLock<HashMap<String, String>>,
}

impl TiShadowMatcher {
    /// Builds the matcher and performs the initial load. A missing file is not
    /// an error: the collector may not have produced an export yet.
    pub fn from_env() -> Self {
        let matcher = Self {
            config: TiShadowConfig::from_env(),
            domains: RwLock::new(HashMap::new()),
        };
        if matcher.config.enabled {
            match matcher.reload() {
                Ok(count) => info!(
                    path = %matcher.config.feed_path.display(),
                    indicators = count,
                    "threat-intel shadow feed loaded (observation only)"
                ),
                Err(e) => debug!(
                    path = %matcher.config.feed_path.display(),
                    "threat-intel shadow feed not loaded: {e}"
                ),
            }
        }
        matcher
    }

    /// Inert matcher for tests and deployments without threat intelligence.
    pub fn disabled() -> Self {
        Self {
            config: TiShadowConfig {
                enabled: false,
                feed_path: PathBuf::from(DEFAULT_FEED_PATH),
                reload_interval: Duration::from_secs(DEFAULT_RELOAD_SECS),
            },
            domains: RwLock::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn len(&self) -> usize {
        self.domains.read().map(|d| d.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Re-reads the export from disk. Returns the number of indicators loaded.
    pub fn reload(&self) -> Result<usize, String> {
        let raw = std::fs::read_to_string(&self.config.feed_path)
            .map_err(|e| format!("{}: {e}", self.config.feed_path.display()))?;
        self.load_from_str(&raw, Some(&self.config.feed_path))
    }

    /// Parses an export and atomically swaps the lookup table.
    pub fn load_from_str(&self, raw: &str, origin: Option<&Path>) -> Result<usize, String> {
        let parsed: ShadowFeedFile =
            serde_json::from_str(raw).map_err(|e| format!("invalid shadow feed JSON: {e}"))?;

        if !parsed.mode.is_empty() && parsed.mode != "shadow" {
            warn!(
                mode = %parsed.mode,
                path = ?origin,
                "threat-intel export is not a shadow artifact; the proxy still treats it as \
                 observation only"
            );
        }

        let mut table = HashMap::with_capacity(parsed.domains.len());
        for domain in parsed.domains {
            let key = domain.trim().trim_end_matches('.').to_ascii_lowercase();
            if key.is_empty() {
                continue;
            }
            let feed = parsed
                .feeds
                .get(&domain)
                .map(String::as_str)
                .unwrap_or(UNKNOWN_FEED)
                .to_string();
            table.insert(key, feed);
        }

        let count = table.len();
        let mut guard = self
            .domains
            .write()
            .map_err(|_| "shadow feed lock poisoned".to_string())?;
        *guard = table;
        Ok(count)
    }

    /// Exact or parent-domain match. Returns `None` when disabled or empty.
    pub fn match_domain(&self, domain: &str) -> Option<ShadowMatch> {
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

        let guard = self.domains.read().ok()?;
        if guard.is_empty() {
            return None;
        }

        let lowered: Cow<'_, str> = if host.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(host.to_ascii_lowercase())
        } else {
            Cow::Borrowed(host)
        };

        let mut candidate: &str = lowered.as_ref();
        loop {
            if let Some(feed) = guard.get(candidate) {
                return Some(ShadowMatch {
                    feed: feed.clone(),
                    indicator: candidate.to_string(),
                });
            }
            match candidate.split_once('.') {
                // Walk up one label at a time, but never match a bare suffix.
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => return None,
            }
        }
    }

    /// Periodically re-reads the export in the background.
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
                // Blocking file IO stays off the async worker.
                let result = tokio::task::spawn_blocking(move || matcher.reload()).await;
                match result {
                    Ok(Ok(count)) => {
                        debug!(indicators = count, "threat-intel shadow feed reloaded")
                    }
                    Ok(Err(e)) => debug!("threat-intel shadow feed reload skipped: {e}"),
                    Err(e) => warn!("threat-intel shadow feed reload task failed: {e}"),
                }
            }
        });
    }
}

/// Annotates an outgoing cache event with a shadow match and counts the metric.
///
/// Observation only: the caller has already made its allow/deny decision and
/// this function must never change it.
pub fn annotate_shadow_match(matcher: &TiShadowMatcher, metrics: &Metrics, event: &mut CacheEvent) {
    if event.threat_shadow_match.is_some() {
        return;
    }
    let Some(hit) = matcher.match_domain(&event.domain) else {
        return;
    };
    metrics.record_ti_shadow_match(&hit.feed);
    debug!(
        domain = %event.domain,
        feed = %hit.feed,
        indicator = %hit.indicator,
        "threat-intel shadow match (request not blocked)"
    );
    event.threat_shadow_match = Some(hit.feed);
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEED: &str = r#"{
        "generated_at": "2026-08-25T00:00:00Z",
        "mode": "shadow",
        "domain_count": 2,
        "domains": ["evil-phish.com", "Bad.Example.NET"],
        "feeds": {"evil-phish.com": "urlhaus", "Bad.Example.NET": "openphish"}
    }"#;

    fn matcher() -> TiShadowMatcher {
        let m = TiShadowMatcher {
            config: TiShadowConfig {
                enabled: true,
                feed_path: PathBuf::from("/nonexistent"),
                reload_interval: Duration::from_secs(300),
            },
            domains: RwLock::new(HashMap::new()),
        };
        assert_eq!(m.load_from_str(FEED, None).unwrap(), 2);
        m
    }

    fn event(domain: &str) -> CacheEvent {
        CacheEvent {
            url: format!("https://{domain}/"),
            method: "GET".into(),
            status: 200,
            cache_key: "k".into(),
            cache_status: "MISS".into(),
            timestamp: 1,
            headers: Default::default(),
            user_id: None,
            username: None,
            client_ip: "10.0.0.1".into(),
            domain: domain.to_string(),
            response_size: 0,
            request_duration_ms: 1,
            content_type: None,
            user_agent: None,
            categories: vec![],
            threat_sources: vec![],
            acl_action: None,
            acl_rule_id: None,
            acl_reason: None,
            session_id: String::new(),
            parent_event_id: None,
            redirect_url: None,
            dlp_violation: None,
            casb_alert: None,
            decision_source: None,
            bypass_reason: None,
            threat_shadow_match: None,
            event_id: "evt".into(),
        }
    }

    #[test]
    fn matches_exact_subdomain_and_normalizes_case() {
        let m = matcher();
        assert_eq!(
            m.match_domain("evil-phish.com"),
            Some(ShadowMatch {
                feed: "urlhaus".into(),
                indicator: "evil-phish.com".into(),
            })
        );
        // Subdomains, host case, trailing dot and port are all handled.
        assert_eq!(
            m.match_domain("Login.EVIL-phish.com.:443").map(|h| h.feed),
            Some("urlhaus".to_string())
        );
        assert_eq!(
            m.match_domain("bad.example.net").map(|h| h.feed),
            Some("openphish".to_string())
        );
    }

    #[test]
    fn does_not_match_unrelated_or_bare_suffix() {
        let m = matcher();
        assert!(m.match_domain("example.com").is_none());
        assert!(m.match_domain("com").is_none());
        assert!(m.match_domain("").is_none());
        assert!(m.match_domain("notevil-phish.com").is_none());
    }

    #[test]
    fn disabled_matcher_never_matches() {
        let m = TiShadowMatcher::disabled();
        assert!(!m.enabled());
        assert!(m.is_empty());
        assert!(m.match_domain("evil-phish.com").is_none());
    }

    #[test]
    fn invalid_feed_keeps_previous_table() {
        let m = matcher();
        assert!(m.load_from_str("{not json", None).is_err());
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn annotation_sets_field_and_increments_metric_without_blocking() {
        let m = matcher();
        let metrics = Metrics::new().unwrap();

        let mut hit = event("login.evil-phish.com");
        annotate_shadow_match(&m, &metrics, &mut hit);
        assert_eq!(hit.threat_shadow_match.as_deref(), Some("urlhaus"));
        // Observation only: nothing in the decision path changed.
        assert_eq!(hit.acl_action, None);
        assert_eq!(hit.status, 200);
        assert_eq!(
            metrics
                .ti_shadow_matches_total
                .with_label_values(&["urlhaus"])
                .get(),
            1.0
        );

        let mut miss = event("example.org");
        annotate_shadow_match(&m, &metrics, &mut miss);
        assert!(miss.threat_shadow_match.is_none());
        assert_eq!(
            metrics
                .ti_shadow_matches_total
                .with_label_values(&["urlhaus"])
                .get(),
            1.0
        );

        // A second matching request increments the same feed counter.
        let mut hit2 = event("evil-phish.com");
        annotate_shadow_match(&m, &metrics, &mut hit2);
        assert_eq!(
            metrics
                .ti_shadow_matches_total
                .with_label_values(&["urlhaus"])
                .get(),
            2.0
        );
    }
}
