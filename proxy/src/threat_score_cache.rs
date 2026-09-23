//! M5.5 async threat score cache — O(1) lock-free lookup on proxy hot path.
//!
//! Background task polls ml-worker `GET /api/threat-scores`; request handling
//! reads an immutable ArcSwap snapshot and does not allocate lookup keys.

use crate::acl::AclDecision;
use arc_swap::ArcSwap;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ThreatScoreHit {
    pub score: f64,
    pub severity: String,
    pub model: String,
    pub entity_type: String,
    pub entity_id: String,
}

#[derive(Debug, Clone)]
pub struct ThreatScoreConfig {
    pub enabled: bool,
    pub poll_url: String,
    pub poll_interval: Duration,
    pub cache_ttl: Duration,
    pub warn_threshold: f64,
    pub block_threshold: f64,
}

impl ThreatScoreConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("THREAT_SCORE_ENABLED")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        let poll_url = std::env::var("THREAT_SCORE_POLL_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8091/api/threat-scores".into());
        let poll_interval = Duration::from_secs(
            std::env::var("THREAT_SCORE_POLL_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60),
        );
        let cache_ttl = Duration::from_secs(
            std::env::var("THREAT_SCORE_CACHE_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(300),
        );
        let warn_threshold = std::env::var("THREAT_SCORE_WARN_THRESHOLD")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.7);
        let block_threshold = std::env::var("THREAT_SCORE_BLOCK_THRESHOLD")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);
        Self {
            enabled,
            poll_url,
            poll_interval,
            cache_ttl,
            warn_threshold,
            block_threshold,
        }
    }

    pub fn block_enabled(&self) -> bool {
        self.block_threshold > 0.0
    }
}

impl Default for ThreatScoreConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            poll_url: "http://127.0.0.1:8091/api/threat-scores".into(),
            poll_interval: Duration::from_secs(60),
            cache_ttl: Duration::from_secs(300),
            warn_threshold: 0.7,
            block_threshold: 0.0,
        }
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    hit: ThreatScoreHit,
    cached_at: Instant,
}

/// Immutable lookup snapshot.
///
/// Splitting entity types avoids constructing `type:value` strings on every
/// request. The composite client/domain score uses nested maps so both probes
/// borrow the existing `&str` inputs and allocate nothing.
#[derive(Debug, Default)]
struct ThreatScoreTable {
    domains: HashMap<String, CacheEntry>,
    client_ips: HashMap<String, CacheEntry>,
    client_domains: HashMap<String, HashMap<String, CacheEntry>>,
}

impl ThreatScoreTable {
    fn insert(&mut self, row: PollScoreRow, cached_at: Instant) {
        let PollScoreRow {
            entity_type,
            entity_id,
            score,
            severity,
            model,
        } = row;
        let entry = CacheEntry {
            hit: ThreatScoreHit {
                score,
                severity,
                model,
                entity_type: entity_type.clone(),
                entity_id: entity_id.clone(),
            },
            cached_at,
        };

        match entity_type.as_str() {
            "domain" => {
                self.domains.insert(entity_id, entry);
            }
            "client_ip" => {
                self.client_ips.insert(entity_id, entry);
            }
            "client_domain" => {
                if let Some((client_ip, domain)) = entity_id.split_once('|') {
                    self.client_domains
                        .entry(client_ip.to_string())
                        .or_default()
                        .insert(domain.to_string(), entry);
                }
            }
            _ => {
                // Unknown entity types were never reachable from lookup in the
                // previous flat map either. Ignore them instead of growing a
                // table that cannot affect a request decision.
            }
        }
    }
}

#[derive(Debug)]
pub struct ThreatScoreCache {
    config: ThreatScoreConfig,
    entries: ArcSwap<ThreatScoreTable>,
}

#[derive(Debug, Clone, Deserialize)]
struct PollResponse {
    #[serde(default)]
    scores: Vec<PollScoreRow>,
}

#[derive(Debug, Clone, Deserialize)]
struct PollScoreRow {
    entity_type: String,
    entity_id: String,
    score: f64,
    severity: String,
    model: String,
}

impl ThreatScoreCache {
    pub fn new(config: ThreatScoreConfig) -> Self {
        Self {
            config,
            entries: ArcSwap::from_pointee(ThreatScoreTable::default()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn config(&self) -> &ThreatScoreConfig {
        &self.config
    }

    pub fn lookup(&self, domain: &str, client_ip: &str) -> Option<ThreatScoreHit> {
        if !self.enabled() {
            return None;
        }
        let table = self.entries.load();
        let mut best: Option<&CacheEntry> = None;
        let candidates = [
            table.domains.get(domain),
            table.client_ips.get(client_ip),
            table
                .client_domains
                .get(client_ip)
                .and_then(|domains| domains.get(domain)),
        ];
        for entry in candidates.into_iter().flatten() {
            if entry.cached_at.elapsed() > self.config.cache_ttl {
                continue;
            }
            if best
                .as_ref()
                .is_none_or(|current| entry.hit.score > current.hit.score)
            {
                best = Some(entry);
            }
        }
        best.map(|entry| entry.hit.clone())
    }

    pub fn apply_to_policy(
        &self,
        domain: &str,
        client_ip: &str,
        threat_sources: &mut Vec<String>,
        blocking: &mut Option<AclDecision>,
    ) -> bool {
        let Some(hit) = self.lookup(domain, client_ip) else {
            return false;
        };
        if hit.score >= self.config.warn_threshold
            && !threat_sources.iter().any(|s| s == "ml_score")
        {
            threat_sources.push("ml_score".to_string());
        }
        if self.config.block_enabled() && hit.score >= self.config.block_threshold {
            if blocking.is_none() {
                *blocking = Some(AclDecision::deny(
                    "ml-threat-score".to_string(),
                    format!(
                        "ML threat score {:.2} ({}, {})",
                        hit.score, hit.model, hit.severity
                    ),
                ));
            }
            return true;
        }
        hit.score >= self.config.warn_threshold
    }

    fn replace_all(&self, rows: Vec<PollScoreRow>) {
        let mut table = ThreatScoreTable::default();
        let now = Instant::now();
        for row in rows {
            table.insert(row, now);
        }
        self.entries.store(Arc::new(table));
    }

    #[cfg(test)]
    pub(crate) fn replace_hits_for_test(&self, hits: Vec<ThreatScoreHit>) {
        self.replace_all(
            hits.into_iter()
                .map(|hit| PollScoreRow {
                    entity_type: hit.entity_type,
                    entity_id: hit.entity_id,
                    score: hit.score,
                    severity: hit.severity,
                    model: hit.model,
                })
                .collect(),
        );
    }

    pub async fn poll_once(client: &Client, cache: &ThreatScoreCache) -> Result<usize, String> {
        let resp = client
            .get(&cache.config.poll_url)
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("poll HTTP {}", resp.status()));
        }
        let body: PollResponse = resp.json().await.map_err(|e| e.to_string())?;
        let n = body.scores.len();
        cache.replace_all(body.scores);
        debug!("threat score cache refreshed: {n} entries");
        Ok(n)
    }

    pub fn spawn_poll_task(self: Arc<Self>) {
        if !self.enabled() {
            return;
        }
        let url = self.config.poll_url.clone();
        let interval = self.config.poll_interval;
        tokio::spawn(async move {
            let client = Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap_or_else(|_| Client::new());
            loop {
                match Self::poll_once(&client, &self).await {
                    Ok(n) => debug!("threat score poll ok: {n} scores from {url}"),
                    Err(e) => warn!("threat score poll failed ({url}): {e}"),
                }
                tokio::time::sleep(interval).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::AclAction;

    fn enabled_config(block_threshold: f64) -> ThreatScoreConfig {
        ThreatScoreConfig {
            enabled: true,
            poll_url: String::new(),
            poll_interval: Duration::from_secs(60),
            cache_ttl: Duration::from_secs(300),
            warn_threshold: 0.7,
            block_threshold,
        }
    }

    #[test]
    fn lookup_picks_highest_score() {
        let cache = ThreatScoreCache::new(enabled_config(0.0));
        cache.replace_all(vec![
            PollScoreRow {
                entity_type: "domain".into(),
                entity_id: "evil.com".into(),
                score: 0.75,
                severity: "high".into(),
                model: "phishing_lexical_v0".into(),
            },
            PollScoreRow {
                entity_type: "client_ip".into(),
                entity_id: "10.0.0.1".into(),
                score: 0.92,
                severity: "critical".into(),
                model: "cc_beacon_v0".into(),
            },
        ]);
        let hit = cache.lookup("evil.com", "10.0.0.1").expect("hit");
        assert!((hit.score - 0.92).abs() < f64::EPSILON);
    }

    #[test]
    fn client_domain_lookup_is_exact() {
        let cache = ThreatScoreCache::new(enabled_config(0.0));
        cache.replace_all(vec![PollScoreRow {
            entity_type: "client_domain".into(),
            entity_id: "10.0.0.1|evil.com".into(),
            score: 0.88,
            severity: "high".into(),
            model: "client_domain_v0".into(),
        }]);
        assert!(cache.lookup("evil.com", "10.0.0.1").is_some());
        assert!(cache.lookup("evil.com", "10.0.0.2").is_none());
        assert!(cache.lookup("good.com", "10.0.0.1").is_none());
    }

    #[test]
    fn replacing_snapshot_removes_old_scores() {
        let cache = ThreatScoreCache::new(enabled_config(0.0));
        cache.replace_all(vec![PollScoreRow {
            entity_type: "domain".into(),
            entity_id: "old.test".into(),
            score: 0.9,
            severity: "high".into(),
            model: "old".into(),
        }]);
        assert!(cache.lookup("old.test", "10.0.0.1").is_some());
        cache.replace_all(Vec::new());
        assert!(cache.lookup("old.test", "10.0.0.1").is_none());
    }

    #[test]
    fn apply_adds_ml_score_source() {
        let cache = ThreatScoreCache::new(enabled_config(0.0));
        cache.replace_all(vec![PollScoreRow {
            entity_type: "domain".into(),
            entity_id: "bad.test".into(),
            score: 0.85,
            severity: "high".into(),
            model: "ueba_zscore_v0".into(),
        }]);
        let mut sources = Vec::new();
        let mut blocking = None;
        assert!(cache.apply_to_policy("bad.test", "1.2.3.4", &mut sources, &mut blocking));
        assert!(sources.contains(&"ml_score".to_string()));
        assert!(blocking.is_none());
    }

    #[test]
    fn block_when_threshold_set() {
        let cache = ThreatScoreCache::new(enabled_config(0.9));
        cache.replace_all(vec![PollScoreRow {
            entity_type: "domain".into(),
            entity_id: "c2.test".into(),
            score: 0.95,
            severity: "critical".into(),
            model: "cc_beacon_v0".into(),
        }]);
        let mut sources = Vec::new();
        let mut blocking = None;
        cache.apply_to_policy("c2.test", "10.0.0.5", &mut sources, &mut blocking);
        assert!(blocking.is_some());
        assert_eq!(blocking.as_ref().unwrap().action, AclAction::Deny);
    }

    #[test]
    fn disabled_returns_none() {
        let cache = ThreatScoreCache::new(ThreatScoreConfig {
            enabled: false,
            ..enabled_config(0.0)
        });
        assert!(cache.lookup("a.com", "1.1.1.1").is_none());
    }
}
