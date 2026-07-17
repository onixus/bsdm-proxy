//! M5.5 async threat score cache — O(1) lookup on proxy hot path.
//!
//! Background task polls ml-worker `GET /api/threat-scores`; request path only reads memory.

use crate::acl::AclDecision;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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

#[derive(Debug, Clone)]
struct CacheEntry {
    hit: ThreatScoreHit,
    cached_at: Instant,
}

#[derive(Debug)]
pub struct ThreatScoreCache {
    config: ThreatScoreConfig,
    entries: Arc<Mutex<HashMap<String, CacheEntry>>>,
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
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn config(&self) -> &ThreatScoreConfig {
        &self.config
    }

    fn cache_key(entity_type: &str, entity_id: &str) -> String {
        format!("{entity_type}:{entity_id}")
    }

    pub fn lookup(&self, domain: &str, client_ip: &str) -> Option<ThreatScoreHit> {
        if !self.enabled() {
            return None;
        }
        let guard = self.entries.lock().unwrap();
        let candidates = [
            Self::cache_key("domain", domain),
            Self::cache_key("client_ip", client_ip),
            Self::cache_key("client_domain", &format!("{client_ip}|{domain}")),
        ];
        let mut best: Option<&CacheEntry> = None;
        for key in candidates {
            if let Some(entry) = guard.get(&key) {
                if entry.cached_at.elapsed() > self.config.cache_ttl {
                    continue;
                }
                if best.as_ref().is_none_or(|b| entry.hit.score > b.hit.score) {
                    best = Some(entry);
                }
            }
        }
        best.map(|e| e.hit.clone())
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
        let mut map = HashMap::new();
        let now = Instant::now();
        for row in rows {
            let key = Self::cache_key(&row.entity_type, &row.entity_id);
            map.insert(
                key,
                CacheEntry {
                    hit: ThreatScoreHit {
                        score: row.score,
                        severity: row.severity,
                        model: row.model,
                        entity_type: row.entity_type,
                        entity_id: row.entity_id,
                    },
                    cached_at: now,
                },
            );
        }
        *self.entries.lock().unwrap() = map;
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

    #[test]
    fn lookup_picks_highest_score() {
        let cache = ThreatScoreCache::new(ThreatScoreConfig {
            enabled: true,
            poll_url: String::new(),
            poll_interval: Duration::from_secs(60),
            cache_ttl: Duration::from_secs(300),
            warn_threshold: 0.7,
            block_threshold: 0.0,
        });
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
    fn apply_adds_ml_score_source() {
        let cache = ThreatScoreCache::new(ThreatScoreConfig {
            enabled: true,
            poll_url: String::new(),
            poll_interval: Duration::from_secs(60),
            cache_ttl: Duration::from_secs(300),
            warn_threshold: 0.7,
            block_threshold: 0.0,
        });
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
        let cache = ThreatScoreCache::new(ThreatScoreConfig {
            enabled: true,
            poll_url: String::new(),
            poll_interval: Duration::from_secs(60),
            cache_ttl: Duration::from_secs(300),
            warn_threshold: 0.7,
            block_threshold: 0.9,
        });
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
            poll_url: String::new(),
            poll_interval: Duration::from_secs(60),
            cache_ttl: Duration::from_secs(300),
            warn_threshold: 0.7,
            block_threshold: 0.0,
        });
        assert!(cache.lookup("a.com", "1.1.1.1").is_none());
    }
}
