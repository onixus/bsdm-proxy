//! Policy decision cache: ACL + categorization per `(principal, domain)`.

use crate::acl::AclDecision;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct PolicyCacheKey {
    principal: String,
    domain: String,
}

#[derive(Clone, Debug)]
struct PolicyCacheEntry {
    blocking: Option<AclDecision>,
    categories: Vec<String>,
    threat_sources: Vec<String>,
    cached_at: Instant,
    generation: u64,
}

#[derive(Debug, Clone)]
pub struct PolicyCacheConfig {
    pub ttl: Duration,
    pub max_keys: usize,
}

impl PolicyCacheConfig {
    pub fn from_env() -> Self {
        let ttl_secs = std::env::var("POLICY_DECISION_CACHE_TTL_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(120);
        let max_keys = std::env::var("POLICY_DECISION_CACHE_MAX_KEYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10_000);
        Self {
            ttl: Duration::from_secs(ttl_secs),
            max_keys: max_keys.max(1),
        }
    }

    pub fn enabled(&self) -> bool {
        !self.ttl.is_zero()
    }
}

#[derive(Debug)]
pub struct PolicyDecisionCache {
    config: PolicyCacheConfig,
    generation: AtomicU64,
    entries: Mutex<HashMap<PolicyCacheKey, PolicyCacheEntry>>,
}

pub struct PolicyCacheHit {
    pub blocking: Option<AclDecision>,
    pub categories: Vec<String>,
    pub threat_sources: Vec<String>,
}

impl PolicyDecisionCache {
    pub fn new(config: PolicyCacheConfig) -> Self {
        Self {
            config,
            generation: AtomicU64::new(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled()
    }

    pub fn config(&self) -> &PolicyCacheConfig {
        &self.config
    }

    pub fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.entries.lock().unwrap().clear();
    }

    fn principal_key(username: Option<&str>, groups: &[&str]) -> String {
        let user = username.unwrap_or("-");
        if groups.is_empty() {
            return user.to_string();
        }
        let mut sorted = groups.to_vec();
        sorted.sort_unstable();
        format!("{user}|{}", sorted.join(","))
    }

    pub fn lookup(
        &self,
        username: Option<&str>,
        domain: &str,
        groups: &[&str],
    ) -> Option<PolicyCacheHit> {
        if !self.enabled() {
            return None;
        }
        let key = PolicyCacheKey {
            principal: Self::principal_key(username, groups),
            domain: domain.to_string(),
        };
        let gen = self.generation.load(Ordering::SeqCst);
        let guard = self.entries.lock().unwrap();
        let entry = guard.get(&key)?;
        if entry.generation != gen || entry.cached_at.elapsed() > self.config.ttl {
            return None;
        }
        Some(PolicyCacheHit {
            blocking: entry.blocking.clone(),
            categories: entry.categories.clone(),
            threat_sources: entry.threat_sources.clone(),
        })
    }

    pub fn store(
        &self,
        username: Option<&str>,
        domain: &str,
        groups: &[&str],
        categories: Vec<String>,
        threat_sources: Vec<String>,
        blocking: Option<AclDecision>,
    ) {
        if !self.enabled() {
            return;
        }
        let key = PolicyCacheKey {
            principal: Self::principal_key(username, groups),
            domain: domain.to_string(),
        };
        let entry = PolicyCacheEntry {
            blocking,
            categories,
            threat_sources,
            cached_at: Instant::now(),
            generation: self.generation.load(Ordering::SeqCst),
        };
        let mut guard = self.entries.lock().unwrap();
        if guard.len() >= self.config.max_keys && !guard.contains_key(&key) {
            if let Some(oldest_key) = guard
                .iter()
                .min_by_key(|(_, v)| v.cached_at)
                .map(|(k, _)| k.clone())
            {
                guard.remove(&oldest_key);
            }
        }
        guard.insert(key, entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AclAction, AclDecision};

    #[test]
    fn cache_hit_skips_second_lookup() {
        let cache = PolicyDecisionCache::new(PolicyCacheConfig {
            ttl: Duration::from_secs(60),
            max_keys: 100,
        });
        cache.store(
            Some("alice"),
            "example.com",
            &[],
            vec!["news".to_string()],
            vec!["custom".to_string()],
            None,
        );
        let hit = cache
            .lookup(Some("alice"), "example.com", &[])
            .expect("hit");
        assert!(hit.blocking.is_none());
        assert_eq!(hit.categories, vec!["news".to_string()]);
    }

    #[test]
    fn invalidate_clears_entries() {
        let cache = PolicyDecisionCache::new(PolicyCacheConfig {
            ttl: Duration::from_secs(60),
            max_keys: 100,
        });
        cache.store(
            Some("alice"),
            "example.com",
            &[],
            Vec::new(),
            Vec::new(),
            Some(AclDecision::deny("r1".to_string(), "blocked")),
        );
        cache.invalidate();
        assert!(cache.lookup(Some("alice"), "example.com", &[]).is_none());
    }

    #[test]
    fn different_domains_are_distinct() {
        let cache = PolicyDecisionCache::new(PolicyCacheConfig {
            ttl: Duration::from_secs(60),
            max_keys: 100,
        });
        cache.store(
            Some("alice"),
            "a.com",
            &[],
            vec!["a".to_string()],
            Vec::new(),
            None,
        );
        assert!(cache.lookup(Some("alice"), "b.com", &[]).is_none());
    }

    #[test]
    fn groups_affect_principal_key() {
        let cache = PolicyDecisionCache::new(PolicyCacheConfig {
            ttl: Duration::from_secs(60),
            max_keys: 100,
        });
        cache.store(
            Some("alice"),
            "example.com",
            &["admins"],
            Vec::new(),
            Vec::new(),
            None,
        );
        assert!(cache.lookup(Some("alice"), "example.com", &[]).is_none());
        assert!(cache
            .lookup(Some("alice"), "example.com", &["admins"])
            .is_some());
    }

    #[test]
    fn disabled_when_ttl_zero() {
        let cache = PolicyDecisionCache::new(PolicyCacheConfig {
            ttl: Duration::ZERO,
            max_keys: 100,
        });
        cache.store(
            Some("alice"),
            "example.com",
            &[],
            Vec::new(),
            Vec::new(),
            None,
        );
        assert!(cache.lookup(Some("alice"), "example.com", &[]).is_none());
    }

    #[test]
    fn stores_blocking_decision() {
        let cache = PolicyDecisionCache::new(PolicyCacheConfig {
            ttl: Duration::from_secs(60),
            max_keys: 100,
        });
        let decision = AclDecision::deny("rule-1".to_string(), "blocked");
        cache.store(
            Some("bob"),
            "blocked.test",
            &[],
            Vec::new(),
            Vec::new(),
            Some(decision.clone()),
        );
        let hit = cache.lookup(Some("bob"), "blocked.test", &[]).expect("hit");
        assert_eq!(
            hit.blocking.as_ref().map(|d| d.action),
            Some(AclAction::Deny)
        );
    }
}
