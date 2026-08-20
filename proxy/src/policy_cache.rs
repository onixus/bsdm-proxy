//! Policy decision cache: ACL + categorization per `(principal, domain)`.
//!
//! Hot-path shape (one lookup per request):
//! - **Sharded** `RwLock` maps instead of one global `Mutex`, so concurrent
//!   lookups on different shards never serialize.
//! - **Allocation-free lookups**: the composite key is rendered into a
//!   thread-local scratch buffer and borrowed for the map probe. Only a store
//!   (cache miss) allocates an owned key.
//! - **Bounded eviction**: a full shard drops expired entries first and
//!   otherwise evicts the oldest of a small sample, instead of scanning every
//!   entry to find a global minimum while holding the lock.

use crate::acl::AclDecision;
use crate::hashing::fx_hash_str;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Separator between the principal and the domain in a composite key.
///
/// ASCII Unit Separator: a control character, so it appears in neither a
/// hostname (which the URL host parser rejects it from) nor a directory
/// principal, and `("ab", "c")` cannot alias `("a", "bc")`.
const KEY_SEP: char = '\u{1f}';

/// Groups sorted without heap allocation up to this count (covers real AD users).
const MAX_INLINE_GROUPS: usize = 16;

/// Candidates inspected when a full shard must evict.
const EVICTION_SAMPLE: usize = 8;

/// Number of shards. Power of two so the index is a mask, not a modulo.
const SHARD_COUNT: usize = 16;

thread_local! {
    /// Reused across lookups on this worker thread; never escapes a call.
    static KEY_SCRATCH: RefCell<String> = const { RefCell::new(String::new()) };
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

/// One shard of the decision cache.
type PolicyShard = RwLock<HashMap<Box<str>, PolicyCacheEntry>>;

#[derive(Debug)]
pub struct PolicyDecisionCache {
    config: PolicyCacheConfig,
    generation: AtomicU64,
    shards: Box<[PolicyShard]>,
    /// `max_keys` split across shards (at least one entry per shard).
    per_shard_capacity: usize,
}

pub struct PolicyCacheHit {
    pub blocking: Option<AclDecision>,
    pub categories: Vec<String>,
    pub threat_sources: Vec<String>,
}

/// Render `principal` into `buf`: `user` or `user|sorted,groups`.
///
/// Group order must not change the key, so groups are sorted — in place on the
/// stack for the common case, falling back to a heap sort only for users with
/// more than [`MAX_INLINE_GROUPS`] groups.
fn write_principal(buf: &mut String, username: Option<&str>, groups: &[&str]) {
    buf.push_str(username.unwrap_or("-"));
    if groups.is_empty() {
        return;
    }
    buf.push('|');
    if groups.len() == 1 {
        buf.push_str(groups[0]);
        return;
    }
    if groups.len() <= MAX_INLINE_GROUPS {
        let mut inline = [""; MAX_INLINE_GROUPS];
        let sorted = &mut inline[..groups.len()];
        sorted.copy_from_slice(groups);
        sorted.sort_unstable();
        join_into(buf, sorted);
    } else {
        let mut sorted = groups.to_vec();
        sorted.sort_unstable();
        join_into(buf, &sorted);
    }
}

fn join_into(buf: &mut String, parts: &[&str]) {
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            buf.push(',');
        }
        buf.push_str(part);
    }
}

/// Render the full `principal\x1fdomain` key into `buf`.
fn write_key(buf: &mut String, username: Option<&str>, domain: &str, groups: &[&str]) {
    buf.clear();
    write_principal(buf, username, groups);
    buf.push(KEY_SEP);
    buf.push_str(domain);
}

impl PolicyDecisionCache {
    pub fn new(config: PolicyCacheConfig) -> Self {
        let per_shard_capacity = config.max_keys.div_ceil(SHARD_COUNT).max(1);
        let shards = (0..SHARD_COUNT)
            .map(|_| RwLock::new(HashMap::new()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            config,
            generation: AtomicU64::new(1),
            shards,
            per_shard_capacity,
        }
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled()
    }

    pub fn config(&self) -> &PolicyCacheConfig {
        &self.config
    }

    pub fn invalidate(&self) {
        // Release: the generation bump must be visible to any thread that later
        // reads an entry written before the bump.
        self.generation.fetch_add(1, Ordering::Release);
        for shard in self.shards.iter() {
            if let Ok(mut guard) = shard.write() {
                guard.clear();
            }
        }
    }

    #[inline]
    fn shard_for(&self, key: &str) -> &PolicyShard {
        &self.shards[(fx_hash_str(key) as usize) & (SHARD_COUNT - 1)]
    }

    /// Run `f` with the composite key rendered into the thread-local scratch buffer.
    fn with_key<R>(
        username: Option<&str>,
        domain: &str,
        groups: &[&str],
        f: impl FnOnce(&str) -> R,
    ) -> R {
        KEY_SCRATCH.with(|scratch| {
            let mut buf = scratch.borrow_mut();
            write_key(&mut buf, username, domain, groups);
            f(&buf)
        })
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
        let generation = self.generation.load(Ordering::Acquire);
        Self::with_key(username, domain, groups, |key| {
            let guard = self.shard_for(key).read().ok()?;
            let entry = guard.get(key)?;
            if entry.generation != generation || entry.cached_at.elapsed() > self.config.ttl {
                return None;
            }
            Some(PolicyCacheHit {
                blocking: entry.blocking.clone(),
                categories: entry.categories.clone(),
                threat_sources: entry.threat_sources.clone(),
            })
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
        let entry = PolicyCacheEntry {
            blocking,
            categories,
            threat_sources,
            cached_at: Instant::now(),
            generation: self.generation.load(Ordering::Acquire),
        };
        Self::with_key(username, domain, groups, |key| {
            let Ok(mut guard) = self.shard_for(key).write() else {
                return;
            };
            if let Some(slot) = guard.get_mut(key) {
                *slot = entry;
                return;
            }
            if guard.len() >= self.per_shard_capacity {
                self.evict_one(&mut guard);
            }
            guard.insert(Box::from(key), entry);
        });
    }

    /// Make room in a full shard without scanning it end to end.
    ///
    /// Expired entries are dropped first (they are dead weight anyway). If none
    /// are expired, the oldest of the first [`EVICTION_SAMPLE`] entries is
    /// dropped — approximate LRU at O(1) instead of O(n) under the lock.
    fn evict_one(&self, guard: &mut HashMap<Box<str>, PolicyCacheEntry>) {
        let ttl = self.config.ttl;
        let before = guard.len();
        guard.retain(|_, entry| entry.cached_at.elapsed() <= ttl);
        if guard.len() < before {
            return;
        }
        let victim = guard
            .iter()
            .take(EVICTION_SAMPLE)
            .min_by_key(|(_, entry)| entry.cached_at)
            .map(|(key, _)| key.clone());
        if let Some(victim) = victim {
            guard.remove(&victim);
        }
    }

    /// Total entries across all shards (diagnostics and tests).
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .filter_map(|shard| shard.read().ok().map(|guard| guard.len()))
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
    fn group_order_does_not_change_the_key() {
        let cache = PolicyDecisionCache::new(PolicyCacheConfig {
            ttl: Duration::from_secs(60),
            max_keys: 100,
        });
        cache.store(
            Some("alice"),
            "example.com",
            &["dev", "admins"],
            vec!["news".to_string()],
            Vec::new(),
            None,
        );
        assert!(cache
            .lookup(Some("alice"), "example.com", &["admins", "dev"])
            .is_some());
    }

    #[test]
    fn principal_and_domain_cannot_bleed_into_each_other() {
        let cache = PolicyDecisionCache::new(PolicyCacheConfig {
            ttl: Duration::from_secs(60),
            max_keys: 100,
        });
        // Without a separator, ("ab", "c") and ("a", "bc") would share a key.
        cache.store(
            Some("ab"),
            "c.example",
            &[],
            vec!["blocked".to_string()],
            Vec::new(),
            None,
        );
        assert!(cache.lookup(Some("a"), "bc.example", &[]).is_none());
    }

    #[test]
    fn eviction_keeps_the_cache_bounded() {
        let max_keys = SHARD_COUNT * 4;
        let cache = PolicyDecisionCache::new(PolicyCacheConfig {
            ttl: Duration::from_secs(60),
            max_keys,
        });
        for i in 0..(max_keys * 20) {
            cache.store(
                Some("alice"),
                &format!("host-{i}.example"),
                &[],
                Vec::new(),
                Vec::new(),
                None,
            );
        }
        assert!(
            cache.len() <= max_keys,
            "cache grew past max_keys: {}",
            cache.len()
        );
        assert!(!cache.is_empty());
    }

    #[test]
    fn store_overwrites_without_growing() {
        let cache = PolicyDecisionCache::new(PolicyCacheConfig {
            ttl: Duration::from_secs(60),
            max_keys: 100,
        });
        for _ in 0..10 {
            cache.store(
                Some("alice"),
                "example.com",
                &[],
                vec!["news".to_string()],
                Vec::new(),
                None,
            );
        }
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn expired_entries_are_not_served() {
        let cache = PolicyDecisionCache::new(PolicyCacheConfig {
            ttl: Duration::from_millis(20),
            max_keys: 100,
        });
        cache.store(
            Some("alice"),
            "example.com",
            &[],
            vec!["news".to_string()],
            Vec::new(),
            None,
        );
        std::thread::sleep(Duration::from_millis(40));
        assert!(cache.lookup(Some("alice"), "example.com", &[]).is_none());
    }

    #[test]
    fn many_groups_fall_back_to_heap_sort() {
        let groups: Vec<String> = (0..MAX_INLINE_GROUPS + 4)
            .map(|i| format!("g{i}"))
            .collect();
        let forward: Vec<&str> = groups.iter().map(String::as_str).collect();
        let mut reversed = forward.clone();
        reversed.reverse();

        let cache = PolicyDecisionCache::new(PolicyCacheConfig {
            ttl: Duration::from_secs(60),
            max_keys: 100,
        });
        cache.store(
            Some("alice"),
            "example.com",
            &forward,
            vec!["news".to_string()],
            Vec::new(),
            None,
        );
        assert!(cache
            .lookup(Some("alice"), "example.com", &reversed)
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
