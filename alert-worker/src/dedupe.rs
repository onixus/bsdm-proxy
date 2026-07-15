//! In-memory fingerprint dedupe with TTL.

use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub struct DedupeCache {
    seen: HashMap<String, Instant>,
}

impl DedupeCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if this fingerprint should fire (not suppressed).
    pub fn should_fire(&mut self, fingerprint: &str, now: Instant, ttl: Duration) -> bool {
        self.evict(now, ttl);
        match self.seen.get(fingerprint) {
            Some(prev) if now.duration_since(*prev) < ttl => false,
            _ => {
                self.seen.insert(fingerprint.to_string(), now);
                true
            }
        }
    }

    fn evict(&mut self, now: Instant, ttl: Duration) {
        self.seen
            .retain(|_, stamped| now.duration_since(*stamped) < ttl);
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suppresses_within_ttl() {
        let mut cache = DedupeCache::new();
        let now = Instant::now();
        let ttl = Duration::from_secs(60);
        assert!(cache.should_fire("fp1", now, ttl));
        assert!(!cache.should_fire("fp1", now + Duration::from_secs(10), ttl));
        assert!(cache.should_fire("fp1", now + Duration::from_secs(61), ttl));
        assert!(cache.should_fire("fp2", now, ttl));
    }
}
