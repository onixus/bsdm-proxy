//! Token-bucket rate limiting per client IP and authenticated user.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Which limit was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitViolation {
    Ip,
    User,
}

/// Per-key token bucket.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(burst: f64) -> Self {
        Self {
            tokens: burst,
            last_refill: Instant::now(),
        }
    }

    fn try_acquire(&mut self, rate: f64, burst: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate).min(burst);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Rate limit configuration loaded from environment.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub ip_rps: f64,
    pub ip_burst: f64,
    pub user_rps: f64,
    pub user_burst: f64,
    pub max_keys: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ip_rps: 100.0,
            ip_burst: 200.0,
            user_rps: 50.0,
            user_burst: 100.0,
            max_keys: 10_000,
        }
    }
}

impl RateLimitConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("RATE_LIMIT_ENABLED")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);

        let ip_rps = parse_positive_f64("RATE_LIMIT_IP_RPS", 100.0);
        let ip_burst = parse_positive_f64("RATE_LIMIT_IP_BURST", ip_rps * 2.0);
        let user_rps = parse_positive_f64("RATE_LIMIT_USER_RPS", 50.0);
        let user_burst = parse_positive_f64("RATE_LIMIT_USER_BURST", user_rps * 2.0);
        let max_keys = std::env::var("RATE_LIMIT_MAX_KEYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10_000)
            .max(1);

        Self {
            enabled,
            ip_rps,
            ip_burst,
            user_rps,
            user_burst,
            max_keys,
        }
    }
}

fn parse_positive_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|v| *v > 0.0)
        .unwrap_or(default)
}

/// Token-bucket rate limiter with separate buckets per IP and per user.
pub struct RateLimiter {
    config: RateLimitConfig,
    ip_buckets: Mutex<HashMap<String, TokenBucket>>,
    user_buckets: Mutex<HashMap<String, TokenBucket>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            ip_buckets: Mutex::new(HashMap::new()),
            user_buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Returns `Some(violation)` when the request must be rejected.
    pub fn check(&self, client_ip: &str, username: Option<&str>) -> Option<RateLimitViolation> {
        if !self.config.enabled {
            return None;
        }

        if !self.try_acquire(
            &self.ip_buckets,
            client_ip,
            self.config.ip_rps,
            self.config.ip_burst,
        ) {
            return Some(RateLimitViolation::Ip);
        }

        if let Some(user) = username.filter(|u| !u.is_empty()) {
            if !self.try_acquire(
                &self.user_buckets,
                user,
                self.config.user_rps,
                self.config.user_burst,
            ) {
                return Some(RateLimitViolation::User);
            }
        }

        None
    }

    fn try_acquire(
        &self,
        buckets: &Mutex<HashMap<String, TokenBucket>>,
        key: &str,
        rate: f64,
        burst: f64,
    ) -> bool {
        let mut guard = buckets
            .lock()
            .expect("rate limit bucket map mutex poisoned");

        if guard.len() >= self.config.max_keys && !guard.contains_key(key) {
            if let Some(evict_key) = guard.keys().next().cloned() {
                guard.remove(&evict_key);
            }
        }

        guard
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(burst))
            .try_acquire(rate, burst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    fn enabled_config(ip_rps: f64, ip_burst: f64) -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            ip_rps,
            ip_burst,
            user_rps: 10.0,
            user_burst: 10.0,
            max_keys: 100,
        }
    }

    #[test]
    fn disabled_allows_all() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        assert!(limiter.check("10.0.0.1", None).is_none());
    }

    #[test]
    fn burst_then_reject() {
        let limiter = RateLimiter::new(enabled_config(1.0, 2.0));
        assert!(limiter.check("10.0.0.1", None).is_none());
        assert!(limiter.check("10.0.0.1", None).is_none());
        assert_eq!(
            limiter.check("10.0.0.1", None),
            Some(RateLimitViolation::Ip)
        );
    }

    #[test]
    fn separate_ips_have_separate_buckets() {
        let limiter = RateLimiter::new(enabled_config(1.0, 1.0));
        assert!(limiter.check("10.0.0.1", None).is_none());
        assert_eq!(
            limiter.check("10.0.0.1", None),
            Some(RateLimitViolation::Ip)
        );
        assert!(limiter.check("10.0.0.2", None).is_none());
    }

    #[test]
    fn user_limit_applies_when_authenticated() {
        let config = RateLimitConfig {
            enabled: true,
            ip_rps: 1000.0,
            ip_burst: 1000.0,
            user_rps: 1.0,
            user_burst: 1.0,
            max_keys: 100,
        };
        let limiter = RateLimiter::new(config);
        assert!(limiter.check("10.0.0.1", Some("alice")).is_none());
        assert_eq!(
            limiter.check("10.0.0.1", Some("alice")),
            Some(RateLimitViolation::User)
        );
        assert!(limiter.check("10.0.0.1", Some("bob")).is_none());
    }

    #[test]
    fn tokens_refill_over_time() {
        let limiter = RateLimiter::new(enabled_config(10.0, 1.0));
        assert!(limiter.check("10.0.0.1", None).is_none());
        assert_eq!(
            limiter.check("10.0.0.1", None),
            Some(RateLimitViolation::Ip)
        );
        thread::sleep(Duration::from_millis(150));
        assert!(limiter.check("10.0.0.1", None).is_none());
    }

    #[test]
    fn evicts_oldest_key_when_at_capacity() {
        let config = RateLimitConfig {
            enabled: true,
            ip_rps: 1.0,
            ip_burst: 1.0,
            user_rps: 1.0,
            user_burst: 1.0,
            max_keys: 2,
        };
        let limiter = RateLimiter::new(config);
        assert!(limiter.check("10.0.0.1", None).is_none());
        assert!(limiter.check("10.0.0.2", None).is_none());
        assert!(limiter.check("10.0.0.3", None).is_none());
    }
}
