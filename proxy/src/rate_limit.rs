//! Token-bucket rate limiting per client IP, authenticated user, and API key.

use hyper::header::{HeaderMap, AUTHORIZATION};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Which limit was exceeded (or missing required credential).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitViolation {
    Ip,
    User,
    ApiKey,
    /// `RATE_LIMIT_API_KEY_REQUIRED=true` but no key was present.
    ApiKeyMissing,
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
    pub api_key_rps: f64,
    pub api_key_burst: f64,
    /// Header name for API key (default `x-api-key`).
    pub api_key_header: String,
    /// Also accept `Authorization: Bearer <key>`.
    pub api_key_bearer: bool,
    /// Reject requests without an API key when rate limiting is enabled.
    pub api_key_required: bool,
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
            api_key_rps: 20.0,
            api_key_burst: 40.0,
            api_key_header: "x-api-key".to_string(),
            api_key_bearer: true,
            api_key_required: false,
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
        let api_key_rps = parse_positive_f64("RATE_LIMIT_API_KEY_RPS", 20.0);
        let api_key_burst = parse_positive_f64("RATE_LIMIT_API_KEY_BURST", api_key_rps * 2.0);
        let api_key_header = std::env::var("RATE_LIMIT_API_KEY_HEADER")
            .ok()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "x-api-key".to_string());
        let api_key_bearer = std::env::var("RATE_LIMIT_API_KEY_BEARER")
            .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no"))
            .unwrap_or(true);
        let api_key_required = std::env::var("RATE_LIMIT_API_KEY_REQUIRED")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
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
            api_key_rps,
            api_key_burst,
            api_key_header,
            api_key_bearer,
            api_key_required,
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

/// Extract API key from request headers using config (header and/or Bearer).
pub fn extract_api_key(headers: &HeaderMap, config: &RateLimitConfig) -> Option<String> {
    let header_name = config.api_key_header.as_str();
    for (name, value) in headers.iter() {
        if name.as_str().eq_ignore_ascii_case(header_name) {
            if let Ok(v) = value.to_str() {
                let key = v.trim();
                if !key.is_empty() {
                    return Some(key.to_string());
                }
            }
        }
    }

    if config.api_key_bearer {
        if let Some(value) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
            if let Some(token) = value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
            {
                let key = token.trim();
                if !key.is_empty() {
                    return Some(key.to_string());
                }
            }
        }
    }

    None
}

use redis::aio::ConnectionManager;
use redis::AsyncCommands;

/// Token-bucket rate limiter with separate buckets per IP, user, and API key.
pub struct RateLimiter {
    config: RateLimitConfig,
    ip_buckets: Mutex<HashMap<String, TokenBucket>>,
    user_buckets: Mutex<HashMap<String, TokenBucket>>,
    api_key_buckets: Mutex<HashMap<String, TokenBucket>>,
    redis_conn: Option<ConnectionManager>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            ip_buckets: Mutex::new(HashMap::new()),
            user_buckets: Mutex::new(HashMap::new()),
            api_key_buckets: Mutex::new(HashMap::new()),
            redis_conn: None,
        }
    }

    pub fn with_redis(mut self, conn: Option<ConnectionManager>) -> Self {
        self.redis_conn = conn;
        self
    }

    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    pub fn is_distributed(&self) -> bool {
        self.redis_conn.is_some()
    }

    /// Async rate limit check supporting distributed Redis counters with fallback to local token buckets.
    pub async fn check_async(
        &self,
        client_ip: &str,
        username: Option<&str>,
        api_key: Option<&str>,
    ) -> Option<RateLimitViolation> {
        if !self.config.enabled {
            return None;
        }

        if self.config.api_key_required && api_key.filter(|k| !k.is_empty()).is_none() {
            return Some(RateLimitViolation::ApiKeyMissing);
        }

        // Distributed Redis checks if available
        if let Some(ref conn) = self.redis_conn {
            let window = 1u64; // 1-second sliding bucket
            let mut conn = conn.clone();

            // Check IP
            let key = format!("bsdm:ratelimit:ip:{}", client_ip);
            if let Ok(count) = conn.incr::<_, i64, i64>(&key, 1).await {
                if count == 1 {
                    let _ = conn.expire::<_, ()>(&key, window as i64).await;
                }
                if (count as f64) > self.config.ip_burst {
                    return Some(RateLimitViolation::Ip);
                }
            }

            // Check User
            if let Some(user) = username.filter(|u| !u.is_empty()) {
                let ukey = format!("bsdm:ratelimit:user:{}", user);
                if let Ok(ucount) = conn.incr::<_, i64, i64>(&ukey, 1).await {
                    if ucount == 1 {
                        let _ = conn.expire::<_, ()>(&ukey, window as i64).await;
                    }
                    if (ucount as f64) > self.config.user_burst {
                        return Some(RateLimitViolation::User);
                    }
                }
            }

            // Check API Key
            if let Some(key_val) = api_key.filter(|k| !k.is_empty()) {
                let kkey = format!("bsdm:ratelimit:apikey:{}", key_val);
                if let Ok(kcount) = conn.incr::<_, i64, i64>(&kkey, 1).await {
                    if kcount == 1 {
                        let _ = conn.expire::<_, ()>(&kkey, window as i64).await;
                    }
                    if (kcount as f64) > self.config.api_key_burst {
                        return Some(RateLimitViolation::ApiKey);
                    }
                }
            }

            return None;
        }

        // Fallback to local token buckets
        self.check(client_ip, username, api_key)
    }

    /// Returns `Some(violation)` when the request must be rejected (local fallback sync mode).
    pub fn check(
        &self,
        client_ip: &str,
        username: Option<&str>,
        api_key: Option<&str>,
    ) -> Option<RateLimitViolation> {
        if !self.config.enabled {
            return None;
        }

        if self.config.api_key_required && api_key.filter(|k| !k.is_empty()).is_none() {
            return Some(RateLimitViolation::ApiKeyMissing);
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

        if let Some(key) = api_key.filter(|k| !k.is_empty()) {
            if !self.try_acquire(
                &self.api_key_buckets,
                key,
                self.config.api_key_rps,
                self.config.api_key_burst,
            ) {
                return Some(RateLimitViolation::ApiKey);
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
    use hyper::header::HeaderValue;
    use std::thread;
    use std::time::Duration;

    fn enabled_config(ip_rps: f64, ip_burst: f64) -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            ip_rps,
            ip_burst,
            user_rps: 10.0,
            user_burst: 10.0,
            api_key_rps: 10.0,
            api_key_burst: 10.0,
            api_key_header: "x-api-key".to_string(),
            api_key_bearer: true,
            api_key_required: false,
            max_keys: 100,
        }
    }

    #[test]
    fn disabled_allows_all() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        assert!(limiter.check("10.0.0.1", None, None).is_none());
    }

    #[test]
    fn burst_then_reject() {
        let limiter = RateLimiter::new(enabled_config(1.0, 2.0));
        assert!(limiter.check("10.0.0.1", None, None).is_none());
        assert!(limiter.check("10.0.0.1", None, None).is_none());
        assert_eq!(
            limiter.check("10.0.0.1", None, None),
            Some(RateLimitViolation::Ip)
        );
    }

    #[test]
    fn separate_ips_have_separate_buckets() {
        let limiter = RateLimiter::new(enabled_config(1.0, 1.0));
        assert!(limiter.check("10.0.0.1", None, None).is_none());
        assert_eq!(
            limiter.check("10.0.0.1", None, None),
            Some(RateLimitViolation::Ip)
        );
        assert!(limiter.check("10.0.0.2", None, None).is_none());
    }

    #[test]
    fn user_limit_applies_when_authenticated() {
        let config = RateLimitConfig {
            enabled: true,
            ip_rps: 1000.0,
            ip_burst: 1000.0,
            user_rps: 1.0,
            user_burst: 1.0,
            api_key_rps: 1000.0,
            api_key_burst: 1000.0,
            api_key_header: "x-api-key".to_string(),
            api_key_bearer: true,
            api_key_required: false,
            max_keys: 100,
        };
        let limiter = RateLimiter::new(config);
        assert!(limiter.check("10.0.0.1", Some("alice"), None).is_none());
        assert_eq!(
            limiter.check("10.0.0.1", Some("alice"), None),
            Some(RateLimitViolation::User)
        );
        assert!(limiter.check("10.0.0.1", Some("bob"), None).is_none());
    }

    #[test]
    fn api_key_limit_applies_per_key() {
        let mut config = enabled_config(1000.0, 1000.0);
        config.api_key_rps = 1.0;
        config.api_key_burst = 1.0;
        let limiter = RateLimiter::new(config);
        assert!(limiter.check("10.0.0.1", None, Some("key-a")).is_none());
        assert_eq!(
            limiter.check("10.0.0.1", None, Some("key-a")),
            Some(RateLimitViolation::ApiKey)
        );
        assert!(limiter.check("10.0.0.1", None, Some("key-b")).is_none());
    }

    #[test]
    fn api_key_required_rejects_missing() {
        let mut config = enabled_config(1000.0, 1000.0);
        config.api_key_required = true;
        let limiter = RateLimiter::new(config);
        assert_eq!(
            limiter.check("10.0.0.1", None, None),
            Some(RateLimitViolation::ApiKeyMissing)
        );
        assert!(limiter.check("10.0.0.1", None, Some("secret")).is_none());
    }

    #[test]
    fn extract_api_key_from_header_and_bearer() {
        let config = RateLimitConfig::default();
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("from-header"));
        assert_eq!(
            extract_api_key(&headers, &config).as_deref(),
            Some("from-header")
        );

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer tok-1"));
        assert_eq!(extract_api_key(&headers, &config).as_deref(), Some("tok-1"));
    }

    #[test]
    fn tokens_refill_over_time() {
        let limiter = RateLimiter::new(enabled_config(10.0, 1.0));
        assert!(limiter.check("10.0.0.1", None, None).is_none());
        assert_eq!(
            limiter.check("10.0.0.1", None, None),
            Some(RateLimitViolation::Ip)
        );
        thread::sleep(Duration::from_millis(150));
        assert!(limiter.check("10.0.0.1", None, None).is_none());
    }

    #[test]
    fn evicts_oldest_key_when_at_capacity() {
        let config = RateLimitConfig {
            enabled: true,
            ip_rps: 1.0,
            ip_burst: 1.0,
            user_rps: 1.0,
            user_burst: 1.0,
            api_key_rps: 1.0,
            api_key_burst: 1.0,
            api_key_header: "x-api-key".to_string(),
            api_key_bearer: true,
            api_key_required: false,
            max_keys: 2,
        };
        let limiter = RateLimiter::new(config);
        assert!(limiter.check("10.0.0.1", None, None).is_none());
        assert!(limiter.check("10.0.0.2", None, None).is_none());
        assert!(limiter.check("10.0.0.3", None, None).is_none());
    }
}
