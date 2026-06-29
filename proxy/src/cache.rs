//! L1 in-memory HTTP response cache types.

use bytes::Bytes;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Response, StatusCode};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::http_types::Body;

pub const CACHEABLE_METHODS: &[&str] = &["GET", "HEAD"];
pub const CACHEABLE_STATUS_CODES: &[u16] = &[200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501];

#[derive(Clone, Debug)]
pub struct CachedResponse {
    pub status: u16,
    pub headers: Arc<[(Arc<str>, Arc<str>)]>,
    pub body: Bytes,
    pub cached_at: SystemTime,
    pub ttl: Duration,
}

impl CachedResponse {
    #[inline]
    pub fn is_expired(&self) -> bool {
        SystemTime::now()
            .duration_since(self.cached_at)
            .map_or(true, |age| age > self.ttl)
    }

    pub fn to_response(&self) -> Response<Body> {
        self.to_response_with_cache_status("HIT")
    }

    pub fn to_response_with_cache_status(&self, cache_status: &str) -> Response<Body> {
        let mut response = Response::new(Body::new(self.body.clone()));
        *response.status_mut() = StatusCode::from_u16(self.status).unwrap_or(StatusCode::OK);

        let headers_mut = response.headers_mut();
        for (key, value) in self.headers.iter() {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(key.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers_mut.insert(name, val);
            }
        }

        if let Ok(val) = HeaderValue::from_str(cache_status) {
            headers_mut.insert("x-cache-status", val);
        }
        response
    }
}

#[derive(Clone)]
pub struct CacheConfig {
    pub capacity: usize,
    pub default_ttl: Duration,
    pub max_body_size: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            capacity: 10_000,
            default_ttl: Duration::from_secs(3600),
            max_body_size: 10 * 1024 * 1024,
        }
    }
}

impl CacheConfig {
    pub fn from_env() -> Self {
        let capacity = std::env::var("CACHE_CAPACITY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10_000);
        let cache_ttl_secs = std::env::var("CACHE_TTL_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3600);
        let max_body_size = std::env::var("MAX_CACHE_BODY_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10 * 1024 * 1024);

        Self {
            capacity,
            default_ttl: Duration::from_secs(cache_ttl_secs),
            max_body_size,
        }
    }
}

pub fn is_cacheable(method: &str, status: u16, body_size: usize, max_body_size: usize) -> bool {
    CACHEABLE_METHODS.contains(&method)
        && CACHEABLE_STATUS_CODES.contains(&status)
        && body_size <= max_body_size
}
