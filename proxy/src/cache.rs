//! L1 in-memory HTTP response cache types.

use bytes::Bytes;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Response, StatusCode};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::warn;

use crate::cache_compress::{decode_body, prepare_body_for_cache, BodyEncoding, CompressionConfig};
use crate::http_types::Body;

pub const CACHEABLE_METHODS: &[&str] = &["GET", "HEAD"];
pub const CACHEABLE_STATUS_CODES: &[u16] = &[200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501];

#[derive(Clone, Debug)]
pub struct CachedResponse {
    pub status: u16,
    pub headers: Arc<[(Arc<str>, Arc<str>)]>,
    pub body: Bytes,
    pub body_encoding: BodyEncoding,
    /// Logical response body size (uncompressed) for clients and metrics.
    pub uncompressed_len: usize,
    pub cached_at: SystemTime,
    pub ttl: Duration,
    pub etag: Option<Arc<str>>,
    pub last_modified: Option<Arc<str>>,
    pub is_negative: bool,
    pub must_revalidate: bool,
}

impl CachedResponse {
    #[inline]
    pub fn is_expired(&self) -> bool {
        SystemTime::now()
            .duration_since(self.cached_at)
            .map_or(true, |age| age > self.ttl)
    }

    #[inline]
    pub fn can_serve_fresh(&self) -> bool {
        !self.must_revalidate && !self.is_expired()
    }

    pub fn has_validators(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }

    /// Refresh metadata after a `304 Not Modified` revalidation.
    pub fn refreshed_after_not_modified(&self, ttl: Duration) -> Self {
        let mut updated = self.clone();
        updated.cached_at = SystemTime::now();
        updated.ttl = ttl;
        updated.must_revalidate = false;
        updated
    }

    pub fn response_body_len(&self) -> usize {
        self.uncompressed_len
    }

    pub fn decoded_body(&self) -> Option<Bytes> {
        match decode_body(&self.body, self.body_encoding) {
            Ok(body) => Some(body),
            Err(e) => {
                warn!(
                    "failed to decode cached body ({:?}): {e}",
                    self.body_encoding
                );
                None
            }
        }
    }

    pub fn to_response(&self) -> Response<Body> {
        self.to_response_with_cache_status("HIT")
    }

    pub fn response_body(&self) -> Bytes {
        match self.body_encoding {
            BodyEncoding::Raw => self.body.clone(),
            _ => self.decoded_body().unwrap_or_else(|| self.body.clone()),
        }
    }

    pub fn to_response_with_cache_status(&self, cache_status: &str) -> Response<Body> {
        let body = self.response_body();
        let mut response = Response::new(Body::new(body));
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

        if let Ok(val) = HeaderValue::from_str(&self.uncompressed_len.to_string()) {
            headers_mut.insert("content-length", val);
        }

        if let Ok(val) = HeaderValue::from_str(cache_status) {
            headers_mut.insert("x-cache-status", val);
        }
        response
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_upstream(
        status: u16,
        headers: Arc<[(Arc<str>, Arc<str>)]>,
        body: Bytes,
        ttl: Duration,
        compression: &CompressionConfig,
        etag: Option<Arc<str>>,
        last_modified: Option<Arc<str>>,
        is_negative: bool,
        must_revalidate: bool,
    ) -> Self {
        let prepared = prepare_body_for_cache(body, headers, compression);
        Self {
            status,
            headers: prepared.headers,
            body: prepared.body,
            body_encoding: prepared.encoding,
            uncompressed_len: prepared.uncompressed_len,
            cached_at: SystemTime::now(),
            ttl,
            etag,
            last_modified,
            is_negative,
            must_revalidate,
        }
    }
}

#[derive(Clone)]
pub struct CacheConfig {
    pub capacity: usize,
    pub default_ttl: Duration,
    pub max_body_size: usize,
    pub compression: CompressionConfig,
    pub negative_cache_enabled: bool,
    pub negative_cache_ttl: Duration,
    pub honor_cache_control: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            capacity: 10_000,
            default_ttl: Duration::from_secs(3600),
            max_body_size: 10 * 1024 * 1024,
            compression: CompressionConfig::default(),
            negative_cache_enabled: true,
            negative_cache_ttl: Duration::from_secs(120),
            honor_cache_control: true,
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
        let negative_cache_enabled = std::env::var("NEGATIVE_CACHE_ENABLED")
            .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no"))
            .unwrap_or(true);
        let negative_cache_ttl_secs = std::env::var("NEGATIVE_CACHE_TTL_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(120);
        let honor_cache_control = std::env::var("CACHE_HONOR_CACHE_CONTROL")
            .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no"))
            .unwrap_or(true);

        Self {
            capacity,
            default_ttl: Duration::from_secs(cache_ttl_secs),
            max_body_size,
            compression: CompressionConfig::from_env(),
            negative_cache_enabled,
            negative_cache_ttl: Duration::from_secs(negative_cache_ttl_secs),
            honor_cache_control,
        }
    }
}

pub fn is_cacheable(method: &str, status: u16, body_size: usize, max_body_size: usize) -> bool {
    CACHEABLE_METHODS.contains(&method)
        && CACHEABLE_STATUS_CODES.contains(&status)
        && body_size <= max_body_size
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache_compress::CompressionConfig;

    #[test]
    fn response_body_raw_skips_decode() {
        let payload = Bytes::from_static(b"cached-payload");
        let cached = CachedResponse {
            status: 200,
            headers: Arc::from([]),
            body: payload.clone(),
            body_encoding: BodyEncoding::Raw,
            uncompressed_len: payload.len(),
            cached_at: SystemTime::now(),
            ttl: Duration::from_secs(60),
            etag: None,
            last_modified: None,
            is_negative: false,
            must_revalidate: false,
        };
        let served = cached.response_body();
        assert_eq!(served, payload);
        assert_eq!(served.as_ptr(), cached.body.as_ptr());
    }

    #[test]
    fn cached_response_serves_decompressed_body() {
        let body = Bytes::from("y".repeat(2048));
        let headers: Arc<[(Arc<str>, Arc<str>)]> =
            Arc::from([(Arc::from("content-type"), Arc::from("text/plain"))]);
        let compression = CompressionConfig {
            codec: BodyEncoding::Zstd,
            min_bytes: 512,
            zstd_level: 3,
        };
        let cached = CachedResponse::from_upstream(
            200,
            headers,
            body.clone(),
            Duration::from_secs(60),
            &compression,
            None,
            None,
            false,
            false,
        );
        assert_eq!(cached.body_encoding, BodyEncoding::Zstd);
        let response = cached.to_response();
        let collected = http_body_util::BodyExt::collect(response.into_body());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let bytes = rt.block_on(collected).unwrap().to_bytes();
        assert_eq!(bytes, body);
    }

    #[test]
    fn can_serve_fresh_respects_must_revalidate() {
        let cached = CachedResponse {
            status: 200,
            headers: Arc::from([]),
            body: Bytes::new(),
            body_encoding: BodyEncoding::Raw,
            uncompressed_len: 0,
            cached_at: SystemTime::now(),
            ttl: Duration::from_secs(3600),
            etag: Some(Arc::from("\"x\"")),
            last_modified: None,
            is_negative: false,
            must_revalidate: true,
        };
        assert!(!cached.can_serve_fresh());
    }
}
