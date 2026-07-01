//! Redis L2 HTTP response cache (shared across proxy instances).

use crate::cache::CachedResponse;
use crate::cache_compress::BodyEncoding;
use crate::metrics::Metrics;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::Bytes;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

#[derive(Clone, Debug)]
pub struct L2CacheConfig {
    pub enabled: bool,
    pub url: String,
    pub key_prefix: String,
}

impl L2CacheConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("REDIS_L2_ENABLED")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        let url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let key_prefix =
            std::env::var("REDIS_KEY_PREFIX").unwrap_or_else(|_| "bsdm:http:".to_string());

        Self {
            enabled,
            url,
            key_prefix,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CachedResponseWire {
    status: u16,
    headers: Vec<(String, String)>,
    body_b64: String,
    #[serde(default)]
    body_encoding: Option<String>,
    #[serde(default)]
    uncompressed_len: Option<usize>,
    cached_at_secs: u64,
    ttl_secs: u64,
    #[serde(default)]
    etag: Option<String>,
    #[serde(default)]
    last_modified: Option<String>,
    #[serde(default)]
    is_negative: bool,
    #[serde(default)]
    must_revalidate: bool,
}

impl CachedResponseWire {
    fn from_cached(value: &CachedResponse) -> Option<Self> {
        let cached_at_secs = value.cached_at.duration_since(UNIX_EPOCH).ok()?.as_secs();
        let headers = value
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Some(Self {
            status: value.status,
            headers,
            body_b64: B64.encode(value.stored_body_bytes().as_ref()),
            body_encoding: if value.body_encoding == BodyEncoding::Raw {
                None
            } else {
                Some(value.body_encoding.wire_name().to_string())
            },
            uncompressed_len: Some(value.uncompressed_len),
            cached_at_secs,
            ttl_secs: value.ttl.as_secs(),
            etag: value.etag.as_ref().map(|v| v.to_string()),
            last_modified: value.last_modified.as_ref().map(|v| v.to_string()),
            is_negative: value.is_negative,
            must_revalidate: value.must_revalidate,
        })
    }

    fn into_cached(self) -> Option<CachedResponse> {
        let body = Bytes::from(B64.decode(self.body_b64).ok()?);
        let headers: Arc<[(Arc<str>, Arc<str>)]> = self
            .headers
            .into_iter()
            .map(|(k, v)| (Arc::from(k.as_str()), Arc::from(v.as_str())))
            .collect();
        let body_encoding = self
            .body_encoding
            .as_deref()
            .and_then(BodyEncoding::from_wire)
            .unwrap_or(BodyEncoding::Raw);
        let uncompressed_len = self.uncompressed_len.unwrap_or_else(|| body.len());
        Some(CachedResponse {
            status: self.status,
            headers,
            body: crate::cache_body::CachedBody::inline(body),
            body_encoding,
            uncompressed_len,
            cached_at: UNIX_EPOCH + Duration::from_secs(self.cached_at_secs),
            ttl: Duration::from_secs(self.ttl_secs),
            etag: self.etag.map(Arc::from),
            last_modified: self.last_modified.map(Arc::from),
            is_negative: self.is_negative,
            must_revalidate: self.must_revalidate,
        })
    }
}

pub fn encode_cached_response(value: &CachedResponse) -> Option<String> {
    let wire = CachedResponseWire::from_cached(value)?;
    serde_json::to_string(&wire).ok()
}

pub fn decode_cached_response(payload: &str) -> Option<CachedResponse> {
    let wire: CachedResponseWire = serde_json::from_str(payload).ok()?;
    wire.into_cached()
}

/// Redis-backed L2 cache. `ConnectionManager` is cheap to clone per operation.
#[derive(Clone)]
pub struct RedisL2Cache {
    conn: ConnectionManager,
    key_prefix: String,
    metrics: Arc<Metrics>,
}

impl RedisL2Cache {
    pub async fn connect(
        config: &L2CacheConfig,
        metrics: Arc<Metrics>,
    ) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(config.url.as_str())?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self {
            conn,
            key_prefix: config.key_prefix.clone(),
            metrics,
        })
    }

    fn redis_key(&self, cache_key: &str) -> String {
        format!("{}{}", self.key_prefix, cache_key)
    }

    fn remaining_ttl_secs(value: &CachedResponse) -> u64 {
        value
            .cached_at
            .checked_add(value.ttl)
            .and_then(|expires| expires.duration_since(SystemTime::now()).ok())
            .map(|d| d.as_secs().max(1))
            .unwrap_or(1)
    }

    pub async fn get(&self, cache_key: &str) -> Option<CachedResponse> {
        let key = self.redis_key(cache_key);
        let mut conn = self.conn.clone();
        let payload: Option<String> = match conn.get(&key).await {
            Ok(v) => v,
            Err(e) => {
                warn!("Redis L2 get failed for {}: {}", key, e);
                self.metrics.cache_l2_errors_total.inc();
                return None;
            }
        };

        let Some(payload) = payload else {
            self.metrics.cache_l2_misses_total.inc();
            return None;
        };

        let cached = match decode_cached_response(&payload) {
            Some(v) if v.can_serve_fresh() => v,
            Some(_) => {
                debug!("Redis L2 entry expired for {}", key);
                self.metrics.cache_l2_misses_total.inc();
                let _ = conn.del::<_, ()>(&key).await;
                return None;
            }
            None => {
                warn!("Redis L2 corrupt payload for {}", key);
                self.metrics.cache_l2_errors_total.inc();
                return None;
            }
        };

        self.metrics.cache_l2_hits_total.inc();
        Some(cached)
    }

    pub async fn set(&self, cache_key: &str, value: &CachedResponse) {
        let Some(payload) = encode_cached_response(value) else {
            self.metrics.cache_l2_errors_total.inc();
            return;
        };

        let key = self.redis_key(cache_key);
        let ttl = Self::remaining_ttl_secs(value);
        let mut conn = self.conn.clone();
        if let Err(e) = conn.set_ex::<_, _, ()>(&key, payload, ttl).await {
            warn!("Redis L2 set failed for {}: {}", key, e);
            self.metrics.cache_l2_errors_total.inc();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn wire_roundtrip() {
        let original = CachedResponse {
            status: 200,
            headers: Arc::from([(Arc::from("content-type"), Arc::from("text/plain"))]),
            body: crate::cache_body::CachedBody::inline(Bytes::from_static(b"hello")),
            body_encoding: BodyEncoding::Raw,
            uncompressed_len: 5,
            cached_at: SystemTime::now(),
            ttl: Duration::from_secs(3600),
            etag: Some(Arc::from("\"v1\"")),
            last_modified: Some(Arc::from("Mon, 01 Jan 2024 00:00:00 GMT")),
            is_negative: false,
            must_revalidate: false,
        };
        let json = encode_cached_response(&original).unwrap();
        let decoded = decode_cached_response(&json).unwrap();
        assert_eq!(decoded.status, 200);
        assert_eq!(decoded.stored_body_bytes(), original.stored_body_bytes());
        assert_eq!(decoded.headers.len(), 1);
    }

    #[test]
    fn wire_roundtrip_compressed() {
        use crate::cache_compress::CompressionConfig;

        let body = Bytes::from("z".repeat(2048));
        let headers: Arc<[(Arc<str>, Arc<str>)]> =
            Arc::from([(Arc::from("content-type"), Arc::from("text/plain"))]);
        let compression = CompressionConfig {
            codec: BodyEncoding::Zstd,
            min_bytes: 512,
            zstd_level: 3,
        };
        let original = crate::cache::CachedResponse::from_upstream(
            200,
            headers,
            body.clone(),
            Duration::from_secs(3600),
            &compression,
            usize::MAX,
            std::env::temp_dir().join("bsdm-test-spill").as_path(),
            None,
            None,
            false,
            false,
        );
        assert_eq!(original.body_encoding, BodyEncoding::Zstd);
        let json = encode_cached_response(&original).unwrap();
        let decoded = decode_cached_response(&json).unwrap();
        assert_eq!(decoded.body_encoding, BodyEncoding::Zstd);
        assert_eq!(decoded.uncompressed_len, body.len());
        assert_eq!(decoded.decoded_body().unwrap(), body);
    }

    #[test]
    fn l2_config_defaults_disabled() {
        std::env::remove_var("REDIS_L2_ENABLED");
        let cfg = L2CacheConfig::from_env();
        assert!(!cfg.enabled);
    }

    #[test]
    fn remaining_ttl_is_at_least_one() {
        let cached = CachedResponse {
            status: 200,
            headers: Arc::from([]),
            body: crate::cache_body::CachedBody::inline(Bytes::new()),
            body_encoding: BodyEncoding::Raw,
            uncompressed_len: 0,
            cached_at: SystemTime::now(),
            ttl: Duration::from_secs(60),
            etag: None,
            last_modified: None,
            is_negative: false,
            must_revalidate: false,
        };
        assert!(RedisL2Cache::remaining_ttl_secs(&cached) >= 1);
    }
}
