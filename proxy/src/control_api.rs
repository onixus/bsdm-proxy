//! Control-plane REST helpers: Lite JSON stats + L1 cache purge (DX Phase 2).

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::AUTHORIZATION;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};

use crate::cache_key::http_cache_key;
use crate::http_types::{full, Body};
use crate::l2_cache::RedisL2Cache;
use crate::metrics::Metrics;
use crate::sharded_cache::HttpL1Cache;

#[derive(Clone)]
pub struct ControlApiState {
    metrics: Arc<Metrics>,
    http_cache: Arc<HttpL1Cache>,
    l2_cache: Option<RedisL2Cache>,
    api_token: Option<String>,
    started_at: Instant,
}

impl ControlApiState {
    pub fn new(
        metrics: Arc<Metrics>,
        http_cache: Arc<HttpL1Cache>,
        l2_cache: Option<RedisL2Cache>,
        api_token: Option<String>,
    ) -> Self {
        Self {
            metrics,
            http_cache,
            l2_cache,
            api_token,
            started_at: Instant::now(),
        }
    }

    pub fn from_env(
        metrics: Arc<Metrics>,
        http_cache: Arc<HttpL1Cache>,
        l2_cache: Option<RedisL2Cache>,
    ) -> Self {
        let api_token = std::env::var("CONTROL_API_TOKEN")
            .ok()
            .filter(|t| !t.is_empty())
            .or_else(|| {
                std::env::var("ACL_API_TOKEN")
                    .ok()
                    .filter(|t| !t.is_empty())
            });
        Self::new(metrics, http_cache, l2_cache, api_token)
    }

    pub async fn handle_request(&self, req: Request<Incoming>) -> Response<Body> {
        let (parts, body) = req.into_parts();
        let body = match BodyExt::collect(body).await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                warn!("Failed to read control API body: {e}");
                Bytes::new()
            }
        };
        self.dispatch(&parts.method, parts.uri.path(), body, &parts.headers)
            .await
    }

    async fn dispatch(
        &self,
        method: &Method,
        path: &str,
        body: Bytes,
        headers: &HeaderMap,
    ) -> Response<Body> {
        // Stats are public (Lite monitoring); mutations require token when configured.
        let needs_auth = path != "/api/stats";
        if needs_auth && !self.is_authorized(headers) {
            return json_response(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#);
        }

        match (method, path) {
            (&Method::GET, "/api/stats") => self.stats(),
            (&Method::POST, "/api/cache/purge") => self.purge(body).await,
            _ => json_response(StatusCode::NOT_FOUND, r#"{"error":"not found"}"#),
        }
    }

    fn is_authorized(&self, headers: &HeaderMap) -> bool {
        let Some(expected) = &self.api_token else {
            return true;
        };
        headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|token| token == expected)
    }

    fn stats(&self) -> Response<Body> {
        let hits = self.metrics.cache_hits_total.get();
        let misses = self.metrics.cache_misses_total.get();
        let bypasses = self.metrics.cache_bypasses_total.get();
        let payload = StatsResponse {
            service: "bsdm-proxy",
            uptime_secs: self.started_at.elapsed().as_secs(),
            requests_in_flight: self.metrics.requests_in_flight.get() as u64,
            cache: CacheStats {
                hits: hits as u64,
                misses: misses as u64,
                bypasses: bypasses as u64,
                hit_ratio: self.metrics.cache_hit_rate(),
                entries: self.http_cache.len(),
                capacity: self.http_cache.capacity(),
                shards: self.http_cache.shard_count(),
            },
        };
        match serde_json::to_string(&payload) {
            Ok(body) => json_response(StatusCode::OK, &body),
            Err(_) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"serialization failed"}"#,
            ),
        }
    }

    async fn purge(&self, body: Bytes) -> Response<Body> {
        let req: PurgeRequest = if body.is_empty() {
            PurgeRequest::default()
        } else {
            match serde_json::from_slice(&body) {
                Ok(r) => r,
                Err(e) => {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        &format!(
                            r#"{{"error":"invalid json: {}}}"#,
                            escape_json(&e.to_string())
                        ),
                    );
                }
            }
        };

        if req.all {
            let removed = self.http_cache.clear();
            if let Some(l2) = &self.l2_cache {
                l2.flush_prefix().await;
            }
            info!("Control API: purged entire L1 cache ({removed} entries)");
            return json_response(
                StatusCode::OK,
                &format!(r#"{{"status":"purged","scope":"all","removed":{removed}}}"#),
            );
        }

        let Some(url) = req.url.as_deref().filter(|u| !u.is_empty()) else {
            return json_response(
                StatusCode::BAD_REQUEST,
                r#"{"error":"provide {\"url\":\"...\"} or {\"all\":true}"}"#,
            );
        };

        let method = req.method.as_deref().unwrap_or("GET");
        let key = http_cache_key(method, url);
        let removed_l1 = self.http_cache.remove(&key).is_some();
        if let Some(l2) = &self.l2_cache {
            l2.delete(key.as_ref()).await;
        }
        info!("Control API: purge url={url} method={method} l1={removed_l1}");
        json_response(
            StatusCode::OK,
            &format!(
                r#"{{"status":"purged","scope":"url","url":"{}","removed":{}}}"#,
                escape_json(url),
                if removed_l1 { 1 } else { 0 }
            ),
        )
    }
}

#[derive(Debug, Serialize)]
struct StatsResponse {
    service: &'static str,
    uptime_secs: u64,
    requests_in_flight: u64,
    cache: CacheStats,
}

#[derive(Debug, Serialize)]
struct CacheStats {
    hits: u64,
    misses: u64,
    bypasses: u64,
    hit_ratio: f64,
    entries: usize,
    capacity: usize,
    shards: usize,
}

#[derive(Debug, Default, Deserialize)]
struct PurgeRequest {
    #[serde(default)]
    all: bool,
    url: Option<String>,
    method: Option<String>,
}

fn json_response(status: StatusCode, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json; charset=utf-8")
        .body(full(Bytes::from(body.to_string())))
        .unwrap_or_else(|_| Response::new(full(Bytes::from_static(b"500 Internal Server Error"))))
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::Metrics;

    #[tokio::test]
    async fn stats_returns_json() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let state = ControlApiState::new(metrics, cache, None, None);
        let resp = state
            .dispatch(&Method::GET, "/api/stats", Bytes::new(), &HeaderMap::new())
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["service"], "bsdm-proxy");
        assert!(v["cache"]["capacity"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn purge_all_clears_cache() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let key = http_cache_key("GET", "http://example.com/");
        cache.insert(
            key.clone(),
            crate::cache::CachedResponse {
                status: 200,
                headers: Arc::from([]),
                body: crate::cache_body::CachedBody::inline(Bytes::from_static(b"x")),
                body_encoding: crate::cache_compress::BodyEncoding::Raw,
                uncompressed_len: 1,
                cached_at: std::time::SystemTime::now(),
                ttl: std::time::Duration::from_secs(60),
                etag: None,
                last_modified: None,
                is_negative: false,
                must_revalidate: false,
            },
        );
        assert_eq!(cache.len(), 1);

        let state = ControlApiState::new(metrics, cache.clone(), None, None);
        let resp = state
            .dispatch(
                &Method::POST,
                "/api/cache/purge",
                Bytes::from_static(br#"{"all":true}"#),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(cache.len(), 0);
    }
}
