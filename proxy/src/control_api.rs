//! Control-plane REST helpers: Lite JSON stats, L1 cache purge, hierarchy peer reload (DX Phase 2).

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
use crate::hierarchy_config::reload_static_peers;
use crate::http_types::{full, Body};
use crate::l2_cache::RedisL2Cache;
use crate::metrics::Metrics;
use crate::peers::PeerRegistry;
use crate::sharded_cache::HttpL1Cache;
use crate::upstream::UpstreamClientHandle;

#[derive(Clone)]
pub struct ControlApiState {
    metrics: Arc<Metrics>,
    http_cache: Arc<HttpL1Cache>,
    l2_cache: Option<RedisL2Cache>,
    api_token: Option<String>,
    started_at: Instant,
    peer_registry: Option<PeerRegistry>,
    hierarchy_use_htcp: bool,
    upstream_client: UpstreamClientHandle,
    #[cfg(feature = "wasm")]
    wasm_hook: Option<Arc<std::sync::RwLock<crate::wasm_host::WasmHookEngine>>>,
}

impl ControlApiState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        metrics: Arc<Metrics>,
        http_cache: Arc<HttpL1Cache>,
        l2_cache: Option<RedisL2Cache>,
        api_token: Option<String>,
        peer_registry: Option<PeerRegistry>,
        hierarchy_use_htcp: bool,
        upstream_client: UpstreamClientHandle,
        #[cfg(feature = "wasm")] wasm_hook: Option<
            Arc<std::sync::RwLock<crate::wasm_host::WasmHookEngine>>,
        >,
    ) -> Self {
        Self {
            metrics,
            http_cache,
            l2_cache,
            api_token,
            started_at: Instant::now(),
            peer_registry,
            hierarchy_use_htcp,
            upstream_client,
            #[cfg(feature = "wasm")]
            wasm_hook,
        }
    }

    pub fn from_env(
        metrics: Arc<Metrics>,
        http_cache: Arc<HttpL1Cache>,
        l2_cache: Option<RedisL2Cache>,
        peer_registry: Option<PeerRegistry>,
        hierarchy_use_htcp: bool,
        upstream_client: UpstreamClientHandle,
        #[cfg(feature = "wasm")] wasm_hook: Option<
            Arc<std::sync::RwLock<crate::wasm_host::WasmHookEngine>>,
        >,
    ) -> Self {
        let api_token = std::env::var("CONTROL_API_TOKEN")
            .ok()
            .filter(|t| !t.is_empty())
            .or_else(|| {
                std::env::var("ACL_API_TOKEN")
                    .ok()
                    .filter(|t| !t.is_empty())
            });
        Self::new(
            metrics,
            http_cache,
            l2_cache,
            api_token,
            peer_registry,
            hierarchy_use_htcp,
            upstream_client,
            #[cfg(feature = "wasm")]
            wasm_hook,
        )
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
        // Public monitoring GETs; mutations require token when configured.
        let needs_auth = !matches!(
            (method, path),
            (&Method::GET, "/api/stats")
                | (&Method::GET, "/api/hierarchy/peers")
                | (&Method::GET, "/api/upstream/tls")
        );
        if needs_auth && !self.is_authorized(headers) {
            return json_response(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#);
        }

        match (method, path) {
            (&Method::GET, "/api/stats") => self.stats(),
            (&Method::POST, "/api/cache/purge") => self.purge(body).await,
            (&Method::GET, "/api/hierarchy/peers") => self.hierarchy_peers().await,
            (&Method::POST, "/api/hierarchy/reload") => self.hierarchy_reload().await,
            (&Method::GET, "/api/upstream/tls") => self.upstream_tls_status(),
            (&Method::POST, "/api/upstream/tls/reload") => self.upstream_tls_reload(),
            #[cfg(feature = "wasm")]
            (&Method::POST, "/api/wasm/reload") => self.wasm_reload(),
            _ => json_response(StatusCode::NOT_FOUND, r#"{"error":"not found"}"#),
        }
    }

    fn is_authorized(&self, headers: &HeaderMap) -> bool {
        let bearer = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        self.is_authorized_bearer(bearer)
    }

    /// Shared auth check for REST and gRPC (`authorization: Bearer …`).
    pub fn is_authorized_bearer(&self, bearer: Option<&str>) -> bool {
        let Some(expected) = &self.api_token else {
            return true;
        };
        bearer.is_some_and(|token| {
            crate::security_util::constant_time_eq(token.as_bytes(), expected.as_bytes())
        })
    }

    /// Whether mutating control RPCs require a Bearer token.
    pub fn auth_required(&self) -> bool {
        self.api_token.is_some()
    }

    pub fn stats_payload(&self) -> StatsResponse {
        let hits = self.metrics.cache_hits_total.get();
        let misses = self.metrics.cache_misses_total.get();
        let bypasses = self.metrics.cache_bypasses_total.get();
        StatsResponse {
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
                tags: self.http_cache.tag_count(),
            },
        }
    }

    fn stats(&self) -> Response<Body> {
        match serde_json::to_string(&self.stats_payload()) {
            Ok(body) => json_response(StatusCode::OK, &body),
            Err(_) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"serialization failed"}"#,
            ),
        }
    }

    pub async fn hierarchy_peers_payload(&self) -> PeersListResponse {
        let Some(registry) = &self.peer_registry else {
            return PeersListResponse {
                enabled: false,
                peers: Vec::new(),
            };
        };
        let peers = registry.all_peers().await;
        let mut items = Vec::with_capacity(peers.len());
        for peer in peers {
            let is_static = registry.is_static(&peer.id).await;
            items.push(PeerListItem {
                id: peer.id.clone(),
                host: peer.config.host.clone(),
                port: peer.config.port,
                peer_type: peer.config.peer_type.to_string(),
                weight: peer.config.weight,
                icp_port: peer.config.icp_port,
                healthy: peer.is_healthy(),
                is_static,
            });
        }
        items.sort_by(|a, b| a.id.cmp(&b.id));
        PeersListResponse {
            enabled: true,
            peers: items,
        }
    }

    async fn hierarchy_peers(&self) -> Response<Body> {
        let payload = self.hierarchy_peers_payload().await;
        if !payload.enabled {
            return json_response(
                StatusCode::OK,
                r#"{"enabled":false,"peers":[],"source_hint":"set HIERARCHY_ENABLED=true"}"#,
            );
        }
        match serde_json::to_string(&payload) {
            Ok(body) => json_response(StatusCode::OK, &body),
            Err(_) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"serialization failed"}"#,
            ),
        }
    }

    pub async fn hierarchy_reload_payload(&self) -> Result<HierarchyReloadPayload, String> {
        let Some(registry) = &self.peer_registry else {
            return Err("hierarchy disabled (HIERARCHY_ENABLED=false)".into());
        };
        let report = reload_static_peers(registry, self.hierarchy_use_htcp).await?;
        Ok(HierarchyReloadPayload {
            status: "reloaded",
            source: report.source.as_str().to_string(),
            added: report.stats.added as u64,
            removed: report.stats.removed as u64,
            preserved_discovery: report.stats.preserved_discovery as u64,
        })
    }

    async fn hierarchy_reload(&self) -> Response<Body> {
        match self.hierarchy_reload_payload().await {
            Ok(report) => {
                let body = format!(
                    r#"{{"status":"{}","source":"{}","added":{},"removed":{},"preserved_discovery":{}}}"#,
                    report.status,
                    report.source,
                    report.added,
                    report.removed,
                    report.preserved_discovery
                );
                json_response(StatusCode::OK, &body)
            }
            Err(e) if e.contains("hierarchy disabled") => json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"hierarchy disabled (HIERARCHY_ENABLED=false)"}"#,
            ),
            Err(e) => json_response(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"{}"}}"#, escape_json(&e)),
            ),
        }
    }

    pub fn upstream_tls_snapshot(&self) -> crate::upstream::UpstreamTlsSnapshot {
        (*self.upstream_client.snapshot()).clone()
    }

    fn upstream_tls_status(&self) -> Response<Body> {
        match serde_json::to_string(&self.upstream_tls_snapshot()) {
            Ok(body) => json_response(StatusCode::OK, &body),
            Err(_) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"serialization failed"}"#,
            ),
        }
    }

    pub fn upstream_tls_reload_payload(
        &self,
    ) -> Result<crate::upstream::UpstreamTlsSnapshot, String> {
        self.upstream_client.reload_from_env()
    }

    fn upstream_tls_reload(&self) -> Response<Body> {
        match self.upstream_tls_reload_payload() {
            Ok(snap) => match serde_json::to_string(&UpstreamTlsReloadResponse {
                status: "reloaded",
                tls: snap,
            }) {
                Ok(body) => json_response(StatusCode::OK, &body),
                Err(_) => json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    r#"{"error":"serialization failed"}"#,
                ),
            },
            Err(e) => json_response(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"{}"}}"#, escape_json(&e)),
            ),
        }
    }

    pub async fn purge_payload(&self, req: PurgeRequest) -> Result<PurgeResult, String> {
        if req.all {
            let removed = self.http_cache.clear();
            if let Some(l2) = &self.l2_cache {
                l2.flush_prefix().await;
            }
            info!("Control API: purged entire L1 cache ({removed} entries)");
            return Ok(PurgeResult {
                status: "purged".into(),
                scope: "all".into(),
                removed,
                url: None,
                tags: Vec::new(),
            });
        }

        let tags = collect_purge_tags(&req);
        if !tags.is_empty() {
            let mut removed = 0usize;
            for tag in &tags {
                let keys = self.http_cache.keys_for_tag(tag);
                for key in &keys {
                    if self.http_cache.remove(key).is_some() {
                        removed += 1;
                    }
                    if let Some(l2) = &self.l2_cache {
                        l2.delete(key.as_ref()).await;
                    }
                }
            }
            info!("Control API: purged tags={tags:?} removed={removed}");
            return Ok(PurgeResult {
                status: "purged".into(),
                scope: "tag".into(),
                removed,
                url: None,
                tags,
            });
        }

        let Some(url) = req.url.as_deref().filter(|u| !u.is_empty()) else {
            return Err(
                "provide {\"url\":\"...\"}, {\"tag\":\"...\"}, {\"tags\":[...]}, or {\"all\":true}"
                    .into(),
            );
        };

        let method = req.method.as_deref().unwrap_or("GET");
        let key = http_cache_key(method, url);
        let removed_l1 = self.http_cache.remove(&key).is_some();
        if let Some(l2) = &self.l2_cache {
            l2.delete(key.as_ref()).await;
        }
        info!("Control API: purge url={url} method={method} l1={removed_l1}");
        Ok(PurgeResult {
            status: "purged".into(),
            scope: "url".into(),
            removed: if removed_l1 { 1 } else { 0 },
            url: Some(url.to_string()),
            tags: Vec::new(),
        })
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

        match self.purge_payload(req).await {
            Ok(r) if r.scope == "all" => json_response(
                StatusCode::OK,
                &format!(
                    r#"{{"status":"purged","scope":"all","removed":{}}}"#,
                    r.removed
                ),
            ),
            Ok(r) if r.scope == "tag" => json_response(
                StatusCode::OK,
                &format!(
                    r#"{{"status":"purged","scope":"tag","tags":[{}],"removed":{}}}"#,
                    r.tags
                        .iter()
                        .map(|t| format!("\"{}\"", escape_json(t)))
                        .collect::<Vec<_>>()
                        .join(","),
                    r.removed
                ),
            ),
            Ok(r) => json_response(
                StatusCode::OK,
                &format!(
                    r#"{{"status":"purged","scope":"url","url":"{}","removed":{}}}"#,
                    escape_json(r.url.as_deref().unwrap_or("")),
                    r.removed
                ),
            ),
            Err(e) => json_response(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"{}"}}"#, escape_json(&e)),
            ),
        }
    }

    #[cfg(feature = "wasm")]
    fn wasm_reload(&self) -> Response<Body> {
        let Some(hook_arc) = &self.wasm_hook else {
            return json_response(
                StatusCode::BAD_REQUEST,
                r#"{"error":"WASM hook is not enabled"}"#,
            );
        };
        let mut hook = hook_arc.write().unwrap();
        match hook.reload() {
            Ok(_) => json_response(StatusCode::OK, r#"{"status":"reloaded"}"#),
            Err(e) => {
                warn!("WASM hook reload failed: {e}");
                let error_json = serde_json::json!({
                    "error": "reload failed",
                    "details": e
                });
                json_response(StatusCode::INTERNAL_SERVER_ERROR, &error_json.to_string())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsResponse {
    pub service: &'static str,
    pub uptime_secs: u64,
    pub requests_in_flight: u64,
    pub cache: CacheStats,
}

#[derive(Debug, Clone, Serialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub bypasses: u64,
    pub hit_ratio: f64,
    pub entries: usize,
    pub capacity: usize,
    pub shards: usize,
    pub tags: usize,
}

#[derive(Debug, Serialize)]
struct UpstreamTlsReloadResponse {
    status: &'static str,
    tls: crate::upstream::UpstreamTlsSnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeersListResponse {
    pub enabled: bool,
    pub peers: Vec<PeerListItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerListItem {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub peer_type: String,
    pub weight: f64,
    pub icp_port: Option<u16>,
    pub healthy: bool,
    pub is_static: bool,
}

#[derive(Debug, Clone)]
pub struct HierarchyReloadPayload {
    pub status: &'static str,
    pub source: String,
    pub added: u64,
    pub removed: u64,
    pub preserved_discovery: u64,
}

#[derive(Debug, Clone)]
pub struct PurgeResult {
    pub status: String,
    pub scope: String,
    pub removed: usize,
    pub url: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct PurgeRequest {
    #[serde(default)]
    pub all: bool,
    pub url: Option<String>,
    pub method: Option<String>,
    pub tag: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn collect_purge_tags(req: &PurgeRequest) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(t) = req.tag.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        out.push(t.to_string());
    }
    for t in &req.tags {
        let t = t.trim();
        if !t.is_empty() && !out.iter().any(|x| x == t) {
            out.push(t.to_string());
        }
    }
    out
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
    use crate::peers::{PeerConfig, PeerType};
    use crate::upstream::UpstreamTlsConfig;

    fn test_upstream() -> UpstreamClientHandle {
        let _ = rustls::crypto::ring::default_provider().install_default();
        UpstreamClientHandle::new(UpstreamTlsConfig::default()).unwrap()
    }

    fn state_plain(metrics: Arc<Metrics>, cache: Arc<HttpL1Cache>) -> ControlApiState {
        ControlApiState::new(
            metrics,
            cache,
            None,
            None,
            None,
            false,
            test_upstream(),
            #[cfg(feature = "wasm")]
            None,
        )
    }

    #[tokio::test]
    async fn stats_returns_json() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let state = state_plain(metrics, cache);
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

        let state = state_plain(metrics, cache.clone());
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

    #[tokio::test]
    async fn purge_by_tag() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let key = http_cache_key("GET", "http://example.com/product");
        cache.insert(
            key.clone(),
            crate::cache::CachedResponse {
                status: 200,
                headers: Arc::from([(Arc::from("cache-tag"), Arc::from("product-42"))]),
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
        let state = state_plain(metrics, cache.clone());
        let resp = state
            .dispatch(
                &Method::POST,
                "/api/cache/purge",
                Bytes::from_static(br#"{"tag":"product-42"}"#),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(cache.len(), 0);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["scope"], "tag");
        assert_eq!(v["removed"], 1);
    }

    #[tokio::test]
    async fn hierarchy_peers_when_disabled() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let state = state_plain(metrics, cache);
        let resp = state
            .dispatch(
                &Method::GET,
                "/api/hierarchy/peers",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["enabled"], false);
    }

    #[tokio::test]
    async fn hierarchy_peers_lists_registry() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let registry = PeerRegistry::new();
        registry
            .add_peer(PeerConfig {
                host: "10.0.0.1".into(),
                port: 1488,
                peer_type: PeerType::Parent,
                weight: 1.0,
                icp_port: None,
                max_connections: 100,
            })
            .await;
        let state = ControlApiState::new(
            metrics,
            cache,
            None,
            None,
            Some(registry),
            false,
            test_upstream(),
            #[cfg(feature = "wasm")]
            None,
        );
        let resp = state
            .dispatch(
                &Method::GET,
                "/api/hierarchy/peers",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["enabled"], true);
        assert_eq!(v["peers"].as_array().unwrap().len(), 1);
        assert_eq!(v["peers"][0]["is_static"], true);
    }

    #[tokio::test]
    async fn upstream_tls_status_and_reload() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let state = state_plain(metrics, cache);
        let resp = state
            .dispatch(
                &Method::GET,
                "/api/upstream/tls",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["custom_ca"], false);

        let resp = state
            .dispatch(
                &Method::POST,
                "/api/upstream/tls/reload",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["status"], "reloaded");
        assert!(v["tls"]["reloaded_at_unix"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn hierarchy_reload_unavailable_when_disabled() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let state = state_plain(metrics, cache);
        let resp = state
            .dispatch(
                &Method::POST,
                "/api/hierarchy/reload",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
