//! Core HTTP proxy service: caching, policy, upstream fetch, and Kafka events.

use base64::engine::general_purpose;
use base64::Engine;
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::header::{
    HeaderName, HeaderValue, AUTHORIZATION, IF_MODIFIED_SINCE, IF_NONE_MATCH, LOCATION,
};
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rdkafka::producer::FutureProducer;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::acl::{AclAction, AclDecision, AclEngine};
use crate::auth::{AuthManager, ProxyAuthOutcome, UserInfo};
use crate::cache::{CacheConfig, CachedResponse, CACHEABLE_METHODS};
use crate::cache_digest::DigestRegistry;
use crate::cache_freshness::{evaluate_store, refresh_ttl_from_headers};
use crate::cache_key::http_cache_key;
use crate::categorization::CategorizationEngine;
use crate::hierarchy::{HierarchyManager, HierarchyResult};
use crate::http_types::Body;
use crate::l2_cache::RedisL2Cache;
use crate::metrics::{FastRequestScope, Metrics, RequestMetricsGuard};
use crate::peer_fetch::fetch_via_peer;
use crate::peers::CachePeer;
use crate::perf::PerfConfig;
use crate::pipeline::{
    create_kafka_producer, flush_kafka, new_event_id, send_to_kafka_async, CacheEvent,
};
use crate::rate_limit::{RateLimitViolation, RateLimiter};
use crate::sharded_cache::HttpL1Cache;
use crate::tls::CertCache;
use crate::upstream::{build_upstream_https_connector, UpstreamTlsConfig};

pub struct ProxyPolicy {
    pub acl_engine: Option<Arc<RwLock<AclEngine>>>,
    pub categorization: Option<Arc<CategorizationEngine>>,
}

pub struct ProxyService {
    pub(crate) cert_cache: CertCache,
    http_cache: Arc<HttpL1Cache>,
    l2_cache: Option<RedisL2Cache>,
    cache_config: CacheConfig,
    kafka_producer: Option<Arc<FutureProducer>>,
    kafka_topic: String,
    http_client:
        hyper_util::client::legacy::Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>,
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) mitm_enabled: bool,
    auth: Option<Arc<AuthManager>>,
    acl_engine: Option<Arc<RwLock<AclEngine>>>,
    categorization: Option<Arc<CategorizationEngine>>,
    hierarchy: Option<Arc<HierarchyManager>>,
    digest_registry: Option<Arc<DigestRegistry>>,
    rate_limiter: Arc<RateLimiter>,
    perf: PerfConfig,
}

impl ProxyService {
    pub fn http_cache(&self) -> Arc<HttpL1Cache> {
        self.http_cache.clone()
    }

    pub fn auth(&self) -> Option<Arc<AuthManager>> {
        self.auth.clone()
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        self.metrics.clone()
    }

    pub fn http_preserve_header_case(&self) -> bool {
        self.perf.http_preserve_header_case
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cert_cache: CertCache,
        cache_config: CacheConfig,
        l2_cache: Option<RedisL2Cache>,
        kafka_brokers: Option<String>,
        kafka_topic: String,
        metrics: Arc<Metrics>,
        mitm_enabled: bool,
        auth: Option<Arc<AuthManager>>,
        policy: &ProxyPolicy,
        hierarchy: Option<Arc<HierarchyManager>>,
        digest_registry: Option<Arc<DigestRegistry>>,
        rate_limit_config: crate::rate_limit::RateLimitConfig,
        upstream_tls: UpstreamTlsConfig,
        perf: PerfConfig,
    ) -> Self {
        let kafka_producer = kafka_brokers.as_deref().and_then(create_kafka_producer);

        let http_cache = Arc::new(HttpL1Cache::new(
            cache_config.capacity,
            cache_config.shard_count,
        ));

        let https = build_upstream_https_connector(&upstream_tls)
            .expect("failed to build upstream HTTPS connector");

        let http_client = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(32)
            .build(https);

        Self {
            cert_cache,
            http_cache,
            l2_cache,
            cache_config,
            kafka_producer,
            kafka_topic,
            http_client,
            metrics,
            mitm_enabled,
            auth,
            acl_engine: policy.acl_engine.clone(),
            categorization: policy.categorization.clone(),
            hierarchy,
            digest_registry,
            rate_limiter: Arc::new(RateLimiter::new(rate_limit_config)),
            perf,
        }
    }

    fn parse_client_ip(client_ip: &str) -> Option<IpAddr> {
        client_ip.parse().ok()
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_cache_hit_event(
        &self,
        url: &str,
        method: &str,
        cache_key: &Arc<str>,
        cache_status: &'static str,
        cached: &CachedResponse,
        user_id: &Option<String>,
        username: &Option<String>,
        client_ip: &str,
        categories: &[String],
        threat_sources: &[String],
        request_start: Instant,
    ) {
        if let Ok(timestamp) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            let event = CacheEvent {
                url: url.to_string(),
                method: method.to_string(),
                status: cached.status,
                cache_key: cache_key.to_string(),
                cache_status: cache_status.to_string(),
                timestamp: timestamp.as_secs(),
                headers: HashMap::new(),
                user_id: user_id.clone(),
                username: username.clone(),
                client_ip: client_ip.to_string(),
                domain: Self::extract_domain(url),
                response_size: cached.response_body_len() as u64,
                request_duration_ms: request_start.elapsed().as_millis() as u64,
                content_type: cached
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                    .map(|(_, v)| v.to_string()),
                user_agent: None,
                categories: categories.to_vec(),
                threat_sources: threat_sources.to_vec(),
                acl_action: None,
                event_id: new_event_id(),
            };
            self.send_cache_event(event);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_policy_event(
        &self,
        url: &str,
        method: &str,
        cache_key: &str,
        decision: &AclDecision,
        user_id: &Option<String>,
        username: &Option<String>,
        client_ip: &str,
        domain: &str,
        categories: &[String],
        threat_sources: &[String],
        request_start: Instant,
    ) {
        if let Ok(timestamp) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            let status = match decision.action {
                AclAction::Deny => 403,
                AclAction::Redirect => 302,
                AclAction::Allow => 200,
            };
            let event = CacheEvent {
                url: url.to_string(),
                method: method.to_string(),
                status,
                cache_key: cache_key.to_string(),
                cache_status: "BLOCKED".to_string(),
                timestamp: timestamp.as_secs(),
                headers: HashMap::new(),
                user_id: user_id.clone(),
                username: username.clone(),
                client_ip: client_ip.to_string(),
                domain: domain.to_string(),
                response_size: 0,
                request_duration_ms: request_start.elapsed().as_millis() as u64,
                content_type: None,
                user_agent: None,
                categories: categories.to_vec(),
                threat_sources: threat_sources.to_vec(),
                acl_action: Some(decision.action.to_string()),
                event_id: new_event_id(),
            };
            self.send_cache_event(event);
        }
    }

    async fn try_l2_cache_get(&self, cache_key: &Arc<str>) -> Option<CachedResponse> {
        let l2 = self.l2_cache.as_ref()?;
        l2.get(cache_key.as_ref()).await
    }

    fn store_in_l1_and_l2(&self, cache_key: Arc<str>, cached_response: CachedResponse) {
        self.http_cache
            .insert(cache_key.clone(), cached_response.clone());
        if let Some(registry) = &self.digest_registry {
            let key = cache_key.to_string();
            let reg = registry.clone();
            tokio::spawn(async move {
                reg.insert_cache_key(&key).await;
            });
        }
        if let Some(l2) = &self.l2_cache {
            let l2 = l2.clone();
            tokio::spawn(async move {
                l2.set(cache_key.as_ref(), &cached_response).await;
            });
        }
    }

    async fn categorize_url(&self, url: &str) -> (Vec<String>, Vec<String>) {
        let Some(engine) = &self.categorization else {
            return (Vec::new(), Vec::new());
        };
        let result = engine.categorize(url).await;
        let categories: Vec<String> = result
            .categories
            .iter()
            .map(crate::categorization::Category::acl_name)
            .filter(|name| !name.is_empty())
            .collect();
        let threat_sources = if result.source != "unknown" && !categories.is_empty() {
            vec![result.source]
        } else {
            Vec::new()
        };
        (categories, threat_sources)
    }

    async fn check_acl(
        &self,
        url: &str,
        domain: &str,
        category_names: &[String],
        username: Option<&str>,
        groups: &[&str],
        client_ip: &str,
    ) -> Option<AclDecision> {
        let Some(acl_engine) = &self.acl_engine else {
            return None;
        };

        let eval_start = Instant::now();
        let category_refs: Vec<&str> = category_names.iter().map(String::as_str).collect();
        let decision = {
            let engine = acl_engine.read().await;
            engine.check_access(
                url,
                domain,
                &category_refs,
                username,
                groups,
                Self::parse_client_ip(client_ip),
            )
        };

        self.metrics
            .acl_eval_duration_seconds
            .observe(eval_start.elapsed().as_secs_f64());
        let action_label = decision.action.to_string();
        self.metrics
            .acl_decisions_total
            .with_label_values(&[&action_label])
            .inc();
        if let Some(rule_id) = &decision.rule_id {
            self.metrics
                .acl_rules_matched_total
                .with_label_values(&[rule_id])
                .inc();
        }

        if decision.action == AclAction::Allow {
            None
        } else {
            info!("ACL {} for {}: {}", decision.action, url, decision.reason);
            Some(decision)
        }
    }

    pub(crate) async fn check_policy(
        &self,
        url: &str,
        domain: &str,
        username: Option<&str>,
        groups: &[&str],
        client_ip: &str,
    ) -> (Option<AclDecision>, Vec<String>, Vec<String>) {
        let (category_names, threat_sources) = self.categorize_url(url).await;
        let decision = self
            .check_acl(url, domain, &category_names, username, groups, client_ip)
            .await;
        (decision, category_names, threat_sources)
    }

    #[allow(clippy::too_many_arguments)]
    fn serve_l1_hit(
        &self,
        cached: &CachedResponse,
        cache_key: &Arc<str>,
        url: &str,
        method: &str,
        user_id: &Option<String>,
        username: &Option<String>,
        client_ip: &str,
        categories: &[String],
        threat_sources: &[String],
        request_start: Instant,
        detailed_metrics: bool,
        guard: &mut Option<RequestMetricsGuard>,
        fast_scope: &mut Option<FastRequestScope>,
        cache_status_label: &'static str,
        x_cache_status: &str,
    ) -> Response<Body> {
        if detailed_metrics {
            if let Some(g) = guard.as_mut() {
                g.set_cache_status(cache_status_label);
            }
            self.metrics.cache_hits_total.inc();
            self.emit_cache_hit_event(
                url,
                method,
                cache_key,
                cache_status_label,
                cached,
                user_id,
                username,
                client_ip,
                categories,
                threat_sources,
                request_start,
            );
        } else if let Some(scope) = fast_scope.take() {
            scope.finish_cache_hit();
        }

        let response = cached.to_response_with_cache_status(x_cache_status);
        let body_size = cached.response_body_len();
        if let Some(g) = guard.take() {
            g.finish(cached.status, 0, body_size);
        }
        response
    }

    fn build_conditional_request(
        req: &Request<Incoming>,
        cached: &CachedResponse,
    ) -> Option<Request<Body>> {
        let mut builder = Request::builder()
            .method(req.method())
            .uri(req.uri().clone());
        for (name, value) in req.headers() {
            builder = builder.header(name, value);
        }
        if let Some(etag) = &cached.etag {
            builder = builder.header(IF_NONE_MATCH, etag.as_ref());
        }
        if let Some(lm) = &cached.last_modified {
            builder = builder.header(IF_MODIFIED_SINCE, lm.as_ref());
        }
        builder.body(Body::new(Bytes::new())).ok()
    }

    #[allow(clippy::too_many_arguments)]
    async fn try_revalidate_stale(
        &self,
        cached: &CachedResponse,
        req: &Request<Incoming>,
        cache_key: &Arc<str>,
        url: &str,
        method: &str,
        user_id: &Option<String>,
        username: &Option<String>,
        client_ip: &str,
        categories: &[String],
        threat_sources: &[String],
        request_start: Instant,
        detailed_metrics: bool,
        guard: &mut Option<RequestMetricsGuard>,
        fast_scope: &mut Option<FastRequestScope>,
    ) -> Option<Response<Body>> {
        if !self.cache_config.honor_cache_control || !cached.has_validators() {
            return None;
        }

        let cond_req = Self::build_conditional_request(req, cached)?;
        let domain = Self::extract_domain(url);
        let upstream_start = Instant::now();

        let response = match self.http_client.request(cond_req).await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("Revalidation upstream error for {}: {}", url, e);
                self.metrics
                    .upstream_errors_total
                    .with_label_values(&[&domain, "revalidate"])
                    .inc();
                return None;
            }
        };

        let upstream_duration = upstream_start.elapsed().as_secs_f64();
        let status = response.status();
        self.metrics
            .upstream_requests_total
            .with_label_values(&[&domain, &status.as_u16().to_string()])
            .inc();
        self.metrics
            .upstream_duration_seconds
            .with_label_values(&[&domain])
            .observe(upstream_duration);

        if status == StatusCode::NOT_MODIFIED {
            let headers_map: HashMap<String, String> = response
                .headers()
                .iter()
                .filter_map(|(k, v)| {
                    v.to_str()
                        .ok()
                        .map(|v| (k.as_str().to_string(), v.to_string()))
                })
                .collect();
            let ttl = refresh_ttl_from_headers(&headers_map, self.cache_config.default_ttl);
            let refreshed = cached.refreshed_after_not_modified(ttl);
            self.store_in_l1_and_l2(cache_key.clone(), refreshed.clone());
            debug!("Cache REVALIDATED (304): {} {}", method, url);
            return Some(self.serve_l1_hit(
                &refreshed,
                cache_key,
                url,
                method,
                user_id,
                username,
                client_ip,
                categories,
                threat_sources,
                request_start,
                detailed_metrics,
                guard,
                fast_scope,
                "REVALIDATED",
                "REVALIDATED",
            ));
        }

        // Changed response: consume body and fall through to normal miss handling upstream.
        let _ = http_body_util::BodyExt::collect(response.into_body()).await;
        None
    }

    pub(crate) fn policy_response(decision: &AclDecision) -> Response<Body> {
        match decision.action {
            AclAction::Deny => {
                let body = format!("403 Forbidden: {}", decision.reason);
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("Content-Type", "text/plain; charset=utf-8")
                    .body(Body::new(Bytes::from(body)))
                    .unwrap_or_else(|_| {
                        Response::new(Body::new(Bytes::from_static(b"403 Forbidden")))
                    })
            }
            AclAction::Redirect => {
                let target = decision
                    .redirect_url
                    .as_deref()
                    .filter(|url| !url.is_empty())
                    .unwrap_or("about:blank");
                Response::builder()
                    .status(StatusCode::FOUND)
                    .header(LOCATION, target)
                    .body(Body::new(Bytes::new()))
                    .unwrap_or_else(|_| Response::new(Body::new(Bytes::new())))
            }
            AclAction::Allow => Response::new(Body::new(Bytes::new())),
        }
    }

    pub(crate) async fn authenticate_proxy(
        &self,
        req: &Request<Incoming>,
        client_ip: &str,
    ) -> Result<Option<Arc<UserInfo>>, Response<Body>> {
        let Some(auth) = &self.auth else {
            return Ok(None);
        };
        if !auth.is_enabled() {
            return Ok(None);
        }

        match auth.handle_proxy_auth(client_ip, req).await {
            ProxyAuthOutcome::Anonymous => Ok(None),
            ProxyAuthOutcome::Authenticated(user) => Ok(Some(Arc::new(user))),
            ProxyAuthOutcome::Challenge {
                authenticate_header,
            } => {
                tracing::debug!("Proxy authentication challenge issued");
                Err(auth.create_auth_challenge_response(authenticate_header))
            }
        }
    }

    pub(crate) fn user_fields(user: Option<&UserInfo>) -> (Option<String>, Option<String>) {
        user.map(|u| {
            let name = u.username.clone();
            (Some(name.clone()), Some(name))
        })
        .unwrap_or((None, None))
    }

    pub(crate) fn check_rate_limit(
        &self,
        client_ip: &str,
        username: Option<&str>,
    ) -> Option<Response<Body>> {
        let violation = self.rate_limiter.check(client_ip, username)?;
        let limit_type = match violation {
            RateLimitViolation::Ip => "ip",
            RateLimitViolation::User => "user",
        };
        self.metrics
            .rate_limit_rejected_total
            .with_label_values(&[limit_type])
            .inc();
        warn!(
            "Rate limit exceeded ({}) for client_ip={} user={}",
            limit_type,
            client_ip,
            username.unwrap_or("-")
        );
        Some(Self::rate_limit_response())
    }

    fn rate_limit_response() -> Response<Body> {
        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("Content-Type", "text/plain; charset=utf-8")
            .header("Retry-After", "1")
            .body(Body::new(Bytes::from_static(
                b"429 Too Many Requests: rate limit exceeded",
            )))
            .unwrap_or_else(|_| {
                Response::new(Body::new(Bytes::from_static(b"429 Too Many Requests")))
            })
    }

    #[inline]
    pub(crate) fn generate_cache_key(&self, method: &str, url: &str) -> Arc<str> {
        http_cache_key(method, url)
    }

    /// Try fetching via hierarchy peer (sibling ICP HIT or parent selection).
    async fn try_fetch_via_hierarchy(
        &self,
        method: &str,
        url: &str,
        req: Request<Body>,
    ) -> Option<(Arc<CachePeer>, hyper::Response<Incoming>)> {
        if !CACHEABLE_METHODS.contains(&method) {
            return None;
        }

        let hierarchy = self.hierarchy.as_ref()?;

        let peer = match hierarchy.resolve_source(url).await {
            HierarchyResult::SiblingHit(peer) | HierarchyResult::ParentHit(peer) => peer,
            HierarchyResult::LocalHit | HierarchyResult::OriginRequired => return None,
        };

        let timeout = hierarchy.parent_timeout();
        match fetch_via_peer(&peer, req, timeout).await {
            Ok(response) => {
                info!("Peer response via {} for {}", peer.id, url);
                Some((peer, response))
            }
            Err(e) => {
                warn!("Peer fetch failed via {} for {}: {}", peer.id, url, e);
                hierarchy.record_peer_error(&peer).await;
                None
            }
        }
    }

    #[inline]
    fn extract_domain(url_str: &str) -> String {
        url::Url::parse(url_str)
            .ok()
            .and_then(|u| u.host().map(|h| h.to_string()))
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn extract_user_info(req: &Request<Incoming>) -> (Option<String>, Option<String>) {
        if let Some(auth_header) = req.headers().get(AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(encoded) = auth_str.strip_prefix("Basic ") {
                    if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(encoded) {
                        if let Ok(credentials) = String::from_utf8(decoded_bytes) {
                            if let Some((username, _)) = credentials.split_once(':') {
                                return (Some(username.to_string()), Some(username.to_string()));
                            }
                        }
                    }
                }
            }
        }
        (None, None)
    }

    pub(crate) fn send_cache_event(&self, event: CacheEvent) {
        if !self.perf.should_emit_kafka_event() {
            return;
        }
        if let Some(producer) = self.kafka_producer.clone() {
            send_to_kafka_async(
                producer,
                self.kafka_topic.clone(),
                self.metrics.clone(),
                event,
            );
        }
    }

    pub async fn flush_kafka(&self, timeout: Duration) {
        let Some(producer) = self.kafka_producer.clone() else {
            return;
        };

        flush_kafka(producer, timeout).await;
    }

    fn finish_request_metrics(
        guard: &mut Option<RequestMetricsGuard>,
        fast_scope: &mut Option<FastRequestScope>,
        status: u16,
        request_size: usize,
        response_size: usize,
    ) {
        if let Some(g) = guard.take() {
            g.finish(status, request_size, response_size);
        } else if let Some(scope) = fast_scope.take() {
            scope.finish(status);
        }
    }

    pub(crate) async fn handle_request(
        &self,
        req: Request<Incoming>,
        client_ip: String,
        proxy_user: Option<Arc<UserInfo>>,
    ) -> Response<Body> {
        let detailed_metrics = self.perf.record_detailed_metrics();
        let http_method = req.method().clone();
        let method = http_method.as_str();
        let uri = req.uri();
        let url = uri.to_string();

        let mut guard = if detailed_metrics {
            Some(RequestMetricsGuard::new(
                self.metrics.clone(),
                method.to_string(),
            ))
        } else {
            None
        };
        let mut fast_scope = if detailed_metrics {
            None
        } else {
            Some(FastRequestScope::begin(self.metrics.clone()))
        };

        let request_start = Instant::now();

        let cache_key = self.generate_cache_key(method, &url);

        if self.perf.fast_cache_hit {
            if let Some(cached) = self.http_cache.get(&cache_key) {
                if cached.can_serve_fresh() {
                    debug!("Cache HIT (fast path): {} {}", method, url);
                    return self.serve_l1_hit(
                        &cached,
                        &cache_key,
                        &url,
                        method,
                        &None,
                        &None,
                        &client_ip,
                        &[],
                        &[],
                        request_start,
                        false,
                        &mut guard,
                        &mut fast_scope,
                        "HIT",
                        "HIT",
                    );
                }
            }
        }

        let (user_id, username) = if let Some(user) = proxy_user.as_deref() {
            Self::user_fields(Some(user))
        } else {
            Self::extract_user_info(&req)
        };

        if let Some(resp) = self.check_rate_limit(&client_ip, username.as_deref()) {
            if let Some(g) = guard.take() {
                g.finish(429, 0, 0);
            } else if let Some(scope) = fast_scope.take() {
                scope.finish(429);
            }
            return resp;
        }

        let user_groups: Vec<&str> = proxy_user
            .as_deref()
            .map(|u| u.groups.iter().map(String::as_str).collect())
            .unwrap_or_default();

        let domain = Self::extract_domain(&url);
        let (policy_decision, categories, threat_sources) = self
            .check_policy(&url, &domain, username.as_deref(), &user_groups, &client_ip)
            .await;
        if let Some(decision) = policy_decision {
            self.emit_policy_event(
                &url,
                method,
                &cache_key,
                &decision,
                &user_id,
                &username,
                &client_ip,
                &domain,
                &categories,
                &threat_sources,
                request_start,
            );
            let response = Self::policy_response(&decision);
            if let Some(g) = guard.take() {
                g.finish(response.status().as_u16(), 0, 0);
            } else if let Some(scope) = fast_scope.take() {
                scope.finish(response.status().as_u16());
            }
            return response;
        }

        let cache_lookup_start = Instant::now();
        if let Some(cached) = self.http_cache.get(&cache_key) {
            if detailed_metrics {
                self.metrics
                    .cache_lookup_duration_seconds
                    .observe(cache_lookup_start.elapsed().as_secs_f64());
            }

            if cached.can_serve_fresh() {
                debug!("Cache HIT: {} {}", method, url);
                return self.serve_l1_hit(
                    &cached,
                    &cache_key,
                    &url,
                    method,
                    &user_id,
                    &username,
                    &client_ip,
                    &categories,
                    &threat_sources,
                    request_start,
                    detailed_metrics,
                    &mut guard,
                    &mut fast_scope,
                    "HIT",
                    "HIT",
                );
            }

            if let Some(resp) = self
                .try_revalidate_stale(
                    &cached,
                    &req,
                    &cache_key,
                    &url,
                    method,
                    &user_id,
                    &username,
                    &client_ip,
                    &categories,
                    &threat_sources,
                    request_start,
                    detailed_metrics,
                    &mut guard,
                    &mut fast_scope,
                )
                .await
            {
                return resp;
            }
        }

        if let Some(cached) = self.try_l2_cache_get(&cache_key).await {
            debug!("Cache L2 HIT: {} {}", method, url);
            self.http_cache.insert(cache_key.clone(), cached.clone());
            let hit_label = if cached.is_negative {
                "NEGATIVE_HIT"
            } else {
                "L2_HIT"
            };
            let x_status = if cached.is_negative {
                "NEGATIVE-HIT"
            } else {
                "L2-HIT"
            };
            if let Some(g) = guard.as_mut() {
                g.set_cache_status(hit_label);
                self.metrics.cache_hits_total.inc();
            }

            if detailed_metrics {
                self.emit_cache_hit_event(
                    &url,
                    method,
                    &cache_key,
                    hit_label,
                    &cached,
                    &user_id,
                    &username,
                    &client_ip,
                    &categories,
                    &threat_sources,
                    request_start,
                );
            }

            let response = cached.to_response_with_cache_status(x_status);
            let body_size = cached.response_body_len();
            if let Some(g) = guard.take() {
                g.finish(cached.status, 0, body_size);
            } else if let Some(scope) = fast_scope.take() {
                scope.finish_cache_hit();
            }
            return response;
        }

        if detailed_metrics {
            self.metrics
                .cache_lookup_duration_seconds
                .observe(cache_lookup_start.elapsed().as_secs_f64());
        }

        debug!("Cache MISS: {} {}", method, url);
        self.metrics.cache_misses_total.inc();

        let (parts, body) = req.into_parts();
        let body_bytes = match http_body_util::BodyExt::collect(body).await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                error!("Body collection failed: {}", e);
                let mut resp = Response::new(Body::new(Bytes::from_static(b"400 Bad Request")));
                *resp.status_mut() = StatusCode::BAD_REQUEST;
                Self::finish_request_metrics(&mut guard, &mut fast_scope, 400, 0, 15);
                return resp;
            }
        };
        let request_body_size = body_bytes.len();
        let req = Request::from_parts(parts, Body::new(body_bytes.clone()));

        let domain = Self::extract_domain(&url);
        let upstream_start = Instant::now();

        let peer_fetch = self
            .try_fetch_via_hierarchy(method, &url, req.clone())
            .await;
        let hierarchy_peer = peer_fetch.as_ref().map(|(peer, _)| peer.clone());

        let fetch_result = if let Some((_, response)) = peer_fetch {
            Ok(response)
        } else {
            self.http_client.request(req).await
        };

        match fetch_result {
            Ok(response) => {
                let upstream_duration = upstream_start.elapsed().as_secs_f64();
                let status = response.status();

                self.metrics
                    .upstream_requests_total
                    .with_label_values(&[&domain, &status.as_u16().to_string()])
                    .inc();
                self.metrics
                    .upstream_duration_seconds
                    .with_label_values(&[&domain])
                    .observe(upstream_duration);

                let headers_map: HashMap<String, String> = response
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| {
                        v.to_str()
                            .ok()
                            .map(|v| (k.as_str().to_string(), v.to_string()))
                    })
                    .collect();

                let body_bytes = match http_body_util::BodyExt::collect(response.into_body()).await
                {
                    Ok(collected) => collected.to_bytes(),
                    Err(e) => {
                        error!("Response body collection failed: {}", e);
                        self.metrics
                            .upstream_errors_total
                            .with_label_values(&[&domain, "body_read"])
                            .inc();
                        let mut resp =
                            Response::new(Body::new(Bytes::from_static(b"502 Bad Gateway")));
                        *resp.status_mut() = StatusCode::BAD_GATEWAY;
                        Self::finish_request_metrics(
                            &mut guard,
                            &mut fast_scope,
                            502,
                            request_body_size,
                            15,
                        );
                        return resp;
                    }
                };
                let body_size = body_bytes.len();

                if let (Some(hierarchy), Some(peer)) =
                    (self.hierarchy.as_ref(), hierarchy_peer.as_ref())
                {
                    hierarchy.record_peer_hit(peer, body_size as u64).await;
                }

                let store_decision = evaluate_store(
                    method,
                    status.as_u16(),
                    &headers_map,
                    body_size,
                    &self.cache_config,
                );
                let cache_status = if store_decision.store {
                    let headers_arc: Arc<[(Arc<str>, Arc<str>)]> = headers_map
                        .iter()
                        .map(|(k, v)| (Arc::from(k.as_str()), Arc::from(v.as_str())))
                        .collect();

                    let cached_response = CachedResponse::from_upstream(
                        status.as_u16(),
                        headers_arc,
                        body_bytes.clone(),
                        store_decision.ttl,
                        &self.cache_config.compression,
                        self.cache_config.spill_threshold_bytes,
                        &self.cache_config.spill_dir,
                        store_decision.etag,
                        store_decision.last_modified,
                        store_decision.is_negative,
                        store_decision.must_revalidate,
                    );
                    self.store_in_l1_and_l2(cache_key.clone(), cached_response);
                    if let Some(g) = guard.as_mut() {
                        g.set_cache_status(if store_decision.is_negative {
                            "NEGATIVE_MISS"
                        } else {
                            "MISS"
                        });
                    }
                    if store_decision.is_negative {
                        "NEGATIVE_MISS"
                    } else {
                        "MISS"
                    }
                } else {
                    self.metrics.cache_bypasses_total.inc();
                    if let Some(g) = guard.as_mut() {
                        g.set_cache_status("BYPASS");
                    }
                    "BYPASS"
                };

                if let Ok(timestamp) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                    let event = CacheEvent {
                        url: url.clone(),
                        method: method.to_string(),
                        status: status.as_u16(),
                        cache_key: cache_key.to_string(),
                        cache_status: cache_status.to_string(),
                        timestamp: timestamp.as_secs(),
                        headers: headers_map.clone(),
                        user_id,
                        username,
                        client_ip,
                        domain,
                        response_size: body_size as u64,
                        request_duration_ms: request_start.elapsed().as_millis() as u64,
                        content_type: headers_map.get("content-type").cloned(),
                        user_agent: headers_map.get("user-agent").cloned(),
                        categories: categories.clone(),
                        threat_sources: threat_sources.clone(),
                        acl_action: None,
                        event_id: new_event_id(),
                    };
                    self.send_cache_event(event);
                }

                let mut resp = Response::new(Body::new(body_bytes));
                *resp.status_mut() = status;
                for (key, value) in headers_map {
                    if let (Ok(name), Ok(val)) = (
                        HeaderName::from_bytes(key.as_bytes()),
                        HeaderValue::from_str(&value),
                    ) {
                        resp.headers_mut().insert(name, val);
                    }
                }
                Self::finish_request_metrics(
                    &mut guard,
                    &mut fast_scope,
                    status.as_u16(),
                    request_body_size,
                    body_size,
                );
                resp
            }
            Err(e) => {
                error!("Upstream error for {}: {}", url, e);
                self.metrics
                    .upstream_errors_total
                    .with_label_values(&[&domain, "connection"])
                    .inc();
                let mut response = Response::new(Body::new(Bytes::from_static(b"502 Bad Gateway")));
                *response.status_mut() = StatusCode::BAD_GATEWAY;
                Self::finish_request_metrics(
                    &mut guard,
                    &mut fast_scope,
                    502,
                    request_body_size,
                    15,
                );
                response
            }
        }
    }
}
