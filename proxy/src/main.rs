mod auth_config;
mod metrics;
mod policy_config;
mod tls;

use auth_config::load_auth_config;
use base64::engine::general_purpose;
use base64::Engine;
use bsdm_proxy::{
    build_hierarchy_manager, fetch_via_peer, http_cache_key, icp_server_bind_addr,
    load_hierarchy_config, should_start_icp_server, AclAction, AclDecision, AuthManager, Category,
    HierarchyManager, HierarchyResult, IcpServer, UserInfo,
};
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue, AUTHORIZATION, LOCATION};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use metrics::{Metrics, RequestMetricsGuard};
use policy_config::{load_policy_config, reload_acl_engine, PolicyConfig};
use quick_cache::sync::Cache;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord, Producer};
use rustls_platform_verifier::BuilderVerifierExt;
use serde::Serialize;
use std::collections::HashMap;
use std::convert::Infallible;
use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};
use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tls::{parse_authority, rewrite_mitm_request, should_mitm_port, CertCache};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::sync::watch;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

type Body = http_body_util::Full<Bytes>;

const CACHEABLE_METHODS: &[&str] = &["GET", "HEAD"];
const CACHEABLE_STATUS_CODES: &[u16] = &[200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501];

/// Hop-by-hop and framing headers that must not be forwarded after the body is buffered.
const STRIP_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

fn normalize_response_headers(
    headers: HashMap<String, String>,
    body_len: usize,
    method: &str,
) -> HashMap<String, String> {
    let is_head = method.eq_ignore_ascii_case("HEAD");
    let upstream_content_length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.clone());

    let mut out: HashMap<String, String> = headers
        .into_iter()
        .filter(|(k, _)| {
            let lower = k.to_ascii_lowercase();
            !STRIP_RESPONSE_HEADERS.contains(&lower.as_str())
                && !(lower == "content-length" && !is_head)
        })
        .collect();

    if is_head {
        if let Some(cl) = upstream_content_length {
            out.insert("content-length".to_string(), cl);
        }
    } else if body_len > 0 || !matches!(method, "GET" | "HEAD") {
        out.insert("content-length".to_string(), body_len.to_string());
    }

    out
}

fn apply_response_headers(response: &mut Response<Body>, headers: &HashMap<String, String>) {
    for (key, value) in headers {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(key.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            response.headers_mut().insert(name, val);
        }
    }
}

#[derive(Clone, Debug)]
struct CachedResponse {
    status: u16,
    headers: Arc<[(Arc<str>, Arc<str>)]>,
    body: Bytes,
    cached_at: SystemTime,
    ttl: Duration,
}

impl CachedResponse {
    #[inline]
    fn is_expired(&self) -> bool {
        SystemTime::now()
            .duration_since(self.cached_at)
            .map_or(true, |age| age > self.ttl)
    }

    fn to_response(&self) -> Response<Body> {
        let mut response = Response::new(Body::new(self.body.clone()));
        *response.status_mut() = StatusCode::from_u16(self.status).unwrap_or(StatusCode::OK);

        let headers_map: HashMap<String, String> = self
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        apply_response_headers(&mut response, &headers_map);
        response
            .headers_mut()
            .insert("x-cache-status", HeaderValue::from_static("HIT"));
        response
    }
}

#[derive(Serialize, Clone, Debug)]
struct CacheEvent {
    url: String,
    method: String,
    status: u16,
    cache_key: String,
    cache_status: &'static str,
    timestamp: u64,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    client_ip: String,
    domain: String,
    response_size: u64,
    request_duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    categories: Vec<String>,
}

#[derive(Clone)]
struct CacheConfig {
    capacity: usize,
    default_ttl: Duration,
    max_body_size: usize,
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

#[derive(Clone)]
struct ProxyService {
    cert_cache: CertCache,
    http_cache: Arc<Cache<Arc<str>, CachedResponse>>,
    cache_config: CacheConfig,
    kafka_producer: Option<Arc<FutureProducer>>,
    http_client: hyper_util::client::legacy::Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Body,
    >,
    metrics: Arc<Metrics>,
    mitm_enabled: bool,
    auth: Option<Arc<AuthManager>>,
    acl_engine: Option<Arc<Mutex<bsdm_proxy::AclEngine>>>,
    categorization: Option<Arc<bsdm_proxy::CategorizationEngine>>,
    hierarchy: Option<Arc<HierarchyManager>>,
}

impl ProxyService {
    #[allow(clippy::too_many_arguments)]
    fn new(
        cert_cache: CertCache,
        cache_config: CacheConfig,
        kafka_brokers: Option<String>,
        metrics: Arc<Metrics>,
        mitm_enabled: bool,
        auth: Option<Arc<AuthManager>>,
        policy: &PolicyConfig,
        hierarchy: Option<Arc<HierarchyManager>>,
    ) -> Self {
        let kafka_producer = kafka_brokers.and_then(|brokers| {
            ClientConfig::new()
                .set("bootstrap.servers", &brokers)
                .set("message.timeout.ms", "5000")
                .set("compression.type", "snappy")
                .set("batch.size", "32768")
                .set("linger.ms", "5")
                .set("acks", "0")
                .create()
                .ok()
                .map(Arc::new)
        });

        let http_cache = Arc::new(Cache::new(cache_config.capacity));

        let https =
            build_upstream_https_connector().expect("failed to build upstream HTTPS connector");

        let http_client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .pool_idle_timeout(Duration::from_secs(90))
                .pool_max_idle_per_host(32)
                .build(https);

        Self {
            cert_cache,
            http_cache,
            cache_config,
            kafka_producer,
            http_client,
            metrics,
            mitm_enabled,
            auth,
            acl_engine: policy.acl_engine.clone(),
            categorization: policy.categorization.clone(),
            hierarchy,
        }
    }

    fn parse_client_ip(client_ip: &str) -> Option<IpAddr> {
        client_ip.parse().ok()
    }

    async fn check_policy(
        &self,
        url: &str,
        domain: &str,
        username: Option<&str>,
        client_ip: &str,
    ) -> (Option<AclDecision>, Vec<String>) {
        let eval_start = Instant::now();
        let mut category_names = Vec::new();

        if let Some(engine) = &self.categorization {
            let result = engine.categorize(url).await;
            category_names = result
                .categories
                .iter()
                .map(Category::acl_name)
                .filter(|name| !name.is_empty())
                .collect();
        }

        let Some(acl_engine) = &self.acl_engine else {
            return (None, category_names);
        };

        let category_refs: Vec<&str> = category_names.iter().map(String::as_str).collect();
        let decision = {
            let mut engine = acl_engine.lock().await;
            engine.check_access(
                url,
                domain,
                &category_refs,
                username,
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
            (None, category_names)
        } else {
            info!("ACL {} for {}: {}", decision.action, url, decision.reason);
            (Some(decision), category_names)
        }
    }

    fn policy_response(decision: &AclDecision) -> Response<Body> {
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

    async fn authenticate_proxy(
        &self,
        req: &Request<Incoming>,
    ) -> Result<Option<Arc<UserInfo>>, Response<Body>> {
        let Some(auth) = &self.auth else {
            return Ok(None);
        };
        if !auth.is_enabled() {
            return Ok(None);
        }

        let Some((username, password)) = auth.extract_credentials(req) else {
            debug!("Proxy authentication required, credentials missing");
            return Err(auth.create_auth_required_response());
        };

        match auth.authenticate(&username, &password).await {
            Ok(user) => Ok(Some(Arc::new(user))),
            Err(e) => {
                warn!("Proxy authentication failed for {}: {}", username, e);
                Err(auth.create_auth_required_response())
            }
        }
    }

    fn user_fields(user: Option<&UserInfo>) -> (Option<String>, Option<String>) {
        user.map(|u| {
            let name = u.username.clone();
            (Some(name.clone()), Some(name))
        })
        .unwrap_or((None, None))
    }

    #[inline]
    fn generate_cache_key(&self, method: &str, url: &str) -> Arc<str> {
        http_cache_key(method, url)
    }

    /// Try fetching via hierarchy peer (sibling ICP HIT or parent selection).
    async fn try_fetch_via_hierarchy(
        &self,
        method: &str,
        url: &str,
        req: Request<Body>,
    ) -> Option<(Arc<bsdm_proxy::CachePeer>, hyper::Response<Incoming>)> {
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
    fn is_cacheable(&self, method: &str, status: u16, body_size: usize) -> bool {
        CACHEABLE_METHODS.contains(&method)
            && CACHEABLE_STATUS_CODES.contains(&status)
            && body_size <= self.cache_config.max_body_size
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

    fn send_to_kafka_async(&self, event: CacheEvent) {
        if let Some(producer) = self.kafka_producer.clone() {
            let metrics = self.metrics.clone();
            tokio::spawn(async move {
                match serde_json::to_string(&event) {
                    Ok(payload) => {
                        let record = FutureRecord::to("cache-events")
                            .payload(&payload)
                            .key(&event.cache_key);
                        match producer.send(record, Duration::ZERO).await {
                            Ok(_) => metrics.kafka_events_sent.inc(),
                            Err((e, _)) => {
                                warn!("Kafka send failed: {}", e);
                                metrics.kafka_send_errors.inc();
                            }
                        }
                    }
                    Err(e) => {
                        error!("Event serialization failed: {}", e);
                        metrics.kafka_send_errors.inc();
                    }
                }
            });
        }
    }

    async fn flush_kafka(&self, timeout: Duration) {
        let Some(producer) = self.kafka_producer.clone() else {
            return;
        };

        info!("Flushing Kafka producer...");
        match tokio::task::spawn_blocking(move || producer.flush(timeout)).await {
            Ok(Ok(())) => info!("Kafka producer flushed"),
            Ok(Err(e)) => warn!("Kafka flush error: {}", e),
            Err(e) => error!("Kafka flush task failed: {}", e),
        }
    }

    async fn handle_request(
        &self,
        req: Request<Incoming>,
        client_ip: String,
        proxy_user: Option<Arc<UserInfo>>,
    ) -> Response<Body> {
        let mut guard = RequestMetricsGuard::new(self.metrics.clone(), req.method().to_string());
        let request_start = Instant::now();
        let method = req.method().to_string();
        let uri = req.uri().clone();
        let url = uri.to_string();
        let (user_id, username) = if let Some(user) = proxy_user.as_deref() {
            Self::user_fields(Some(user))
        } else {
            Self::extract_user_info(&req)
        };
        let domain = Self::extract_domain(&url);

        let (policy_decision, categories) = self
            .check_policy(&url, &domain, username.as_deref(), &client_ip)
            .await;
        if let Some(decision) = policy_decision {
            let response = Self::policy_response(&decision);
            guard.finish(response.status().as_u16(), 0, 0);
            return response;
        }

        let cache_key = self.generate_cache_key(&method, &url);

        // Cache lookup with timing
        let cache_lookup_start = Instant::now();
        if let Some(cached) = self.http_cache.get(&cache_key) {
            self.metrics
                .cache_lookup_duration_seconds
                .observe(cache_lookup_start.elapsed().as_secs_f64());

            if !cached.is_expired() {
                info!("Cache HIT: {} {}", method, url);
                self.metrics.cache_hits_total.inc();
                guard.set_cache_status("HIT");

                if let Ok(timestamp) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                    let event = CacheEvent {
                        url: url.clone(),
                        method: method.clone(),
                        status: cached.status,
                        cache_key: cache_key.to_string(),
                        cache_status: "HIT",
                        timestamp: timestamp.as_secs(),
                        headers: HashMap::new(),
                        user_id: user_id.clone(),
                        username: username.clone(),
                        client_ip: client_ip.clone(),
                        domain: Self::extract_domain(&url),
                        response_size: cached.body.len() as u64,
                        request_duration_ms: request_start.elapsed().as_millis() as u64,
                        content_type: cached
                            .headers
                            .iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                            .map(|(_, v)| v.to_string()),
                        user_agent: None,
                        categories: categories.clone(),
                    };
                    self.send_to_kafka_async(event);
                }
                let response = cached.to_response();
                let body_size = cached.body.len();
                guard.finish(cached.status, 0, body_size);
                return response;
            }
        }
        self.metrics
            .cache_lookup_duration_seconds
            .observe(cache_lookup_start.elapsed().as_secs_f64());

        info!("Cache MISS: {} {}", method, url);
        self.metrics.cache_misses_total.inc();

        // Request to upstream
        let (parts, body) = req.into_parts();
        let body_bytes = match http_body_util::BodyExt::collect(body).await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                error!("Body collection failed: {}", e);
                let mut resp = Response::new(Body::new(Bytes::from_static(b"400 Bad Request")));
                *resp.status_mut() = StatusCode::BAD_REQUEST;
                guard.finish(400, 0, 15);
                return resp;
            }
        };
        let request_body_size = body_bytes.len();
        let req = Request::from_parts(parts, Body::new(body_bytes.clone()));

        let domain = Self::extract_domain(&url);
        let upstream_start = Instant::now();

        let peer_fetch = self
            .try_fetch_via_hierarchy(&method, &url, req.clone())
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

                let raw_headers: HashMap<String, String> = response
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
                        guard.finish(502, request_body_size, 15);
                        return resp;
                    }
                };
                let body_size = body_bytes.len();
                let headers_map = normalize_response_headers(raw_headers, body_size, &method);

                if let (Some(hierarchy), Some(peer)) =
                    (self.hierarchy.as_ref(), hierarchy_peer.as_ref())
                {
                    hierarchy.record_peer_hit(peer, body_size as u64).await;
                }

                let cache_status = if self.is_cacheable(&method, status.as_u16(), body_size) {
                    let headers_arc: Arc<[(Arc<str>, Arc<str>)]> = headers_map
                        .iter()
                        .map(|(k, v)| (Arc::from(k.as_str()), Arc::from(v.as_str())))
                        .collect();

                    let cached_response = CachedResponse {
                        status: status.as_u16(),
                        headers: headers_arc,
                        body: body_bytes.clone(),
                        cached_at: SystemTime::now(),
                        ttl: self.cache_config.default_ttl,
                    };
                    self.http_cache.insert(cache_key.clone(), cached_response);
                    guard.set_cache_status("MISS");
                    "MISS"
                } else {
                    self.metrics.cache_bypasses_total.inc();
                    guard.set_cache_status("BYPASS");
                    "BYPASS"
                };

                if let Ok(timestamp) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                    let event = CacheEvent {
                        url: url.clone(),
                        method: method.clone(),
                        status: status.as_u16(),
                        cache_key: cache_key.to_string(),
                        cache_status,
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
                    };
                    self.send_to_kafka_async(event);
                }

                let mut resp = Response::new(Body::new(body_bytes));
                *resp.status_mut() = status;
                apply_response_headers(&mut resp, &headers_map);
                guard.finish(status.as_u16(), request_body_size, body_size);
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
                guard.finish(502, request_body_size, 15);
                response
            }
        }
    }
}

fn build_upstream_tls_with_combined_roots() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let native_certs = rustls_native_certs::load_native_certs();
    for err in &native_certs.errors {
        warn!("Failed to load native CA certificate: {err}");
    }
    let mut native = 0usize;
    for cert in native_certs.certs {
        if roots.add(cert).is_ok() {
            native += 1;
        }
    }
    info!("Upstream TLS: webpki-roots + {native} native CA certificate(s)");
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

fn build_upstream_https_connector() -> Result<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Box<dyn std::error::Error>,
> {
    let tls_config = if let Ok(path) = std::env::var("UPSTREAM_CA_CERT") {
        let pem = std::fs::read(&path)
            .map_err(|e| format!("failed to read UPSTREAM_CA_CERT {path}: {e}"))?;
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut Cursor::new(pem))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(|cert| cert.into_owned())
                .collect();
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(certs);
        info!("Upstream TLS: trusting custom CA from UPSTREAM_CA_CERT");
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else if std::env::var("UPSTREAM_TLS_PLATFORM")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        match rustls::ClientConfig::builder()
            .with_platform_verifier()
            .map(|builder| builder.with_no_client_auth())
        {
            Ok(config) => {
                info!("Upstream TLS: using platform certificate verifier");
                config
            }
            Err(e) => {
                warn!(
                    "Platform TLS verifier unavailable ({e}); falling back to webpki + native roots"
                );
                build_upstream_tls_with_combined_roots()
            }
        }
    } else {
        build_upstream_tls_with_combined_roots()
    };

    Ok(hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .build())
}

async fn metrics_server(
    metrics: Arc<Metrics>,
    draining: Arc<AtomicBool>,
    mut shutdown_rx: watch::Receiver<bool>,
    metrics_port: u16,
) {
    let bind_addr = format!("0.0.0.0:{}", metrics_port);
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind metrics server on {}: {}", bind_addr, e);
            return;
        }
    };

    info!("📊 Metrics server started on {}", bind_addr);

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, addr) = match accept_result {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!("Failed to accept metrics connection: {}", e);
                        continue;
                    }
                };

                let metrics = metrics.clone();
                let draining = draining.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |req: Request<Incoming>| {
                        let metrics = metrics.clone();
                        let draining = draining.clone();
                        async move {
                            let path = req.uri().path();
                            debug!("Metrics request from {}: {}", addr, path);

                            let response = match path {
                                "/metrics" => {
                                    debug!("Exporting metrics...");
                                    let export_result =
                                        panic::catch_unwind(panic::AssertUnwindSafe(|| metrics.export()));

                                    match export_result {
                                        Ok(Ok(body)) => {
                                            debug!("Metrics exported successfully: {} bytes", body.len());
                                            Response::builder()
                                                .status(StatusCode::OK)
                                                .header("Content-Type", "text/plain; version=0.0.4")
                                                .header("Content-Length", body.len().to_string())
                                                .body(Body::new(Bytes::from(body)))
                                                .unwrap_or_else(|e| {
                                                    error!("Failed to build metrics response: {}", e);
                                                    Response::new(Body::new(Bytes::from_static(
                                                        b"500 Internal Server Error",
                                                    )))
                                                })
                                        }
                                        Ok(Err(e)) => {
                                            error!("Failed to export metrics: {}", e);
                                            Response::builder()
                                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                .body(Body::new(Bytes::from_static(
                                                    b"500 Internal Server Error",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(Body::new(Bytes::from_static(
                                                        b"500 Internal Server Error",
                                                    )))
                                                })
                                        }
                                        Err(panic_info) => {
                                            error!("Metrics export panicked: {:?}", panic_info);
                                            Response::builder()
                                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                .body(Body::new(Bytes::from_static(
                                                    b"500 Panic in metrics export",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(Body::new(Bytes::from_static(
                                                        b"500 Internal Server Error",
                                                    )))
                                                })
                                        }
                                    }
                                }
                                "/health" => {
                                    debug!("Health check OK");
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("Content-Type", "application/json")
                                        .body(Body::new(Bytes::from_static(b"{\"status\":\"ok\"}")))
                                        .unwrap_or_else(|_| {
                                            Response::new(Body::new(Bytes::from_static(
                                                b"{\"status\":\"ok\"}",
                                            )))
                                        })
                                }
                                "/ready" => {
                                    if draining.load(Ordering::Relaxed) {
                                        debug!("Readiness check: draining");
                                        Response::builder()
                                            .status(StatusCode::SERVICE_UNAVAILABLE)
                                            .header("Content-Type", "application/json")
                                            .body(Body::new(Bytes::from_static(
                                                b"{\"status\":\"draining\"}",
                                            )))
                                            .unwrap_or_else(|_| {
                                                Response::new(Body::new(Bytes::from_static(
                                                    b"{\"status\":\"draining\"}",
                                                )))
                                            })
                                    } else {
                                        debug!("Readiness check OK");
                                        Response::builder()
                                            .status(StatusCode::OK)
                                            .header("Content-Type", "application/json")
                                            .body(Body::new(Bytes::from_static(
                                                b"{\"status\":\"ready\"}",
                                            )))
                                            .unwrap_or_else(|_| {
                                                Response::new(Body::new(Bytes::from_static(
                                                    b"{\"status\":\"ready\"}",
                                                )))
                                            })
                                    }
                                }
                                _ => {
                                    warn!("Unknown metrics endpoint: {}", path);
                                    Response::builder()
                                        .status(StatusCode::NOT_FOUND)
                                        .body(Body::new(Bytes::from_static(b"404 Not Found")))
                                        .unwrap_or_else(|_| {
                                            Response::new(Body::new(Bytes::from_static(b"404 Not Found")))
                                        })
                                }
                            };
                            Ok::<_, Infallible>(response)
                        }
                    });

                    if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                        error!("Metrics server connection error from {}: {}", addr, e);
                    }
                });
            }
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    info!("Metrics server stopping");
                    break;
                }
            }
        }
    }
}

async fn wait_shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = signal::ctrl_c().await {
            error!("Failed to listen for Ctrl+C: {}", e);
        } else {
            info!("Received Ctrl+C");
        }
    };

    #[cfg(unix)]
    {
        let mut sigterm =
            signal::unix::signal(signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {},
            _ = sigterm.recv() => info!("Received SIGTERM"),
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,bsdm_proxy=debug".into()),
        )
        .init();

    let metrics = Arc::new(Metrics::new()?);
    let draining = Arc::new(AtomicBool::new(false));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let connection_tasks = TaskTracker::new();

    let shutdown_timeout_secs = std::env::var("SHUTDOWN_TIMEOUT_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let shutdown_timeout = Duration::from_secs(shutdown_timeout_secs);

    let metrics_port = std::env::var("METRICS_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9090);

    tokio::spawn(metrics_server(
        metrics.clone(),
        draining.clone(),
        shutdown_rx.clone(),
        metrics_port,
    ));

    let mitm_enabled = std::env::var("MITM_ENABLED")
        .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no"))
        .unwrap_or(true);

    let cert_cache = CertCache::load_for_startup(mitm_enabled).await?;
    let kafka_brokers = std::env::var("KAFKA_BROKERS").ok();
    let cache_capacity = std::env::var("CACHE_CAPACITY")
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

    let cache_config = CacheConfig {
        capacity: cache_capacity,
        default_ttl: Duration::from_secs(cache_ttl_secs),
        max_body_size,
    };

    let auth_config = load_auth_config();
    let auth = if auth_config.enabled {
        Some(Arc::new(AuthManager::new(auth_config.clone())))
    } else {
        None
    };

    let policy_config = load_policy_config();
    if policy_config.acl_enabled {
        info!("ACL enabled");
    }
    if policy_config.categorization.is_some() {
        info!("URL categorization enabled");
    }

    let hierarchy_config = load_hierarchy_config();
    let hierarchy = build_hierarchy_manager(&hierarchy_config)
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e })?;

    let service = Arc::new(ProxyService::new(
        cert_cache,
        cache_config.clone(),
        kafka_brokers,
        metrics.clone(),
        mitm_enabled,
        auth,
        &policy_config,
        hierarchy.clone(),
    ));

    if should_start_icp_server(&hierarchy_config) {
        let icp_bind = icp_server_bind_addr();
        let cache_for_icp = service.http_cache.clone();
        match IcpServer::new(&icp_bind, move |url: &str| {
            let key = http_cache_key("GET", url);
            cache_for_icp
                .get(&key)
                .is_some_and(|cached| !cached.is_expired())
        })
        .await
        {
            Ok(server) => {
                info!("ICP server listening on {}", icp_bind);
                let server = Arc::new(server);
                tokio::spawn(async move {
                    server.serve().await;
                });
            }
            Err(e) => warn!("ICP server disabled: failed to bind {}: {}", icp_bind, e),
        }
    }

    if hierarchy_config.enabled {
        if let Some(ref manager) = hierarchy {
            info!("{}", manager.stats_summary().await);
        }
    }

    if policy_config.acl_auto_reload {
        if let (Some(acl_engine), Some(rules_path)) = (
            policy_config.acl_engine.clone(),
            policy_config.acl_rules_path.clone(),
        ) {
            let default_action = std::env::var("ACL_DEFAULT_ACTION")
                .map(|v| match v.to_ascii_lowercase().as_str() {
                    "deny" => AclAction::Deny,
                    "redirect" => AclAction::Redirect,
                    _ => AclAction::Allow,
                })
                .unwrap_or(AclAction::Allow);
            let reload_interval = policy_config.acl_reload_interval;
            let mut shutdown_rx = shutdown_rx.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(reload_interval);
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            match reload_acl_engine(&rules_path, default_action) {
                                Ok(engine) => {
                                    let mut guard = acl_engine.lock().await;
                                    *guard = engine;
                                    info!("ACL rules reloaded from {}", rules_path);
                                }
                                Err(e) => warn!("ACL reload failed: {}", e),
                            }
                        }
                        changed = shutdown_rx.changed() => {
                            if changed.is_ok() && *shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    }

    let http_port = std::env::var("HTTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1488);

    let listener = TcpListener::bind(format!("0.0.0.0:{}", http_port)).await?;
    info!("🚀 BSDM-Proxy v2.0 (optimized) on 0.0.0.0:{}", http_port);
    info!(
        "🔐 MITM: {} (ports 443/8443)",
        if mitm_enabled { "enabled" } else { "disabled" }
    );
    if auth_config.enabled {
        info!(
            "👤 Proxy auth: enabled (backend={}, realm={})",
            auth_config.backend, auth_config.realm
        );
    } else {
        info!("👤 Proxy auth: disabled");
    }
    info!(
        "📦 Cache: {} entries, TTL: {:?}, max body: {}MB",
        service.http_cache.capacity(),
        cache_config.default_ttl,
        max_body_size / 1024 / 1024
    );

    let metrics_clone = metrics.clone();
    let cache_clone = service.http_cache.clone();
    let mut cache_shutdown_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let entries = cache_clone.len();
                    let weight = cache_clone.weight();

                    metrics_clone.cache_entries.set(entries as f64);
                    metrics_clone.cache_size_bytes.set(weight as f64);

                    debug!(
                        "Cache stats: entries={}, weight={}KB",
                        entries,
                        weight / 1024
                    );
                }
                changed = cache_shutdown_rx.changed() => {
                    if changed.is_ok() && *cache_shutdown_rx.borrow() {
                        debug!("Cache metrics reporter stopped");
                        break;
                    }
                }
            }
        }
    });

    if let Some(auth_manager) = service.auth.clone() {
        let mut auth_shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = interval.tick() => auth_manager.cleanup_cache().await,
                    changed = auth_shutdown_rx.changed() => {
                        if changed.is_ok() && *auth_shutdown_rx.borrow() {
                            debug!("Auth cache cleanup stopped");
                            break;
                        }
                    }
                }
            }
        });
    }

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, addr) = match accept_result {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!("Accept failed: {}", e);
                        continue;
                    }
                };
                let service_clone = service.clone();
                let client_ip = addr.ip().to_string();
                let tasks = connection_tasks.clone();
                connection_tasks.spawn(async move {
                    handle_connection(stream, addr, service_clone, client_ip, tasks).await;
                });
            }
            _ = wait_shutdown_signal() => {
                info!("Shutdown signal received, stopping accept loop");
                break;
            }
        }
    }

    draining.store(true, Ordering::SeqCst);
    let _ = shutdown_tx.send(true);
    drop(listener);

    let in_flight = service.metrics.requests_in_flight.get() as usize;
    info!(
        "Draining connections: {} tracked tasks, {} in-flight HTTP requests",
        connection_tasks.len(),
        in_flight
    );

    connection_tasks.close();
    tokio::select! {
        _ = connection_tasks.wait() => info!("All proxy connections closed"),
        _ = tokio::time::sleep(shutdown_timeout) => {
            warn!(
                "Shutdown timeout after {}s, {} tasks still active",
                shutdown_timeout_secs,
                connection_tasks.len()
            );
        }
    }

    service
        .flush_kafka(shutdown_timeout.min(Duration::from_secs(10)))
        .await;
    info!("Graceful shutdown complete");
    Ok(())
}

async fn handle_connect_tunnel(
    upgraded: hyper::upgrade::Upgraded,
    authority: String,
    service: Arc<ProxyService>,
    client_ip: String,
    request_start: Instant,
    proxy_user: Option<Arc<UserInfo>>,
) {
    let mut client_io = TokioIo::new(upgraded);

    match TcpStream::connect(&authority).await {
        Ok(mut upstream) => {
            service.metrics.upstream_connections_created.inc();
            service.metrics.upstream_connections_active.inc();

            match copy_bidirectional(&mut client_io, &mut upstream).await {
                Ok((bytes_c2u, bytes_u2c)) => {
                    service.metrics.upstream_connections_active.dec();
                    let duration_ms = request_start.elapsed().as_millis() as u64;
                    let domain = parse_authority(&authority).0;
                    let (user_id, username) = ProxyService::user_fields(proxy_user.as_deref());

                    if let Ok(timestamp) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
                    {
                        let event = CacheEvent {
                            url: format!("https://{}", authority),
                            method: "CONNECT".to_string(),
                            status: 200,
                            cache_key: service
                                .generate_cache_key("CONNECT", &authority)
                                .to_string(),
                            cache_status: "BYPASS",
                            timestamp: timestamp.as_secs(),
                            headers: HashMap::new(),
                            user_id,
                            username,
                            client_ip,
                            domain,
                            response_size: bytes_u2c,
                            request_duration_ms: duration_ms,
                            content_type: None,
                            user_agent: None,
                            categories: vec![],
                        };
                        service.send_to_kafka_async(event);
                    }
                    debug!("CONNECT tunnel closed: {}↑ {}↓", bytes_c2u, bytes_u2c);
                }
                Err(e) => {
                    error!("CONNECT copy failed: {}", e);
                    service.metrics.upstream_connections_active.dec();
                }
            }
        }
        Err(e) => {
            error!("CONNECT upstream failed: {}", e);
            service
                .metrics
                .upstream_errors_total
                .with_label_values(&[&authority, "connect"])
                .inc();
        }
    }
}

async fn handle_connect_mitm(
    upgraded: hyper::upgrade::Upgraded,
    authority: String,
    service: Arc<ProxyService>,
    client_ip: String,
    proxy_user: Option<Arc<UserInfo>>,
) {
    let (domain, _port) = parse_authority(&authority);

    let server_config = match service.cert_cache.server_config_for_domain(&domain).await {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to build TLS config for {}: {}", domain, e);
            return;
        }
    };

    let tls_acceptor = TlsAcceptor::from(server_config);
    let tls_stream = match tls_acceptor.accept(TokioIo::new(upgraded)).await {
        Ok(stream) => {
            service
                .metrics
                .tls_handshakes_total
                .with_label_values(&["success"])
                .inc();
            stream
        }
        Err(e) => {
            service
                .metrics
                .tls_handshakes_total
                .with_label_values(&["error"])
                .inc();
            error!("TLS handshake failed for {}: {}", domain, e);
            return;
        }
    };

    info!("MITM session established for {}", authority);
    let authority_log = authority.clone();
    let io = TokioIo::new(tls_stream);
    let svc = service_fn(move |req: Request<Incoming>| {
        let service = service.clone();
        let client_ip = client_ip.clone();
        let authority = authority.clone();
        let proxy_user = proxy_user.clone();

        async move {
            let req = match rewrite_mitm_request(req, &authority) {
                Ok(req) => req,
                Err(e) => {
                    error!("Failed to rewrite MITM request for {}: {}", authority, e);
                    let mut resp = Response::new(Body::new(Bytes::from_static(b"400 Bad Request")));
                    *resp.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok::<_, Infallible>(resp);
                }
            };

            Ok::<_, Infallible>(service.handle_request(req, client_ip, proxy_user).await)
        }
    });

    if let Err(e) = http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, svc)
        .await
    {
        debug!("MITM connection closed for {}: {}", authority_log, e);
    }
}

async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    service: Arc<ProxyService>,
    client_ip: String,
    tasks: TaskTracker,
) {
    let io = TokioIo::new(stream);

    let svc = service_fn(move |req: Request<Incoming>| {
        let service = service.clone();
        let client_ip = client_ip.clone();
        let request_start = Instant::now();
        let tasks = tasks.clone();

        async move {
            if req.method() == Method::CONNECT {
                let authority = match req.uri().authority() {
                    Some(auth) => auth.as_str().to_string(),
                    None => {
                        error!("CONNECT without authority");
                        let mut resp =
                            Response::new(Body::new(Bytes::from_static(b"400 Bad Request")));
                        *resp.status_mut() = StatusCode::BAD_REQUEST;
                        return Ok::<_, Infallible>(resp);
                    }
                };

                let proxy_user = match service.authenticate_proxy(&req).await {
                    Ok(user) => user,
                    Err(resp) => return Ok(resp),
                };

                let connect_url = format!("https://{}", authority);
                let connect_domain = parse_authority(&authority).0;
                let policy_username = proxy_user.as_deref().map(|u| u.username.as_str());
                let (policy_decision, _) = service
                    .check_policy(&connect_url, &connect_domain, policy_username, &client_ip)
                    .await;
                if let Some(decision) = policy_decision {
                    return Ok::<_, Infallible>(ProxyService::policy_response(&decision));
                }

                tasks.spawn({
                    let service = service.clone();
                    let client_ip = client_ip.clone();
                    let authority = authority.clone();
                    let proxy_user = proxy_user.clone();
                    async move {
                        match hyper::upgrade::on(req).await {
                            Ok(upgraded) => {
                                let (_, port) = parse_authority(&authority);
                                if service.mitm_enabled && should_mitm_port(port) {
                                    handle_connect_mitm(
                                        upgraded, authority, service, client_ip, proxy_user,
                                    )
                                    .await;
                                } else {
                                    handle_connect_tunnel(
                                        upgraded,
                                        authority,
                                        service,
                                        client_ip,
                                        request_start,
                                        proxy_user,
                                    )
                                    .await;
                                }
                            }
                            Err(e) => error!("Upgrade failed: {}", e),
                        }
                    }
                });

                let response = Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::new(Bytes::new()))
                    .unwrap_or_else(|e| {
                        error!("Failed to build response: {}", e);
                        let mut resp = Response::new(Body::new(Bytes::new()));
                        *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        resp
                    });
                return Ok::<_, Infallible>(response);
            }

            let proxy_user = match service.authenticate_proxy(&req).await {
                Ok(user) => user,
                Err(resp) => return Ok(resp),
            };

            Ok::<_, Infallible>(service.handle_request(req, client_ip, proxy_user).await)
        }
    });

    if let Err(e) = http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, svc)
        .with_upgrades()
        .await
    {
        error!("Connection error from {}: {}", addr, e);
    }
}
