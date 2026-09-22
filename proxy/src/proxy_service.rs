//! Core HTTP proxy service: caching, policy, upstream fetch, and Kafka events.

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, LOCATION};
use hyper::{Request, Response, StatusCode};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tracing::{debug, error, info, warn};

use crate::acl::{AclAction, AclDecision, AclEngineHandle};
use crate::auth::{AuthManager, ProxyAuthOutcome, UserInfo};
use crate::cache::{CacheConfig, CachedResponse, CACHEABLE_METHODS};
use crate::cache_digest::DigestRegistry;
use crate::cache_freshness::{
    cache_status_metric_label, evaluate_store, evaluate_store_precheck, miss_x_cache_status_header,
    refresh_ttl_from_headers,
};
use crate::categorization::CategorizationEngine;
use crate::hierarchy::{HierarchyManager, HierarchyResult};
use crate::hop_headers::strip_hop_by_hop_request_headers;
use crate::http_types::{empty, full, Body};
use crate::icap::{IcapClient, IcapOutcome};
use crate::l2_cache::RedisL2Cache;
use crate::metrics::{FastRequestScope, Metrics, RequestMetricsGuard, StatusLabel};
use crate::miss_coalesce::{CoalesceJoin, MissFlightMap, MissFlightPermit};
use crate::mitm_breaker::MitmCircuitBreaker;
use crate::peer_fetch::{fetch_via_peer, PeerTlsConfig};
use crate::peers::CachePeer;
use crate::perf::PerfConfig;
use crate::pinning::PinningRegistry;
use crate::pipeline::{dispatch_cache_event, new_event_id, CacheEvent, HttpEventPipeline};
#[cfg(feature = "kafka")]
use crate::pipeline::{flush_kafka, KafkaEventPipeline};
use crate::policy_cache::PolicyDecisionCache;
use crate::policy_engine::{PolicyEngine, PolicyEvaluation};
use crate::policy_event::{build_policy_event, effective_decision_source, PolicyEventContext};
use crate::rate_limit::{extract_api_key_ref, RateLimitViolation, RateLimiter};
use crate::semantic_cache::{
    content_cache_key, evaluate_llm_store, extract_embed_text, normalize_llm_body,
    SemanticCacheConfig, SemanticIndex,
};
use crate::session::{header_ci, resolve_location, SessionCorrelator};
use crate::sharded_cache::HttpL1Cache;
use crate::streaming_miss::TeeMissBody;
use crate::threat_score_cache::ThreatScoreCache;
use crate::ti_enforce::TiEnforceMatcher;
use crate::ti_shadow::TiShadowMatcher;
use crate::tls::CertCache;
use crate::upstream::{UpstreamClientHandle, UpstreamTlsConfig};
#[cfg(feature = "wasm")]
use crate::wasm_host::{try_load_from_env, WasmHookDecision, WasmHookRequest};

mod access;
mod cache_ops;
mod helpers;
mod types;

pub struct ProxyPolicy {
    pub policy_mode: crate::policy_config::PolicyMode,
    pub mitm_categories: Vec<String>,
    pub pinning_registry: Arc<PinningRegistry>,
    pub mitm_circuit_breaker: Arc<MitmCircuitBreaker>,
    pub acl_engine: Option<Arc<AclEngineHandle>>,
    pub categorization: Option<Arc<CategorizationEngine>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TlsPolicyDecision {
    pub mitm: bool,
    pub decision_source: &'static str,
    pub bypass_reason: Option<&'static str>,
}

/// Classify whether CONNECT should terminate TLS (MITM) for a domain.
///
/// # Invariant (#272)
/// `PolicyMode::Sni` **never** returns `mitm: true`, regardless of
/// `mitm_enabled`, pinning, or selective-category hints. Callers must still
/// skip MITM for non-TLS ports via [`crate::tls::should_mitm_port`].
fn classify_tls_policy_decision(
    mitm_enabled: bool,
    pinned: bool,
    tripped: bool,
    policy_mode: crate::policy_config::PolicyMode,
    selective_mitm: bool,
) -> TlsPolicyDecision {
    // Hard gate: SNI-only mode is pure tunnel — no TLS termination path.
    // Evaluated first so category hints cannot override the mode.
    if policy_mode == crate::policy_config::PolicyMode::Sni {
        return TlsPolicyDecision {
            mitm: false,
            decision_source: "sni",
            bypass_reason: Some("policy_mode_sni"),
        };
    }
    if !mitm_enabled {
        return TlsPolicyDecision {
            mitm: false,
            decision_source: "sni",
            bypass_reason: Some("mitm_disabled"),
        };
    }
    if pinned {
        return TlsPolicyDecision {
            mitm: false,
            decision_source: "pinning-bypass",
            bypass_reason: Some("certificate_pinning_exception"),
        };
    }
    if tripped {
        return TlsPolicyDecision {
            mitm: false,
            decision_source: "pinning-bypass",
            bypass_reason: Some("circuit_breaker_tripped"),
        };
    }
    match policy_mode {
        crate::policy_config::PolicyMode::FullMitm => TlsPolicyDecision {
            mitm: true,
            decision_source: "mitm",
            bypass_reason: None,
        },
        crate::policy_config::PolicyMode::SelectiveMitm => TlsPolicyDecision {
            mitm: selective_mitm,
            decision_source: if selective_mitm { "mitm" } else { "sni" },
            bypass_reason: if selective_mitm {
                None
            } else {
                Some("category_not_selected_for_mitm")
            },
        },
        // Defensive: Sni is handled at the top of this function.
        crate::policy_config::PolicyMode::Sni => TlsPolicyDecision {
            mitm: false,
            decision_source: "sni",
            bypass_reason: Some("policy_mode_sni"),
        },
    }
}

/// Prometheus label for an HTTP method.
///
/// Standard methods map to a `&'static str`, so the request path does not
/// allocate a label string; anything exotic still gets a correct (copied) label.
fn method_metric_label(method: &hyper::Method) -> std::borrow::Cow<'static, str> {
    use std::borrow::Cow;
    match *method {
        hyper::Method::GET => Cow::Borrowed("GET"),
        hyper::Method::POST => Cow::Borrowed("POST"),
        hyper::Method::HEAD => Cow::Borrowed("HEAD"),
        hyper::Method::PUT => Cow::Borrowed("PUT"),
        hyper::Method::DELETE => Cow::Borrowed("DELETE"),
        hyper::Method::OPTIONS => Cow::Borrowed("OPTIONS"),
        hyper::Method::PATCH => Cow::Borrowed("PATCH"),
        hyper::Method::CONNECT => Cow::Borrowed("CONNECT"),
        hyper::Method::TRACE => Cow::Borrowed("TRACE"),
        _ => Cow::Owned(method.as_str().to_string()),
    }
}

fn request_decision_source(url: &str) -> &'static str {
    if url.starts_with("https://") {
        "mitm"
    } else {
        "sni"
    }
}

pub struct ProxyService {
    pub(crate) cert_cache: CertCache,
    http_cache: Arc<HttpL1Cache>,
    l2_cache: Option<RedisL2Cache>,
    cache_config: CacheConfig,
    #[cfg(feature = "kafka")]
    kafka_pipeline: Option<Arc<KafkaEventPipeline>>,
    http_pipeline: Option<Arc<HttpEventPipeline>>,
    http_client: UpstreamClientHandle,
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) policy_mode: crate::policy_config::PolicyMode,
    pub(crate) mitm_categories: std::collections::HashSet<String>,
    pub(crate) pinning_registry: Arc<PinningRegistry>,
    pub(crate) mitm_circuit_breaker: Arc<MitmCircuitBreaker>,
    pub(crate) mitm_enabled: bool,
    auth: Option<Arc<AuthManager>>,
    policy_engine: PolicyEngine,
    hierarchy: Option<Arc<HierarchyManager>>,
    digest_registry: Option<Arc<DigestRegistry>>,
    rate_limiter: Arc<RateLimiter>,
    perf: PerfConfig,
    sessions: Arc<SessionCorrelator>,
    /// Observe-only threat-intel matcher (issue #330); never blocks.
    ti_shadow: Arc<TiShadowMatcher>,
    miss_flights: MissFlightMap,
    semantic_config: SemanticCacheConfig,
    semantic_index: SemanticIndex,
    peer_tls: PeerTlsConfig,
    #[cfg(feature = "wasm")]
    pub wasm_hook: Option<Arc<std::sync::RwLock<crate::wasm_host::WasmHookEngine>>>,
    /// Optional ICAP adaptation client (`ICAP_ENABLED`).
    icap: Option<Arc<IcapClient>>,
    dlp_engine: Arc<crate::dlp::DlpEngine>,
    casb_engine: Arc<crate::casb::CasbEngine>,
    reverse_proxy_config: Option<crate::reverse_proxy::ReverseProxyConfig>,
    pub(crate) block_cloud_metadata: bool,
    pub(crate) block_loopback_forwarding: bool,
    pub(crate) allowed_connect_ports: Option<Vec<u16>>,
}

impl ProxyService {
    pub(crate) fn tls_policy_decision(&self, domain: &str) -> TlsPolicyDecision {
        // SNI mode: never evaluate categories or MITM enablement for termination.
        if self.policy_mode == crate::policy_config::PolicyMode::Sni {
            let decision = classify_tls_policy_decision(
                self.mitm_enabled,
                false,
                false,
                crate::policy_config::PolicyMode::Sni,
                false,
            );
            debug_assert!(!decision.mitm, "POLICY_MODE=sni must never terminate TLS");
            self.metrics
                .record_policy_decision_source(decision.decision_source);
            info!(
                domain = %domain,
                policy_mode = %self.policy_mode,
                decision_source = decision.decision_source,
                mitm = false,
                bypass_reason = decision.bypass_reason.unwrap_or("none"),
                "TLS policy decision"
            );
            return decision;
        }

        let pinned = self.pinning_registry.matches(domain);
        let tripped = self.mitm_circuit_breaker.is_tripped(domain);

        let selective_mitm = if self.mitm_enabled
            && !pinned
            && !tripped
            && self.policy_mode == crate::policy_config::PolicyMode::SelectiveMitm
        {
            let url = format!("https://{}", domain);
            let (categories, _) = self.policy_engine.categorize_url(&url);
            categories
                .iter()
                .any(|cat| self.mitm_categories.contains(&cat.to_ascii_lowercase()))
        } else {
            false
        };
        let decision = classify_tls_policy_decision(
            self.mitm_enabled,
            pinned,
            tripped,
            self.policy_mode,
            selective_mitm,
        );

        self.metrics
            .record_policy_decision_source(decision.decision_source);
        info!(
            domain = %domain,
            policy_mode = %self.policy_mode,
            decision_source = decision.decision_source,
            mitm = decision.mitm,
            bypass_reason = decision.bypass_reason.unwrap_or("none"),
            "TLS policy decision"
        );
        decision
    }

    pub fn should_mitm_domain(&self, domain: &str) -> bool {
        self.tls_policy_decision(domain).mitm
    }

    pub fn http_cache(&self) -> Arc<HttpL1Cache> {
        self.http_cache.clone()
    }

    pub fn casb_engine(&self) -> Arc<crate::casb::CasbEngine> {
        self.casb_engine.clone()
    }

    pub fn dlp_engine(&self) -> Arc<crate::dlp::DlpEngine> {
        self.dlp_engine.clone()
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

    pub fn policy_cache(&self) -> Arc<PolicyDecisionCache> {
        self.policy_engine.policy_cache()
    }

    pub fn upstream_client(&self) -> UpstreamClientHandle {
        self.http_client.clone()
    }

    /// Observe-only threat-intel matcher (issue #330).
    pub fn ti_shadow(&self) -> Arc<TiShadowMatcher> {
        self.ti_shadow.clone()
    }

    /// Threat-intel enforcement matcher (Phase 2 / ADR-0008).
    pub fn ti_enforce(&self) -> &Arc<TiEnforceMatcher> {
        self.policy_engine.ti_enforce()
    }

    pub fn pinning_registry(&self) -> Arc<PinningRegistry> {
        self.pinning_registry.clone()
    }

    pub fn mitm_circuit_breaker(&self) -> Arc<MitmCircuitBreaker> {
        self.mitm_circuit_breaker.clone()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cert_cache: CertCache,
        cache_config: CacheConfig,
        l2_cache: Option<RedisL2Cache>,
        #[cfg(feature = "kafka")] kafka_pipeline: Option<Arc<KafkaEventPipeline>>,
        http_pipeline: Option<Arc<HttpEventPipeline>>,
        metrics: Arc<Metrics>,
        mitm_enabled: bool,
        auth: Option<Arc<AuthManager>>,
        policy: &ProxyPolicy,
        hierarchy: Option<Arc<HierarchyManager>>,
        digest_registry: Option<Arc<DigestRegistry>>,
        rate_limit_config: crate::rate_limit::RateLimitConfig,
        upstream_tls: UpstreamTlsConfig,
        perf: PerfConfig,
        policy_cache: Arc<PolicyDecisionCache>,
        threat_score_cache: Arc<ThreatScoreCache>,
        reverse_proxy_config: Option<crate::reverse_proxy::ReverseProxyConfig>,
        ti_enforce: Arc<TiEnforceMatcher>,
    ) -> Self {
        let http_cache = Arc::new(HttpL1Cache::new(
            cache_config.capacity,
            cache_config.shard_count,
        ));

        let http_client =
            UpstreamClientHandle::new(upstream_tls).expect("failed to build upstream HTTPS client");
        let semantic_config = SemanticCacheConfig::from_env();
        let semantic_index = SemanticIndex::from_config(&semantic_config);
        let peer_tls = PeerTlsConfig::from_env();
        if let Err(e) = peer_tls.validate() {
            tracing::warn!("Hierarchy peer mTLS config invalid: {e}");
        }
        #[cfg(feature = "wasm")]
        let wasm_hook = try_load_from_env();
        let icap = IcapClient::try_from_env();

        let block_cloud_metadata = std::env::var("BLOCK_CLOUD_METADATA")
            .map(|v| {
                !matches!(
                    v.to_ascii_lowercase().as_str(),
                    "0" | "false" | "no" | "off"
                )
            })
            .unwrap_or(true);
        let block_loopback_forwarding = std::env::var("BLOCK_LOOPBACK_FORWARDING")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        let allowed_connect_ports = std::env::var("ALLOWED_CONNECT_PORTS")
            .ok()
            .map(|s| {
                s.split(',')
                    .filter_map(|p| p.trim().parse::<u16>().ok())
                    .collect::<Vec<u16>>()
            })
            .filter(|ports| !ports.is_empty());

        Self {
            cert_cache,
            http_cache,
            l2_cache,
            cache_config,
            #[cfg(feature = "kafka")]
            kafka_pipeline,
            http_pipeline,
            http_client,
            metrics: metrics.clone(),
            policy_mode: policy.policy_mode,
            mitm_categories: policy.mitm_categories.iter().cloned().collect(),
            pinning_registry: policy.pinning_registry.clone(),
            mitm_circuit_breaker: policy.mitm_circuit_breaker.clone(),
            mitm_enabled,
            auth,
            policy_engine: PolicyEngine::new(
                policy.acl_engine.clone(),
                policy.categorization.clone(),
                policy_cache,
                threat_score_cache,
                ti_enforce,
                metrics.clone(),
            ),
            hierarchy,
            digest_registry,
            rate_limiter: Arc::new(RateLimiter::new(rate_limit_config)),
            perf,
            sessions: Arc::new(SessionCorrelator::from_env()),
            ti_shadow: Arc::new(TiShadowMatcher::from_env()),
            miss_flights: MissFlightMap::new(),
            semantic_config,
            semantic_index,
            peer_tls,
            #[cfg(feature = "wasm")]
            wasm_hook,
            icap,
            dlp_engine: Arc::new(crate::dlp::DlpEngine::from_env()),
            casb_engine: Arc::new(crate::casb::CasbEngine::new()),
            reverse_proxy_config,
            block_cloud_metadata,
            block_loopback_forwarding,
            allowed_connect_ports,
        }
    }

    pub(crate) fn check_destination_security(
        &self,
        host: &str,
        port: u16,
    ) -> Result<(), &'static str> {
        crate::security_util::is_destination_allowed(
            host,
            port,
            self.block_cloud_metadata,
            self.block_loopback_forwarding,
            self.allowed_connect_ports.as_deref(),
        )
    }

    pub(crate) fn sessions(&self) -> Arc<SessionCorrelator> {
        self.sessions.clone()
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
        user_agent: Option<&str>,
        client_ip: &str,
        categories: &[String],
        threat_sources: &[String],
        request_start: Instant,
    ) {
        if !self.has_event_sink() {
            return;
        }
        if let Ok(timestamp) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            let event_id = new_event_id();
            let redirect_url = cached
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                .map(|(_, v)| resolve_location(url, v));
            let corr = self
                .sessions
                .begin_request(client_ip, username.as_deref(), user_agent, url);
            self.sessions.note_redirect(
                client_ip,
                &event_id,
                cached.status,
                url,
                redirect_url.as_deref(),
            );
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
                user_agent: user_agent.map(str::to_string),
                categories: categories.to_vec(),
                threat_sources: threat_sources.to_vec(),
                acl_action: None,
                acl_rule_id: None,
                acl_reason: None,
                session_id: corr.session_id,
                parent_event_id: corr.parent_event_id,
                redirect_url,
                dlp_violation: None,
                casb_alert: None,
                decision_source: Some(request_decision_source(url).to_string()),
                bypass_reason: None,
                threat_shadow_match: None,
                event_id,
            };
            self.send_cache_event(event);
        }
    }

    pub(crate) fn emit_policy_event(
        &self,
        decision: &AclDecision,
        policy: &PolicyEvaluation,
        context: PolicyEventContext<'_>,
    ) {
        let decision_source = effective_decision_source(decision, context.decision_source);
        self.metrics.record_policy_decision_source(decision_source);
        info!(
            domain = %context.domain,
            decision_source,
            action = %decision.action,
            "ACL policy decision"
        );
        if !self.has_event_sink() {
            return;
        }
        if let Some(event) = build_policy_event(&self.sessions, decision, policy, &context) {
            self.send_cache_event(event);
        }
    }

    pub fn check_policy(
        &self,
        url: &str,
        domain: &str,
        username: Option<&str>,
        groups: &[&str],
        client_ip: &str,
    ) -> PolicyEvaluation {
        self.policy_engine
            .evaluate(url, domain, username, groups, client_ip)
    }

    pub(crate) fn policy_response(decision: &AclDecision) -> Response<Body> {
        match decision.action {
            AclAction::Deny => {
                let body = format!("403 Forbidden: {}", decision.reason);
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("Content-Type", "text/plain; charset=utf-8")
                    .header("X-Content-Type-Options", "nosniff")
                    .header("X-Frame-Options", "DENY")
                    .body(full(Bytes::from(body)))
                    .unwrap_or_else(|_| Response::new(full(Bytes::from_static(b"403 Forbidden"))))
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
                    .body(empty())
                    .unwrap_or_else(|_| Response::new(empty()))
            }
            AclAction::Allow => Response::new(empty()),
        }
    }

    /// Optional Wasm request hook (feature `wasm`): after auth/RL, before ACL policy.
    /// Returns `Some(response)` when the guest denies (or hard-fails with fail_open=false).
    #[cfg(feature = "wasm")]
    pub(crate) fn run_wasm_hook(
        &self,
        method: &str,
        url: &str,
        client_ip: &str,
        username: Option<&str>,
        headers: &mut hyper::HeaderMap,
    ) -> Option<Response<Body>> {
        let Some(hook_arc) = &self.wasm_hook else {
            return None;
        };
        let hook = hook_arc.read().unwrap();
        let mut req_headers = HashMap::new();
        for (k, v) in headers.iter() {
            if let Ok(val_str) = v.to_str() {
                req_headers.insert(k.as_str().to_ascii_lowercase(), val_str.to_string());
            }
        }
        let decision = match hook.evaluate(WasmHookRequest {
            method: method.to_string(),
            url: url.to_string(),
            client_ip: client_ip.to_string(),
            username: username.map(str::to_string),
            headers: req_headers,
        }) {
            Ok(d) => d,
            Err(e) => {
                if hook.fail_open() {
                    warn!("Wasm hook error (fail-open): {e}");
                    return None;
                }
                warn!("Wasm hook error (fail-closed): {e}");
                return Some(
                    Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .header("Content-Type", "text/plain; charset=utf-8")
                        .body(full(Bytes::from(format!(
                            "502 Bad Gateway: wasm hook: {e}"
                        ))))
                        .unwrap_or_else(|_| {
                            Response::new(full(Bytes::from_static(b"502 Bad Gateway")))
                        }),
                );
            }
        };
        match decision {
            WasmHookDecision::Allow { set_headers } => {
                for (name, value) in set_headers {
                    if let (Ok(hn), Ok(hv)) = (
                        HeaderName::from_bytes(name.as_bytes()),
                        HeaderValue::from_str(&value),
                    ) {
                        headers.insert(hn, hv);
                    }
                }
                None
            }
            WasmHookDecision::Deny { reason } => {
                debug!("Wasm hook deny: {reason}");
                Some(
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header("Content-Type", "text/plain; charset=utf-8")
                        .header("X-Wasm-Hook", "deny")
                        .body(full(Bytes::from(format!("403 Forbidden: {reason}"))))
                        .unwrap_or_else(|_| {
                            Response::new(full(Bytes::from_static(b"403 Forbidden")))
                        }),
                )
            }
        }
    }

    #[cfg(feature = "wasm")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn run_wasm_hook_response(
        &self,
        method: &str,
        url: &str,
        client_ip: &str,
        username: Option<&str>,
        req_headers: &hyper::HeaderMap,
        resp_status: u16,
        resp_headers: &mut hyper::HeaderMap,
    ) {
        let Some(hook_arc) = &self.wasm_hook else {
            return;
        };
        let hook = hook_arc.read().unwrap();

        let mut req_hdrs = HashMap::new();
        for (k, v) in req_headers.iter() {
            if let Ok(val_str) = v.to_str() {
                req_hdrs.insert(k.as_str().to_ascii_lowercase(), val_str.to_string());
            }
        }
        let request = WasmHookRequest {
            method: method.to_string(),
            url: url.to_string(),
            client_ip: client_ip.to_string(),
            username: username.map(str::to_string),
            headers: req_hdrs,
        };

        let mut res_hdrs = HashMap::new();
        for (k, v) in resp_headers.iter() {
            if let Ok(val_str) = v.to_str() {
                res_hdrs.insert(k.as_str().to_ascii_lowercase(), val_str.to_string());
            }
        }
        let response = crate::wasm_host::WasmHookResponseContext {
            status: resp_status,
            headers: res_hdrs,
        };

        let decision = match hook.evaluate_response(request, response) {
            Ok(d) => d,
            Err(e) => {
                if !hook.fail_open() {
                    warn!("Wasm response hook error (fail-closed, but too late to drop body cleanly): {e}");
                } else {
                    warn!("Wasm response hook error (fail-open): {e}");
                }
                return;
            }
        };

        match decision {
            crate::wasm_host::WasmHookResponseDecision::Continue { set_headers } => {
                for (name, value) in set_headers {
                    if let (Ok(hn), Ok(hv)) = (
                        HeaderName::from_bytes(name.as_bytes()),
                        HeaderValue::from_str(&value),
                    ) {
                        resp_headers.insert(hn, hv);
                    }
                }
            }
        }
    }

    /// CONNECT path: evaluate Wasm hook (no request header rewrite needed).
    #[cfg(feature = "wasm")]
    pub(crate) fn run_wasm_hook_connect(
        &self,
        method: &str,
        url: &str,
        client_ip: &str,
        username: Option<&str>,
    ) -> Option<Response<Body>> {
        let mut headers = hyper::HeaderMap::new();
        self.run_wasm_hook(method, url, client_ip, username, &mut headers)
    }

    /// Map ICAP HTTP response / errors into a client `Response`.
    fn icap_to_response(&self, outcome: Result<IcapOutcome, String>) -> Option<Response<Body>> {
        match outcome {
            Ok(IcapOutcome::Allow) => None,
            Ok(IcapOutcome::HttpResponse {
                status,
                headers,
                body,
            }) => {
                let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
                let mut resp = Response::new(full(body));
                *resp.status_mut() = status_code;
                Self::apply_response_headers(&headers, &mut resp);
                resp.headers_mut().insert(
                    HeaderName::from_static("x-icap-action"),
                    HeaderValue::from_static("adapted"),
                );
                Some(resp)
            }
            Err(e) => {
                let Some(client) = &self.icap else {
                    return None;
                };
                if client.fail_open() {
                    warn!("ICAP error (fail-open): {e}");
                    None
                } else {
                    warn!("ICAP error (fail-closed): {e}");
                    Some(
                        Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .header("Content-Type", "text/plain; charset=utf-8")
                            .header("X-Icap-Action", "error")
                            .body(full(Bytes::from(format!("502 Bad Gateway: icap: {e}"))))
                            .unwrap_or_else(|_| {
                                Response::new(full(Bytes::from_static(b"502 Bad Gateway")))
                            }),
                    )
                }
            }
        }
    }

    /// REQMOD after request body is available (before upstream/peer fetch).
    async fn run_icap_reqmod(
        &self,
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> Option<Response<Body>> {
        let Some(client) = &self.icap else {
            return None;
        };
        if !client.reqmod_enabled() {
            return None;
        }
        self.icap_to_response(client.reqmod(method, url, headers, body).await)
    }

    /// RESPMOD on buffered upstream response (streaming MISS not adapted).
    async fn run_icap_respmod(
        &self,
        method: &str,
        url: &str,
        req_headers: &HashMap<String, String>,
        status: u16,
        resp_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> Option<(u16, HashMap<String, String>, Bytes)> {
        let Some(client) = &self.icap else {
            return None;
        };
        if !client.respmod_enabled() {
            return None;
        }
        match client
            .respmod(method, url, req_headers, status, resp_headers, body)
            .await
        {
            Ok(IcapOutcome::Allow) => None,
            Ok(IcapOutcome::HttpResponse {
                status,
                headers,
                body,
            }) => Some((status, headers, body)),
            Err(e) => {
                if client.fail_open() {
                    warn!("ICAP RESPMOD error (fail-open): {e}");
                    None
                } else {
                    warn!("ICAP RESPMOD error (fail-closed): {e}");
                    Some((
                        502,
                        HashMap::from([(
                            "content-type".into(),
                            "text/plain; charset=utf-8".into(),
                        )]),
                        Bytes::from(format!("502 Bad Gateway: icap: {e}")),
                    ))
                }
            }
        }
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
        let tls = if self.peer_tls.enabled {
            Some(&self.peer_tls)
        } else {
            None
        };
        match fetch_via_peer(&peer, req, timeout, tls).await {
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

    /// Whether any analytics sink is configured.
    ///
    /// Building a `CacheEvent` costs ~20 allocations plus session-correlator
    /// bookkeeping. With no sink wired up (the lite / no-analytics deployment)
    /// every one of those events is dropped, so callers check this before doing
    /// the work rather than after.
    #[inline]
    pub(crate) fn has_event_sink(&self) -> bool {
        #[cfg(feature = "kafka")]
        if self.kafka_pipeline.is_some() {
            return true;
        }
        self.http_pipeline.is_some()
    }

    pub(crate) fn send_cache_event(&self, mut event: CacheEvent) {
        crate::ti_shadow::annotate_shadow_match(&self.ti_shadow, &self.metrics, &mut event);
        if !self.perf.should_emit_kafka_event() {
            return;
        }
        dispatch_cache_event(
            #[cfg(feature = "kafka")]
            self.kafka_pipeline.as_deref(),
            self.http_pipeline.as_deref(),
            event,
            &self.metrics,
        );
    }

    pub async fn flush_kafka(&self, timeout: Duration) {
        #[cfg(feature = "kafka")]
        {
            let Some(pipeline) = self.kafka_pipeline.as_ref() else {
                return;
            };
            flush_kafka(pipeline.producer(), timeout).await;
        }
        #[cfg(not(feature = "kafka"))]
        let _ = timeout;
    }

    /// Whether an ICAP stage will read the request headers on this request.
    #[inline]
    fn icap_wants_request_headers(&self) -> bool {
        self.icap
            .as_ref()
            .is_some_and(|client| client.reqmod_enabled() || client.respmod_enabled())
    }

    #[allow(clippy::too_many_arguments)]
    fn complete_cache_miss(
        &self,
        cache_key: Arc<str>,
        url: &str,
        method: &str,
        domain: &str,
        status: u16,
        headers_map: &HashMap<String, String>,
        body_bytes: Bytes,
        store_decision: &crate::cache_freshness::CacheStoreDecision,
        stored: bool,
        user_id: Option<String>,
        username: Option<String>,
        user_agent: Option<String>,
        client_ip: &str,
        categories: &[String],
        threat_sources: &[String],
        request_start: Instant,
        request_body_size: usize,
        hierarchy_peer: Option<Arc<CachePeer>>,
        guard: Option<RequestMetricsGuard>,
        fast_scope: Option<FastRequestScope>,
    ) -> &'static str {
        let stored_and_cached = stored && store_decision.store;
        self.miss_completion_handle().complete_cache_miss(
            cache_key,
            url,
            method,
            domain,
            status,
            headers_map,
            body_bytes,
            store_decision,
            stored,
            user_id,
            username,
            user_agent,
            client_ip,
            categories,
            threat_sources,
            request_start,
            request_body_size,
            hierarchy_peer,
            guard,
            fast_scope,
        );
        if stored_and_cached {
            if store_decision.is_negative {
                "NEGATIVE_MISS"
            } else {
                "MISS"
            }
        } else {
            "BYPASS"
        }
    }

    pub(crate) async fn handle_request(
        &self,
        mut req: Request<Incoming>,
        client_ip: &str,
        mut proxy_user: Option<Arc<UserInfo>>,
    ) -> Response<Body> {
        let mut rp_username = None;
        if let Some(rp_config) = &self.reverse_proxy_config {
            // Маршруты входа (/-/login, /-/callback, /-/logout) обслуживает
            // сам reverse-proxy и наверх не отдаёт.
            if crate::reverse_proxy::ReverseProxyConfig::is_auth_path(req.uri().path()) {
                return rp_config.handle_auth_route(req).await;
            }

            let session_id = crate::reverse_proxy::ReverseProxyConfig::extract_session_cookie(&req);
            rp_username = session_id.and_then(|id| rp_config.get_session(&id));

            if rp_username.is_none() {
                // Try AuthManager for AD / HTTP Basic / Negotiate
                if let Some(auth) = &self.auth {
                    if auth.is_enabled() {
                        match auth.handle_proxy_auth(client_ip, &req, None, true).await {
                            crate::auth::ProxyAuthOutcome::Authenticated(user) => {
                                let mut allowed = true;
                                if let Some(admin_group) = &rp_config.admin_group {
                                    if !user.groups.contains(admin_group) {
                                        allowed = false;
                                    }
                                }

                                if allowed {
                                    let session_id =
                                        rp_config.create_session(user.username.clone());
                                    let path_query = req
                                        .uri()
                                        .path_and_query()
                                        .map(|pq| pq.as_str())
                                        .unwrap_or("/");
                                    return hyper::Response::builder()
                                        .status(hyper::StatusCode::FOUND)
                                        .header(hyper::header::LOCATION, path_query)
                                        .header(
                                            hyper::header::SET_COOKIE,
                                            format!(
                                                "bsdm_session={}; Path=/; HttpOnly",
                                                session_id
                                            ),
                                        )
                                        .body(crate::http_types::empty())
                                        .unwrap();
                                } else {
                                    return hyper::Response::builder()
                                        .status(hyper::StatusCode::FORBIDDEN)
                                        .body(crate::http_types::full(bytes::Bytes::from(
                                            "403 Forbidden: User not in required AD group",
                                        )))
                                        .unwrap();
                                }
                            }
                            crate::auth::ProxyAuthOutcome::Challenge {
                                authenticate_header,
                            } => {
                                return auth
                                    .create_auth_challenge_response(authenticate_header, true);
                            }
                            crate::auth::ProxyAuthOutcome::Anonymous => {}
                        }
                    }
                }

                return rp_config.handle_unauthenticated(&req).await;
            }

            let upstream_base = &rp_config.upstream_url;
            let path_and_query = req
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("");
            let new_uri_str = format!("{}{}", upstream_base.trim_end_matches('/'), path_and_query);
            if let Ok(new_uri) = new_uri_str.parse::<hyper::Uri>() {
                *req.uri_mut() = new_uri;
            }

            if let Some(user) = &rp_username {
                if let Ok(val) = hyper::header::HeaderValue::from_str(user) {
                    req.headers_mut().insert("x-forwarded-user", val);
                }
            }
        }

        if let Some(user) = &rp_username {
            proxy_user = Some(Arc::new(crate::auth::UserInfo {
                username: user.clone(),
                display_name: None,
                email: None,
                groups: vec!["reverse_proxy_users".to_string()],
                authenticated_at: std::time::Instant::now(),
            }));
        }
        let detailed_metrics = self.perf.record_detailed_metrics();
        let http_method = req.method().clone();
        let method = http_method.as_str();
        let url = req.uri().to_string();
        let mut req = Some(req);

        let mut guard = if detailed_metrics {
            Some(RequestMetricsGuard::new(
                self.metrics.clone(),
                method_metric_label(&http_method),
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
        let llm_mode = self.semantic_config.applies(method, &url);

        let mut cache_key = self.generate_cache_key(method, &url);

        let req_ref = req.as_ref().expect("request present");
        let (user_id, username) = if let Some(user) = proxy_user.as_deref() {
            Self::user_fields(Some(user))
        } else {
            Self::extract_user_info(req_ref)
        };
        let user_agent = Self::request_header_str(req_ref, "user-agent");

        if let Some(resp) = self.check_rate_limit(client_ip, username.as_deref(), req_ref.headers())
        {
            let code = resp.status().as_u16();
            if let Some(g) = guard.take() {
                g.finish(code, 0, 0);
            } else if let Some(scope) = fast_scope.take() {
                scope.finish(code);
            }
            return resp;
        }

        if self.perf.skip_policy_on_cache_serve() && !llm_mode {
            if let Some(resp) = self
                .try_serve_cache_before_policy(
                    req.as_ref().expect("request present"),
                    &cache_key,
                    &url,
                    method,
                    client_ip,
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

        let user_groups: Vec<&str> = proxy_user
            .as_deref()
            .map(|u| u.groups.iter().map(String::as_str).collect())
            .unwrap_or_default();

        #[cfg(feature = "wasm")]
        {
            let req_mut = req.as_mut().expect("request present");
            if let Some(resp) = self.run_wasm_hook(
                method,
                &url,
                client_ip,
                username.as_deref(),
                req_mut.headers_mut(),
            ) {
                let code = resp.status().as_u16();
                if let Some(g) = guard.take() {
                    g.finish(code, 0, 0);
                } else if let Some(scope) = fast_scope.take() {
                    scope.finish(code);
                }
                return resp;
            }
        }

        let domain = Self::extract_domain(&url);
        let (host_dest, port_dest) = req
            .as_ref()
            .and_then(|r| r.uri().authority())
            .map(|a| crate::tls::parse_authority(a.as_str()))
            .unwrap_or_else(|| (domain.to_string(), 80));
        if let Err(reason) = self.check_destination_security(&host_dest, port_dest) {
            warn!(%url, %reason, "Request blocked by destination security policy");
            self.metrics
                .ssrf_blocked_total
                .with_label_values(&[reason])
                .inc();
            let response = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "text/plain; charset=utf-8")
                .header("X-Content-Type-Options", "nosniff")
                .header("X-Frame-Options", "DENY")
                .body(full(Bytes::from(format!("403 Forbidden: {reason}"))))
                .unwrap_or_else(|_| Response::new(full(Bytes::from_static(b"403 Forbidden"))));
            let code = response.status().as_u16();
            if let Some(g) = guard.take() {
                g.finish(code, 0, 0);
            } else if let Some(scope) = fast_scope.take() {
                scope.finish(code);
            }
            return response;
        }
        let policy = self.check_policy(&url, &domain, username.as_deref(), &user_groups, client_ip);
        if let Some(decision) = policy.blocking.as_ref() {
            self.emit_policy_event(
                decision,
                &policy,
                PolicyEventContext {
                    url: &url,
                    method,
                    cache_key: cache_key.as_ref(),
                    user_id: &user_id,
                    username: &username,
                    user_agent: user_agent.as_deref(),
                    client_ip,
                    domain: &domain,
                    request_start,
                    decision_source: request_decision_source(&url),
                },
            );
            let response = Self::policy_response(decision);
            if let Some(g) = guard.take() {
                g.finish(response.status().as_u16(), 0, 0);
            } else if let Some(scope) = fast_scope.take() {
                scope.finish(response.status().as_u16());
            }
            return response;
        }

        let categories = policy.categories;
        let threat_sources = policy.threat_sources;

        let cache_lookup_start = Instant::now();
        let mut early_body = None::<(hyper::http::request::Parts, Bytes)>;
        let mut llm_normalized: Option<Bytes> = None;

        if llm_mode {
            let (parts, body) = req.take().expect("request present").into_parts();
            let is_casb = self.casb_engine.is_llm_provider(&domain);
            let dlp_body = crate::dlp::DlpBodyStream::new(body, self.dlp_engine.clone());
            let body_bytes = match http_body_util::BodyExt::collect(dlp_body).await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    let err_msg = e.to_string();
                    error!("LLM body collection failed: {}", err_msg);
                    if err_msg.contains("DLP Violation") {
                        let mut resp = Response::new(full(Bytes::from_static(
                            b"403 Forbidden: DLP Violation",
                        )));
                        *resp.status_mut() = StatusCode::FORBIDDEN;
                        Self::finish_request_metrics(&mut guard, &mut fast_scope, 403, 0, 30);

                        if self.has_event_sink() {
                            let event = CacheEvent {
                                url: url.to_string(),
                                method: method.to_string(),
                                status: 403,
                                cache_key: cache_key.to_string(),
                                cache_status: "BLOCKED".to_string(),
                                timestamp: SystemTime::now()
                                    .duration_since(SystemTime::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                                headers: parts
                                    .headers
                                    .iter()
                                    .filter_map(|(k, v)| {
                                        v.to_str()
                                            .ok()
                                            .map(|s| (k.as_str().to_string(), s.to_string()))
                                    })
                                    .collect(),
                                user_id: user_id.clone(),
                                username: username.clone(),
                                client_ip: client_ip.to_string(),
                                domain: domain.to_string(),
                                response_size: 30,
                                request_duration_ms: request_start.elapsed().as_millis() as u64,
                                content_type: None,
                                user_agent: user_agent.clone(),
                                categories: categories.to_vec(),
                                threat_sources: threat_sources.to_vec(),
                                acl_action: Some("deny".to_string()),
                                acl_rule_id: None,
                                acl_reason: Some(err_msg.clone()),
                                session_id: String::new(),
                                parent_event_id: None,
                                redirect_url: None,
                                dlp_violation: Some(err_msg.clone()),
                                casb_alert: if is_casb {
                                    Some("GenAI Leak Prevented".to_string())
                                } else {
                                    None
                                },
                                decision_source: Some("mitm".to_string()),
                                bypass_reason: None,
                                threat_shadow_match: None,
                                event_id: new_event_id(),
                            };
                            self.send_cache_event(event);
                        }

                        return resp;
                    }

                    let mut resp = Response::new(full(Bytes::from_static(b"400 Bad Request")));
                    *resp.status_mut() = StatusCode::BAD_REQUEST;
                    Self::finish_request_metrics(&mut guard, &mut fast_scope, 400, 0, 15);
                    return resp;
                }
            };
            let normalized = Bytes::from(normalize_llm_body(&body_bytes));
            cache_key = content_cache_key(method, &url, &normalized);

            if let Some(cached) = self.http_cache.get(&cache_key) {
                if cached.can_serve_fresh() {
                    debug!("LLM cache exact HIT: {} {}", method, url);
                    self.metrics.semantic_cache_exact_hits_total.inc();
                    return self.serve_l1_hit(
                        &cached,
                        &cache_key,
                        &url,
                        method,
                        &user_id,
                        &username,
                        user_agent.as_deref(),
                        client_ip,
                        &categories,
                        &threat_sources,
                        request_start,
                        detailed_metrics,
                        &mut guard,
                        &mut fast_scope,
                        "LLM_HIT",
                        "LLM-HIT",
                    );
                }
            }

            if self.semantic_config.near_hit_enabled() {
                let text = extract_embed_text(&normalized);
                match self.semantic_config.embed(&text).await {
                    Ok(emb) => {
                        match self
                            .semantic_index
                            .find_similar(&emb, self.semantic_config.similarity_threshold)
                            .await
                        {
                            Ok(Some(near_key)) => {
                                if let Some(cached) = self.http_cache.get(&near_key) {
                                    if cached.can_serve_fresh() {
                                        debug!("LLM cache semantic HIT: {} {}", method, url);
                                        self.metrics.semantic_cache_similar_hits_total.inc();
                                        return self.serve_l1_hit(
                                            &cached,
                                            &near_key,
                                            &url,
                                            method,
                                            &user_id,
                                            &username,
                                            user_agent.as_deref(),
                                            client_ip,
                                            &categories,
                                            &threat_sources,
                                            request_start,
                                            detailed_metrics,
                                            &mut guard,
                                            &mut fast_scope,
                                            "SEMANTIC_HIT",
                                            "SEMANTIC-HIT",
                                        );
                                    }
                                }
                            }
                            Ok(None) => {}
                            Err(e) => {
                                self.metrics.semantic_cache_vector_errors_total.inc();
                                warn!("semantic index search failed: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        self.metrics.semantic_cache_vector_errors_total.inc();
                        warn!("semantic embed failed: {e}");
                    }
                }
            }

            llm_normalized = Some(normalized);
            early_body = Some((parts, body_bytes));
            if detailed_metrics {
                self.metrics
                    .cache_lookup_duration_seconds
                    .observe(cache_lookup_start.elapsed().as_secs_f64());
            }
        } else if let Some(cached) = self.http_cache.get(&cache_key) {
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
                    user_agent.as_deref(),
                    client_ip,
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
                    req.as_ref().expect("request present"),
                    &cache_key,
                    &url,
                    method,
                    &user_id,
                    &username,
                    client_ip,
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

        if !llm_mode {
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
                        user_agent.as_deref(),
                        client_ip,
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
        }

        // Collapse concurrent identical GET/HEAD MISSes onto one upstream fill.
        let mut flight_permit: Option<MissFlightPermit> = None;
        if self.perf.miss_coalesce_enabled && CACHEABLE_METHODS.contains(&method) && !llm_mode {
            match self.miss_flights.join(&cache_key) {
                CoalesceJoin::Follower(wait) => {
                    if let Some(cached) = wait.wait().await {
                        debug!("Cache COALESCED HIT: {} {}", method, url);
                        self.metrics.cache_coalesced_total.inc();
                        return self.serve_l1_hit(
                            &cached,
                            &cache_key,
                            &url,
                            method,
                            &user_id,
                            &username,
                            user_agent.as_deref(),
                            client_ip,
                            &categories,
                            &threat_sources,
                            request_start,
                            detailed_metrics,
                            &mut guard,
                            &mut fast_scope,
                            "COALESCED",
                            "COALESCED-HIT",
                        );
                    }
                    // Leader failed / bypassed — check L1 then fetch without coalescing.
                    if let Some(cached) = self.http_cache.get(&cache_key) {
                        if cached.can_serve_fresh() {
                            return self.serve_l1_hit(
                                &cached,
                                &cache_key,
                                &url,
                                method,
                                &user_id,
                                &username,
                                user_agent.as_deref(),
                                client_ip,
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
                    }
                }
                CoalesceJoin::Leader(permit) => {
                    flight_permit = Some(permit);
                }
            }
        }

        debug!("Cache MISS: {} {}", method, url);
        self.metrics.cache_misses_total.inc();

        let (mut parts, body_bytes) = if let Some(early) = early_body.take() {
            early
        } else {
            let (parts, body) = req.take().expect("request present").into_parts();
            let is_casb = self.casb_engine.is_llm_provider(&domain);
            let dlp_body = crate::dlp::DlpBodyStream::new(body, self.dlp_engine.clone());
            let body_bytes = match http_body_util::BodyExt::collect(dlp_body).await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    let err_msg = e.to_string();
                    error!("Body collection failed: {}", err_msg);
                    if let Some(permit) = flight_permit.take() {
                        permit.complete(None);
                    }
                    if err_msg.contains("DLP Violation") {
                        let mut resp = Response::new(full(Bytes::from_static(
                            b"403 Forbidden: DLP Violation",
                        )));
                        *resp.status_mut() = StatusCode::FORBIDDEN;
                        Self::finish_request_metrics(&mut guard, &mut fast_scope, 403, 0, 30);

                        if self.has_event_sink() {
                            let event = CacheEvent {
                                url: url.to_string(),
                                method: method.to_string(),
                                status: 403,
                                cache_key: cache_key.to_string(),
                                cache_status: "BLOCKED".to_string(),
                                timestamp: SystemTime::now()
                                    .duration_since(SystemTime::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                                headers: parts
                                    .headers
                                    .iter()
                                    .filter_map(|(k, v)| {
                                        v.to_str()
                                            .ok()
                                            .map(|s| (k.as_str().to_string(), s.to_string()))
                                    })
                                    .collect(),
                                user_id: user_id.clone(),
                                username: username.clone(),
                                client_ip: client_ip.to_string(),
                                domain: domain.to_string(),
                                response_size: 30,
                                request_duration_ms: request_start.elapsed().as_millis() as u64,
                                content_type: None,
                                user_agent: user_agent.clone(),
                                categories: categories.to_vec(),
                                threat_sources: threat_sources.to_vec(),
                                acl_action: Some("deny".to_string()),
                                acl_rule_id: None,
                                acl_reason: Some(err_msg.clone()),
                                session_id: String::new(),
                                parent_event_id: None,
                                redirect_url: None,
                                dlp_violation: Some(err_msg.clone()),
                                casb_alert: if is_casb {
                                    Some("GenAI Leak Prevented".to_string())
                                } else {
                                    None
                                },
                                decision_source: Some("mitm".to_string()),
                                bypass_reason: None,
                                threat_shadow_match: None,
                                event_id: new_event_id(),
                            };
                            if !event.session_id.is_empty() {
                                self.sessions.begin_request(
                                    client_ip,
                                    username.as_deref(),
                                    user_agent.as_deref(),
                                    &url,
                                );
                            }
                            self.send_cache_event(event);
                        }

                        return resp;
                    }

                    let mut resp = Response::new(full(Bytes::from_static(b"400 Bad Request")));
                    *resp.status_mut() = StatusCode::BAD_REQUEST;
                    Self::finish_request_metrics(&mut guard, &mut fast_scope, 400, 0, 15);
                    return resp;
                }
            };
            (parts, body_bytes)
        };
        let request_body_size = body_bytes.len();

        // ICAP REQMOD (optional): before peer/upstream fetch. ICAP is opt-in, so
        // the header map is only materialized when an adaptation stage will
        // actually read it — otherwise it was two allocations per header on
        // every MISS, discarded unread.
        let icap_req_headers: HashMap<String, String> = if self.icap_wants_request_headers() {
            Self::headers_map_from_parts(&parts)
        } else {
            HashMap::new()
        };
        if let Some(resp) = self
            .run_icap_reqmod(method, &url, &icap_req_headers, &body_bytes)
            .await
        {
            if let Some(permit) = flight_permit.take() {
                permit.complete(None);
            }
            let code = resp.status().as_u16();
            Self::finish_request_metrics(&mut guard, &mut fast_scope, code, request_body_size, 0);
            return resp;
        }

        // The body has been buffered, and the client's `Proxy-Authorization`
        // addresses *this* proxy, so neither the peer nor the origin may see
        // the connection-specific headers the client sent us. Stripped after
        // ICAP so an adaptation service still inspects the request as received.
        strip_hop_by_hop_request_headers(&mut parts.headers);

        // Cloning the parts deep-copies every request header. Only a hierarchy
        // peer fetch needs that second copy, so skip it when no hierarchy is
        // configured or the request can never go to a peer.
        let peer_fetch_possible =
            !llm_mode && self.hierarchy.is_some() && CACHEABLE_METHODS.contains(&method);
        let req_for_peer = peer_fetch_possible
            .then(|| Request::from_parts(parts.clone(), full(body_bytes.clone())));
        let req = Request::from_parts(parts, full(body_bytes));

        let upstream_start = Instant::now();

        let peer_fetch = match req_for_peer {
            Some(req_for_peer) => {
                self.try_fetch_via_hierarchy(method, &url, req_for_peer)
                    .await
            }
            None => None,
        };
        let hierarchy_peer = peer_fetch.as_ref().map(|(peer, _)| peer.clone());

        let fetch_result = if let Some((_, response)) = peer_fetch {
            Ok(response)
        } else {
            self.http_client.load().request(req).await
        };

        match fetch_result {
            Ok(response) => {
                let upstream_duration = upstream_start.elapsed().as_secs_f64();
                let status = response.status();
                let status_code = status.as_u16();

                self.metrics.record_upstream_request(
                    domain.as_str(),
                    StatusLabel::new(status_code).as_str(),
                );
                self.metrics
                    .record_upstream_duration(&domain, upstream_duration);

                let headers_map = Self::headers_map_from_response(&response);
                let store_precheck = if llm_mode {
                    evaluate_llm_store(
                        status_code,
                        0,
                        self.cache_config.max_body_size,
                        self.semantic_config.ttl,
                    )
                } else {
                    evaluate_store_precheck(method, status_code, &headers_map, &self.cache_config)
                };

                if self.perf.streaming_miss_enabled {
                    let upstream_body = response.into_body();
                    let x_cache = if llm_mode && store_precheck.store {
                        "LLM-MISS-STREAMING"
                    } else {
                        miss_x_cache_status_header(true, &store_precheck)
                    };
                    if let Some(g) = guard.as_mut() {
                        g.set_cache_status(cache_status_metric_label(x_cache));
                    }

                    // Completion path finishes the flight; disarm Drop.
                    if let Some(permit) = flight_permit.take() {
                        permit.disarm();
                    }

                    let handle = if llm_mode {
                        self.miss_completion_handle_llm(llm_normalized.clone().unwrap_or_default())
                    } else {
                        self.miss_completion_handle()
                    };
                    let cache_key_cb = cache_key.clone();
                    let url_cb = url.clone();
                    let method_cb = method.to_string();
                    let domain_cb = domain.clone();
                    let headers_cb = headers_map.clone();
                    let store_precheck_cb = store_precheck.clone();
                    let user_id_cb = user_id.clone();
                    let username_cb = username.clone();
                    let user_agent_cb = user_agent.clone();
                    let client_ip_cb = client_ip.to_string();
                    let categories_cb = categories.clone();
                    let threat_sources_cb = threat_sources.clone();
                    let hierarchy_peer_cb = hierarchy_peer.clone();
                    let mut guard_cb = guard.take();
                    let mut fast_scope_cb = fast_scope.take();

                    let tee = TeeMissBody::new(
                        upstream_body,
                        store_precheck.store,
                        self.cache_config.max_body_size,
                        move |body_bytes, stored| {
                            let final_decision = if !stored {
                                crate::cache_freshness::CacheStoreDecision::bypass()
                            } else if handle.llm_mode {
                                evaluate_llm_store(
                                    status_code,
                                    body_bytes.len(),
                                    handle.cache_config.max_body_size,
                                    handle.semantic_config.ttl,
                                )
                            } else {
                                evaluate_store(
                                    &method_cb,
                                    status_code,
                                    &headers_cb,
                                    body_bytes.len(),
                                    &handle.cache_config,
                                )
                            };
                            handle.complete_cache_miss(
                                cache_key_cb,
                                &url_cb,
                                &method_cb,
                                &domain_cb,
                                status_code,
                                &headers_cb,
                                body_bytes,
                                &final_decision,
                                stored && final_decision.store,
                                user_id_cb,
                                username_cb,
                                user_agent_cb,
                                &client_ip_cb,
                                &categories_cb,
                                &threat_sources_cb,
                                request_start,
                                request_body_size,
                                hierarchy_peer_cb,
                                guard_cb.take(),
                                fast_scope_cb.take(),
                            );
                            let _ = store_precheck_cb;
                        },
                    );

                    let mut resp = Response::new(tee.boxed());
                    *resp.status_mut() = status;
                    Self::apply_response_headers(&headers_map, &mut resp);
                    Self::attach_x_cache_status(&mut resp, x_cache);
                    return resp;
                }

                let body_bytes = match http_body_util::BodyExt::collect(response.into_body()).await
                {
                    Ok(collected) => collected.to_bytes(),
                    Err(e) => {
                        error!("Response body collection failed: {}", e);
                        if let Some(permit) = flight_permit.take() {
                            permit.complete(None);
                        }
                        self.metrics
                            .record_upstream_error(domain.as_str(), "body_read");
                        let mut resp = Response::new(full(Bytes::from_static(b"502 Bad Gateway")));
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

                // ICAP RESPMOD (optional, buffered path only).
                let (status_code, headers_map, body_bytes) = if let Some((st, hdrs, body)) = self
                    .run_icap_respmod(
                        method,
                        &url,
                        &icap_req_headers,
                        status_code,
                        &headers_map,
                        &body_bytes,
                    )
                    .await
                {
                    (st, hdrs, body)
                } else {
                    (status_code, headers_map, body_bytes)
                };
                let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::OK);

                // Buffered path: complete_cache_miss finishes the flight; disarm Drop.
                if let Some(permit) = flight_permit.take() {
                    permit.disarm();
                }

                let store_decision = if llm_mode {
                    evaluate_llm_store(
                        status_code,
                        body_bytes.len(),
                        self.cache_config.max_body_size,
                        self.semantic_config.ttl,
                    )
                } else {
                    evaluate_store(
                        method,
                        status_code,
                        &headers_map,
                        body_bytes.len(),
                        &self.cache_config,
                    )
                };
                if llm_mode {
                    self.miss_completion_handle_llm(llm_normalized.clone().unwrap_or_default())
                        .complete_cache_miss(
                            cache_key,
                            &url,
                            method,
                            &domain,
                            status_code,
                            &headers_map,
                            body_bytes.clone(),
                            &store_decision,
                            store_decision.store,
                            user_id,
                            username,
                            user_agent,
                            client_ip,
                            &categories,
                            &threat_sources,
                            request_start,
                            request_body_size,
                            hierarchy_peer,
                            guard.take(),
                            fast_scope.take(),
                        );
                } else {
                    let _cache_status = self.complete_cache_miss(
                        cache_key,
                        &url,
                        method,
                        &domain,
                        status_code,
                        &headers_map,
                        body_bytes.clone(),
                        &store_decision,
                        store_decision.store,
                        user_id,
                        username,
                        user_agent,
                        client_ip,
                        &categories,
                        &threat_sources,
                        request_start,
                        request_body_size,
                        hierarchy_peer,
                        guard.take(),
                        fast_scope.take(),
                    );
                }

                let mut resp = Response::new(full(body_bytes));
                *resp.status_mut() = status;
                Self::apply_response_headers(&headers_map, &mut resp);
                let header_label = if llm_mode && store_decision.store {
                    "LLM-MISS"
                } else {
                    miss_x_cache_status_header(false, &store_decision)
                };
                Self::attach_x_cache_status(&mut resp, header_label);
                resp
            }
            Err(e) => {
                error!("Upstream error for {}: {}", url, e);
                if let Some(permit) = flight_permit.take() {
                    permit.complete(None);
                }
                self.metrics
                    .record_upstream_error(domain.as_str(), "connection");
                let mut response = Response::new(full(Bytes::from_static(b"502 Bad Gateway")));
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

#[cfg(test)]
mod decision_source_tests {
    use super::{
        classify_tls_policy_decision, request_decision_source, ProxyService, TlsPolicyDecision,
    };
    use crate::policy_config::PolicyMode;

    #[test]
    fn classifies_all_policy_modes_and_bypasses() {
        let cases = [
            (
                false,
                false,
                false,
                PolicyMode::FullMitm,
                false,
                TlsPolicyDecision {
                    mitm: false,
                    decision_source: "sni",
                    bypass_reason: Some("mitm_disabled"),
                },
            ),
            (
                true,
                true,
                false,
                PolicyMode::FullMitm,
                false,
                TlsPolicyDecision {
                    mitm: false,
                    decision_source: "pinning-bypass",
                    bypass_reason: Some("certificate_pinning_exception"),
                },
            ),
            (
                true,
                false,
                true,
                PolicyMode::FullMitm,
                false,
                TlsPolicyDecision {
                    mitm: false,
                    decision_source: "pinning-bypass",
                    bypass_reason: Some("circuit_breaker_tripped"),
                },
            ),
            (
                true,
                false,
                false,
                PolicyMode::Sni,
                false,
                TlsPolicyDecision {
                    mitm: false,
                    decision_source: "sni",
                    bypass_reason: Some("policy_mode_sni"),
                },
            ),
            (
                true,
                false,
                false,
                PolicyMode::FullMitm,
                false,
                TlsPolicyDecision {
                    mitm: true,
                    decision_source: "mitm",
                    bypass_reason: None,
                },
            ),
            (
                true,
                false,
                false,
                PolicyMode::SelectiveMitm,
                true,
                TlsPolicyDecision {
                    mitm: true,
                    decision_source: "mitm",
                    bypass_reason: None,
                },
            ),
            (
                true,
                false,
                false,
                PolicyMode::SelectiveMitm,
                false,
                TlsPolicyDecision {
                    mitm: false,
                    decision_source: "sni",
                    bypass_reason: Some("category_not_selected_for_mitm"),
                },
            ),
        ];

        for (enabled, pinned, tripped, mode, selective_mitm, expected) in cases {
            assert_eq!(
                classify_tls_policy_decision(enabled, pinned, tripped, mode, selective_mitm),
                expected
            );
        }
    }

    /// #272: POLICY_MODE=sni never terminates TLS — exhaustive flag combinations.
    #[test]
    fn policy_mode_sni_never_sets_mitm_true() {
        for mitm_enabled in [false, true] {
            for pinned in [false, true] {
                for tripped in [false, true] {
                    for selective_mitm in [false, true] {
                        let d = classify_tls_policy_decision(
                            mitm_enabled,
                            pinned,
                            tripped,
                            PolicyMode::Sni,
                            selective_mitm,
                        );
                        assert!(
                            !d.mitm,
                            "Sni mode mitm=true for enabled={mitm_enabled} pinned={pinned} tripped={tripped} selective={selective_mitm}"
                        );
                        assert_eq!(d.decision_source, "sni");
                        assert_eq!(d.bypass_reason, Some("policy_mode_sni"));
                    }
                }
            }
        }
    }

    #[test]
    fn classifies_decrypted_and_plain_http_events() {
        assert_eq!(request_decision_source("https://example.com/path"), "mitm");
        assert_eq!(request_decision_source("http://example.com/path"), "sni");
    }

    /// The reference the fast path must never disagree with.
    fn extract_domain_reference(url_str: &str) -> String {
        url::Url::parse(url_str)
            .ok()
            .and_then(|u| u.host().map(|h| h.to_string()))
            .unwrap_or_else(|| "unknown".to_string())
    }

    #[test]
    fn fast_domain_extraction_matches_the_url_parser() {
        let urls = [
            "http://example.com/",
            "http://example.com",
            "https://example.com/path?q=1#frag",
            "https://EXAMPLE.COM/Path",
            "https://sub.domain.example.com:8443/x",
            "http://user:pass@example.com/x",
            "http://user@host.example/x",
            "https://192.0.2.10:443/x",
            "https://example.com:8080",
            "https://a-b--c.example/x",
            "https://xn--80ak6aa92e.com/x",
            // Below here the fast path must defer to the parser.
            "https://[2001:db8::1]:8443/x",
            "https://[::1]/x",
            "https://пример.рф/x",
            "https://ex%41mple.com/x",
            "https://example.com./x",
            "https://.example.com/x",
            "https://exa..mple.com/x",
            "http:///no-host",
            "not a url",
            "",
            "/relative/path",
        ];
        for url in urls {
            assert_eq!(
                ProxyService::extract_domain(url),
                extract_domain_reference(url),
                "domain mismatch for {url}"
            );
        }
    }

    #[test]
    fn fast_domain_extraction_defers_on_unusual_authorities() {
        // Anything the URL spec does more than lowercase to must reach the parser.
        for url in [
            "https://[2001:db8::1]/x",
            "https://пример.рф/x",
            "https://ex%41mple.com/x",
            "https://example.com./x",
            "http:///no-host",
            "relative/only",
        ] {
            assert!(
                ProxyService::extract_domain_fast(url).is_none(),
                "{url} should fall back to Url::parse"
            );
        }
    }

    #[test]
    fn fast_domain_extraction_handles_the_common_shapes() {
        assert_eq!(
            ProxyService::extract_domain_fast("https://EXAMPLE.com:8443/a?b#c"),
            Some("example.com".to_string())
        );
        assert_eq!(
            ProxyService::extract_domain_fast("http://user:pw@host.example/x"),
            Some("host.example".to_string())
        );
    }

    #[test]
    fn unparseable_urls_report_unknown_domain() {
        assert_eq!(ProxyService::extract_domain("not a url"), "unknown");
        assert_eq!(ProxyService::extract_domain(""), "unknown");
    }
}
