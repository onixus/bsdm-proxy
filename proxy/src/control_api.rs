//! Control-plane REST helpers: Lite JSON stats, L1 cache purge, hierarchy peer reload (DX Phase 2).

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::header::{AUTHORIZATION, LOCATION};
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::acl_api::AclApiState;
use crate::agent_crl::AgentCrl;
use crate::agent_events::{AgentEventBatch, AgentEventIngestor};
use crate::agent_ocsp;
use crate::agent_policy_hub::PolicyHub;
use crate::cache_key::http_cache_key;
use crate::device_registry::{
    DeviceRegistry, EnrollError, EnrollRequest, HeartbeatUpdate, RevokeError,
};
use crate::hierarchy_config::reload_static_peers;
use crate::http_types::{full, Body};
use crate::l2_cache::RedisL2Cache;
use crate::metrics::Metrics;
use crate::peers::PeerRegistry;
use crate::pinning::PinningRegistry;
use crate::pipeline::HttpEventPipeline;
#[cfg(feature = "kafka")]
use crate::pipeline::KafkaEventPipeline;
use crate::runtime_config::{
    apply_env_map, config_snapshot, read_env_file, schedule_service_restart, write_acl_rules_file,
    write_env_file, ConfigApplyRequest, ConfigApplyResponse,
};
use crate::sharded_cache::HttpL1Cache;
use crate::tls::CertCache;
use crate::upstream::UpstreamClientHandle;

#[derive(Serialize, Deserialize)]
struct DlpPatternDto {
    pub pattern: String,
    pub description: String,
}

#[derive(Deserialize)]
struct AgentHeartbeatDto {
    device_id: String,
    status: Option<String>,
    agent_version: Option<String>,
    policy_version: Option<String>,
    name: Option<String>,
    ip: Option<String>,
    device_type: Option<String>,
    cert_subject: Option<String>,
    cert_fingerprint: Option<String>,
    trust_score: Option<u8>,
}

impl From<AgentHeartbeatDto> for HeartbeatUpdate {
    fn from(hb: AgentHeartbeatDto) -> Self {
        Self {
            device_id: hb.device_id,
            status: hb.status,
            agent_version: hb.agent_version,
            policy_version: hb.policy_version,
            name: hb.name,
            ip: hb.ip,
            device_type: hb.device_type,
            cert_subject: hb.cert_subject,
            cert_fingerprint: hb.cert_fingerprint,
            trust_score: hb.trust_score,
        }
    }
}

impl ControlApiState {
    fn casb_domains(&self) -> Response<Body> {
        let domains = self.casb_engine.get_domains();
        match serde_json::to_string(&domains) {
            Ok(json) => json_response(StatusCode::OK, &json),
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(r#"{{"error":"{}"}}"#, e),
            ),
        }
    }

    async fn casb_update(&self, body: Bytes) -> Response<Body> {
        match serde_json::from_slice::<Vec<String>>(&body) {
            Ok(domains) => {
                self.casb_engine.set_domains(domains);
                json_response(StatusCode::OK, r#"{"status":"ok"}"#)
            }
            Err(e) => json_response(StatusCode::BAD_REQUEST, &format!(r#"{{"error":"{}"}}"#, e)),
        }
    }

    fn dlp_patterns(&self) -> Response<Body> {
        let patterns: Vec<DlpPatternDto> = self
            .dlp_engine
            .get_patterns()
            .into_iter()
            .map(|(p, d)| DlpPatternDto {
                pattern: p,
                description: d,
            })
            .collect();
        match serde_json::to_string(&patterns) {
            Ok(json) => json_response(StatusCode::OK, &json),
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(r#"{{"error":"{}"}}"#, e),
            ),
        }
    }

    async fn dlp_update(&self, body: Bytes) -> Response<Body> {
        match serde_json::from_slice::<Vec<DlpPatternDto>>(&body) {
            Ok(dtos) => {
                let patterns = dtos
                    .into_iter()
                    .map(|dto| (dto.pattern, dto.description))
                    .collect();
                self.dlp_engine.set_patterns(patterns);
                json_response(StatusCode::OK, r#"{"status":"ok"}"#)
            }
            Err(e) => json_response(StatusCode::BAD_REQUEST, &format!(r#"{{"error":"{}"}}"#, e)),
        }
    }

    async fn amneziawg_status(&self) -> Response<Body> {
        let guard = self.awg_server.read().await;
        match serde_json::to_string(&*guard) {
            Ok(json) => json_response(StatusCode::OK, &json),
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(r#"{{"error":"{}"}}"#, e),
            ),
        }
    }

    async fn amneziawg_update(&self, body: Bytes) -> Response<Body> {
        match serde_json::from_slice::<crate::amneziawg::AwgServerConfig>(&body) {
            Ok(config) => {
                let mut guard = self.awg_server.write().await;
                *guard = config;
                let conf_path = std::env::var("AWG_CONFIG_PATH")
                    .unwrap_or_else(|_| "./certs/awg/awg0.conf".to_string());
                let path = std::path::Path::new(&conf_path);
                let reload_msg = match crate::amneziawg::sync_sidecar_interface(path, &mut guard) {
                    Ok(msg) => msg,
                    Err(err) => err,
                };
                let payload = serde_json::json!({
                    "status": "ok",
                    "reload_status": reload_msg,
                    "config_path": conf_path,
                });
                json_response(StatusCode::OK, &payload.to_string())
            }
            Err(e) => json_response(StatusCode::BAD_REQUEST, &format!(r#"{{"error":"{}"}}"#, e)),
        }
    }

    async fn amneziawg_add_peer(&self, body: Bytes) -> Response<Body> {
        match serde_json::from_slice::<crate::amneziawg::AwgPeerConfig>(&body) {
            Ok(peer) => {
                let mut guard = self.awg_server.write().await;
                guard.peers.push(peer);
                let conf_path = std::env::var("AWG_CONFIG_PATH")
                    .unwrap_or_else(|_| "./certs/awg/awg0.conf".to_string());
                let path = std::path::Path::new(&conf_path);
                let reload_msg = match crate::amneziawg::sync_sidecar_interface(path, &mut guard) {
                    Ok(msg) => msg,
                    Err(err) => err,
                };
                let payload = serde_json::json!({
                    "status": "ok",
                    "reload_status": reload_msg,
                    "config_path": conf_path,
                });
                json_response(StatusCode::OK, &payload.to_string())
            }
            Err(e) => json_response(StatusCode::BAD_REQUEST, &format!(r#"{{"error":"{}"}}"#, e)),
        }
    }

    async fn amneziawg_delete_peer(&self, body: Bytes) -> Response<Body> {
        #[derive(serde::Deserialize)]
        struct DeleteReq {
            id: String,
        }
        match serde_json::from_slice::<DeleteReq>(&body) {
            Ok(req) => {
                let mut guard = self.awg_server.write().await;
                let initial_len = guard.peers.len();
                guard.peers.retain(|p| p.id != req.id);
                if guard.peers.len() == initial_len {
                    return json_response(StatusCode::NOT_FOUND, r#"{"error":"peer not found"}"#);
                }
                let conf_path = std::env::var("AWG_CONFIG_PATH")
                    .unwrap_or_else(|_| "./certs/awg/awg0.conf".to_string());
                let path = std::path::Path::new(&conf_path);
                let reload_msg = match crate::amneziawg::sync_sidecar_interface(path, &mut guard) {
                    Ok(msg) => msg,
                    Err(err) => err,
                };
                let payload = serde_json::json!({
                    "status": "deleted",
                    "reload_status": reload_msg,
                    "config_path": conf_path,
                });
                json_response(StatusCode::OK, &payload.to_string())
            }
            Err(e) => json_response(StatusCode::BAD_REQUEST, &format!(r#"{{"error":"{}"}}"#, e)),
        }
    }

    pub fn cluster_session_state(&self) -> Response<Body> {
        let redis_connected = self.session_store.is_redis_connected();
        let session_count = self.session_store.session_count();
        let payload = serde_json::json!({
            "status": if redis_connected { "redis_connected" } else { "standalone_memory" },
            "redis_connected": redis_connected,
            "session_count": session_count,
            "distributed_rate_limit_enabled": redis_connected,
        });
        json_response(StatusCode::OK, &payload.to_string())
    }

    pub fn threat_sync_peers(&self) -> Response<Body> {
        let peers = self.threat_sync.get_peers();
        let events = self.threat_sync.get_recent_events();
        let sync_enabled = self.threat_sync.is_sync_enabled();
        let payload = serde_json::json!({
            "node_id": self.threat_sync.node_id(),
            "sync_enabled": sync_enabled,
            "peers": peers,
            "recent_events": events,
        });
        json_response(StatusCode::OK, &payload.to_string())
    }

    pub async fn threat_sync_broadcast(&self, body: Bytes) -> Response<Body> {
        let event: crate::threat_sync::ThreatSyncEvent = match serde_json::from_slice(&body) {
            Ok(evt) => evt,
            Err(e) => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    &format!(
                        r#"{{"error":"invalid threat event payload: {}"}}"#,
                        escape_json(&e.to_string())
                    ),
                );
            }
        };

        match self.threat_sync.broadcast(event.clone()).await {
            Ok(()) => {
                self.metrics.threat_sync_events_total.inc();
                json_response(StatusCode::OK, r#"{"status":"broadcasted"}"#)
            }
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(r#"{{"error":"broadcast failed: {}"}}"#, escape_json(&e)),
            ),
        }
    }

    fn config_get(&self) -> Response<Body> {
        match config_snapshot() {
            Ok(snapshot) => match serde_json::to_string(&snapshot) {
                Ok(json) => json_response(StatusCode::OK, &json),
                Err(error) => json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!(r#"{{"error":"{}"}}"#, escape_json(&error.to_string())),
                ),
            },
            Err(error) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(r#"{{"error":"{}"}}"#, escape_json(&error)),
            ),
        }
    }

    async fn config_apply(&self, body: Bytes) -> Response<Body> {
        let request: ConfigApplyRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    &format!(
                        r#"{{"error":"invalid config apply payload: {}"}}"#,
                        escape_json(&error.to_string())
                    ),
                );
            }
        };

        if request.env.is_empty() {
            return json_response(
                StatusCode::BAD_REQUEST,
                r#"{"error":"env map must not be empty"}"#,
            );
        }

        let mut merged = read_env_file().unwrap_or_default();
        for (key, value) in request.env {
            if value.is_empty() {
                merged.remove(&key);
            } else {
                merged.insert(key, value);
            }
        }

        let env_path = match write_env_file(&merged) {
            Ok(path) => path,
            Err(error) => {
                return json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!(r#"{{"error":"{}"}}"#, escape_json(&error)),
                );
            }
        };

        apply_env_map(&merged);

        let mut hot_reload = Vec::new();

        if let Some(rules) = &request.acl_rules {
            let rules_path = merged
                .get("ACL_RULES_PATH")
                .cloned()
                .or_else(|| std::env::var("ACL_RULES_PATH").ok())
                .unwrap_or_else(|| "./acl-rules.json".to_string());
            if let Err(error) = write_acl_rules_file(&rules_path, rules) {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    &format!(r#"{{"error":"{}"}}"#, escape_json(&error)),
                );
            }
            merged.insert("ACL_RULES_PATH".to_string(), rules_path);
            if let Some(acl_api) = &self.acl_api {
                match acl_api.reload_from_disk() {
                    Ok(count) => {
                        hot_reload.push(format!("acl:{count}"));
                    }
                    Err(error) => warn!("ACL hot reload after config apply failed: {error}"),
                }
            }
        }

        if self.upstream_tls_reload_payload().is_ok() {
            hot_reload.push("upstream_tls".to_string());
        }

        if self.hierarchy_reload_payload().await.is_ok() {
            hot_reload.push("hierarchy".to_string());
        }

        let should_restart = request.restart.unwrap_or(true);
        let restart_status = if should_restart {
            if let Some(shutdown_tx) = &self.shutdown_tx {
                schedule_service_restart(shutdown_tx.clone());
                "scheduled"
            } else {
                "unavailable"
            }
        } else {
            "skipped"
        };

        let message = if should_restart {
            "Configuration saved; proxy will restart shortly to apply all settings."
        } else {
            "Configuration saved and hot-reloaded where supported."
        };

        info!(
            env_path = %env_path.display(),
            hot_reload = ?hot_reload,
            restart = restart_status,
            "Configuration applied from admin console"
        );

        let payload = ConfigApplyResponse {
            status: "applied",
            env_path: env_path.display().to_string(),
            hot_reload,
            restart: restart_status,
            message: message.to_string(),
        };
        match serde_json::to_string(&payload) {
            Ok(json) => json_response(StatusCode::OK, &json),
            Err(error) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(r#"{{"error":"{}"}}"#, escape_json(&error.to_string())),
            ),
        }
    }

    fn agent_policy(&self) -> Response<Body> {
        let snap = self.policy_hub.snapshot();
        json_response(StatusCode::OK, &snap.document.to_string())
    }

    /// Long-poll until policy_version changes (`?since=&timeout_secs=`).
    async fn agent_policy_watch(&self, query: Option<&str>) -> Response<Body> {
        let mut since: Option<String> = None;
        let mut timeout_secs: u64 = 30;
        if let Some(q) = query {
            for pair in q.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    match k {
                        "since" => {
                            if !v.is_empty() {
                                since = Some(v.to_string());
                            }
                        }
                        "timeout_secs" => {
                            if let Ok(n) = v.parse::<u64>() {
                                timeout_secs = n.clamp(1, 120);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        let (snap, changed) = self
            .policy_hub
            .wait_change(since.as_deref(), Duration::from_secs(timeout_secs))
            .await;
        let mut body = snap.document;
        body["changed"] = serde_json::Value::Bool(changed);
        body["timeout"] = serde_json::Value::Bool(!changed);
        json_response(StatusCode::OK, &body.to_string())
    }

    /// SSE stream of policy pushes (`text/event-stream`).
    fn agent_policy_stream(&self) -> Response<Body> {
        use http_body_util::channel::Channel;
        use std::convert::Infallible;

        let hub = self.policy_hub.clone();
        let (mut tx, body) = Channel::<Bytes, Infallible>::new(8);
        tokio::spawn(async move {
            // Immediate snapshot so clients sync without a separate pull.
            let mut last = hub.snapshot().version;
            let initial = hub.snapshot();
            let data = format!("event: policy\ndata: {}\n\n", initial.document);
            if tx.send_data(Bytes::from(data)).await.is_err() {
                return;
            }
            let notify = hub.notify_handle();
            let mut ping = tokio::time::interval(Duration::from_secs(15));
            loop {
                tokio::select! {
                    _ = notify.notified() => {
                        let snap = hub.snapshot();
                        if snap.version == last {
                            continue;
                        }
                        last = snap.version.clone();
                        let data = format!("event: policy\ndata: {}\n\n", snap.document);
                        if tx.send_data(Bytes::from(data)).await.is_err() {
                            break;
                        }
                    }
                    _ = ping.tick() => {
                        if tx.send_data(Bytes::from_static(b": ping\n\n")).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let boxed = body.map_err(|e: Infallible| match e {}).boxed();
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .header("Connection", "keep-alive")
            .body(boxed)
            .unwrap_or_else(|_| {
                json_response(StatusCode::INTERNAL_SERVER_ERROR, r#"{"error":"sse body"}"#)
            })
    }

    /// Operator: rebuild policy from env+pinning and notify subscribers.
    fn agent_policy_push(&self, body: Bytes) -> Response<Body> {
        #[derive(Deserialize)]
        struct PushDto {
            #[serde(default)]
            reason: Option<String>,
            #[serde(default)]
            actor: Option<String>,
        }
        let dto: PushDto = serde_json::from_slice(&body).unwrap_or(PushDto {
            reason: None,
            actor: None,
        });
        let reason = dto
            .reason
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "manual-push".into());
        let actor = dto.actor.unwrap_or_else(|| "operator".into());
        let snap = self
            .policy_hub
            .publish_from_runtime(&self.pinning_registry, &reason);
        info!(%actor, version = %snap.version, %reason, "Agent policy push");
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "status": "pushed",
                "policy_version": snap.version,
                "reason": snap.reason,
                "pushed_at": snap.pushed_at,
                "document": snap.document,
            })
            .to_string(),
        )
    }

    fn pinning_exceptions(&self) -> Response<Body> {
        let entries = self.pinning_registry.snapshot();
        let active_count = self.pinning_registry.active_domains().len();
        let payload = serde_json::json!({
            "source": self.pinning_registry.source(),
            "audit_path": self.pinning_registry.audit_path(),
            "count": entries.len(),
            "active_count": active_count,
            "exceptions": entries,
        });
        json_response(StatusCode::OK, &payload.to_string())
    }

    fn pinning_reload(&self, body: Bytes) -> Response<Body> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ReloadRequest {
            actor: String,
            reason: String,
        }

        let request: ReloadRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({
                        "error": format!("invalid reload payload: {error}"),
                    })
                    .to_string(),
                );
            }
        };
        match self
            .pinning_registry
            .reload(&request.actor, &request.reason)
        {
            Ok(report) => {
                info!(
                    actor = %request.actor,
                    reason = %request.reason,
                    added = report.added.len(),
                    removed = report.removed.len(),
                    updated = report.updated.len(),
                    "Certificate pinning exceptions reloaded"
                );
                // Push refreshed agent policy so subscribers pick up new pinning.
                let _ = self.policy_hub.publish_from_runtime(
                    &self.pinning_registry,
                    &format!("pinning-reload:{}", request.reason),
                );
                match serde_json::to_string(&report) {
                    Ok(payload) => json_response(StatusCode::OK, &payload),
                    Err(error) => json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &serde_json::json!({"error": error.to_string()}).to_string(),
                    ),
                }
            }
            Err(error) => {
                warn!(
                    actor = %request.actor,
                    reason = %request.reason,
                    error = %error,
                    "Certificate pinning exception reload failed"
                );
                json_response(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({"error": error}).to_string(),
                )
            }
        }
    }

    async fn agent_heartbeat(&self, body: Bytes) -> Response<Body> {
        let hb: AgentHeartbeatDto = match serde_json::from_slice(&body) {
            Ok(hb) => hb,
            Err(e) => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    &format!(
                        r#"{{"error":"invalid heartbeat payload: {}"}}"#,
                        escape_json(&e.to_string())
                    ),
                );
            }
        };
        match self.device_registry.apply_heartbeat(hb.into()) {
            Ok(persisted) => json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "status": "acknowledged",
                    "persisted": persisted,
                })
                .to_string(),
            ),
            Err(err) => json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({ "error": err.message() }).to_string(),
            ),
        }
    }

    fn registered_devices(&self) -> Response<Body> {
        let rows = self.device_registry.list_api_rows();
        json_response(StatusCode::OK, &serde_json::Value::Array(rows).to_string())
    }

    fn revoke_device(&self, device_id: &str) -> Response<Body> {
        match self.device_registry.revoke(device_id) {
            Ok((persisted, fingerprint, serial)) => {
                let crl_added = self.agent_crl.revoke(
                    device_id,
                    fingerprint.as_deref(),
                    serial.as_deref(),
                    "cessationOfOperation",
                );
                json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "success": true,
                        "message": format!("Device {device_id} revoked"),
                        "persisted": persisted,
                        "crl_added": crl_added,
                        "cert_fingerprint": fingerprint,
                    })
                    .to_string(),
                )
            }
            Err(RevokeError::InvalidId) => {
                json_response(StatusCode::BAD_REQUEST, r#"{"error":"invalid device id"}"#)
            }
            Err(RevokeError::NotFound) => {
                json_response(StatusCode::NOT_FOUND, r#"{"error":"device not found"}"#)
            }
        }
    }

    fn agent_crl_json(&self) -> Response<Body> {
        json_response(
            StatusCode::OK,
            &self.agent_crl.to_json_document().to_string(),
        )
    }

    /// Lab OCSP-style status: `?fingerprint=` and/or `?serial=`.
    fn agent_ocsp_status(&self, query: Option<&str>) -> Response<Body> {
        let mut fingerprint: Option<String> = None;
        let mut serial: Option<String> = None;
        if let Some(q) = query {
            for pair in q.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    let v = v.replace("%2F", "/"); // minimal decode
                    match k {
                        "fingerprint" if !v.is_empty() => fingerprint = Some(v),
                        "serial" if !v.is_empty() => serial = Some(v),
                        _ => {}
                    }
                }
            }
        }
        match agent_ocsp::check_status(
            &self.agent_crl,
            &self.device_registry,
            fingerprint.as_deref(),
            serial.as_deref(),
        ) {
            Ok(status) => {
                let code = match status.status {
                    agent_ocsp::OcspCertStatus::Good => StatusCode::OK,
                    agent_ocsp::OcspCertStatus::Revoked => StatusCode::OK,
                    agent_ocsp::OcspCertStatus::Unknown => StatusCode::OK,
                };
                match serde_json::to_string(&status) {
                    Ok(body) => json_response(code, &body),
                    Err(e) => json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!(r#"{{"error":"{e}"}}"#),
                    ),
                }
            }
            Err(e) => json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({ "error": e }).to_string(),
            ),
        }
    }

    fn agent_crl_pem(&self) -> Response<Body> {
        let Some(cache) = self.cert_cache.as_ref() else {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"CA not loaded; cannot sign X.509 CRL (use GET /api/v1/agent/crl JSON)"}"#,
            );
        };
        let entries = self.agent_crl.list();
        let revoked: Vec<(String, u64)> = entries
            .iter()
            .filter_map(|e| e.serial_hex.as_ref().map(|s| (s.clone(), e.revoked_at)))
            .collect();
        match cache.sign_agent_crl_pem(&revoked, self.agent_crl.crl_number()) {
            Ok(pem) => Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/x-pem-file")
                .header("Content-Disposition", "inline; filename=\"agent-crl.pem\"")
                .body(full(Bytes::from(pem)))
                .unwrap_or_else(|_| {
                    json_response(StatusCode::INTERNAL_SERVER_ERROR, r#"{"error":"crl body"}"#)
                }),
            Err(e) => json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({
                    "error": format!("X.509 CRL sign failed: {e}"),
                    "hint": "JSON CRL is always available at GET /api/v1/agent/crl",
                    "json_count": self.agent_crl.list().len(),
                })
                .to_string(),
            ),
        }
    }

    fn agent_events_ingest(&self, body: Bytes) -> Response<Body> {
        let batch: AgentEventBatch = match serde_json::from_slice(&body) {
            Ok(batch) => batch,
            Err(e) => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    &format!(
                        r#"{{"error":"invalid events payload: {}"}}"#,
                        escape_json(&e.to_string())
                    ),
                );
            }
        };
        match self.agent_events.ingest(batch, &self.metrics) {
            Ok(report) => json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "status": "accepted",
                    "accepted": report.accepted,
                    "enqueued": report.enqueued,
                })
                .to_string(),
            ),
            Err(err) => json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({ "error": err.message() }).to_string(),
            ),
        }
    }

    fn agent_events_recent(&self) -> Response<Body> {
        let rows = self.agent_events.recent_snapshot(50);
        json_response(
            StatusCode::OK,
            &serde_json::json!({ "events": rows }).to_string(),
        )
    }

    fn agent_enroll(&self, body: Bytes) -> Response<Body> {
        #[derive(Deserialize)]
        struct EnrollDto {
            #[serde(default)]
            device_id: Option<String>,
            platform: String,
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            user_identity: Option<String>,
            #[serde(default)]
            capabilities: Vec<String>,
            #[serde(default)]
            device_type: Option<String>,
            /// Optional PEM CSR for mTLS client certificate issuance.
            #[serde(default)]
            csr_pem: Option<String>,
            /// Client cert validity in days (default 90, max 825).
            #[serde(default)]
            cert_validity_days: Option<u32>,
        }
        let dto: EnrollDto = match serde_json::from_slice(&body) {
            Ok(dto) => dto,
            Err(e) => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    &format!(
                        r#"{{"error":"invalid enroll payload: {}"}}"#,
                        escape_json(&e.to_string())
                    ),
                );
            }
        };

        let device_id_hint = dto
            .device_id
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("dev-{}", hex::encode(rand::random::<u64>().to_be_bytes())));

        let mut client_cert_pem = None;
        let mut ca_cert_pem = None;
        let mut cert_not_after = None;
        let mut cert_subject = None;
        let mut cert_fingerprint = None;
        let mut cert_serial = None;

        if let Some(csr) = dto
            .csr_pem
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            let Some(cache) = self.cert_cache.as_ref() else {
                return json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    r#"{"error":"CSR provided but CA not loaded on control plane"}"#,
                );
            };
            let days = dto.cert_validity_days.unwrap_or(90);
            match cache.sign_agent_client_csr(
                &csr,
                &device_id_hint,
                dto.user_identity.as_deref(),
                &dto.platform,
                days,
            ) {
                Ok(signed) => {
                    client_cert_pem = Some(signed.client_cert_pem);
                    ca_cert_pem = Some(signed.ca_cert_pem);
                    cert_not_after = Some(signed.not_after_unix);
                    cert_subject = Some(signed.subject);
                    cert_fingerprint = Some(signed.fingerprint_sha256);
                    cert_serial = Some(signed.serial_hex);
                }
                Err(e) => {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        &serde_json::json!({ "error": format!("CSR sign failed: {e}") })
                            .to_string(),
                    );
                }
            }
        }

        match self.device_registry.enroll(EnrollRequest {
            device_id: Some(device_id_hint),
            platform: dto.platform,
            name: dto.name,
            user_identity: dto.user_identity,
            capabilities: dto.capabilities,
            device_type: dto.device_type,
            cert_subject: cert_subject.clone(),
            cert_fingerprint: cert_fingerprint.clone(),
            cert_serial: cert_serial.clone(),
        }) {
            Ok(result) => {
                let mtls = client_cert_pem.is_some();
                json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "status": "enrolled",
                        "device_id": result.device_id,
                        "device_token": result.device_token,
                        "platform": result.platform,
                        "enrolled_at": result.enrolled_at,
                        "persisted": result.persisted,
                        "reenrolled": result.reenrolled,
                        "endpoints": {
                            "policy": "/api/v1/agent/policy",
                            "heartbeat": "/api/v1/agent/heartbeat",
                            "events": "/api/v1/agent/events",
                            "crl": "/api/v1/agent/crl",
                            "ocsp": "/api/v1/agent/ocsp/status",
                        },
                        "ocsp_status_url": cert_fingerprint.as_ref().map(|fp| {
                            format!("/api/v1/agent/ocsp/status?fingerprint={fp}")
                        }),
                        "auth": "Bearer device_token for agent endpoints (or CONTROL_API_TOKEN)",
                        "mtls": mtls,
                        "client_cert_pem": client_cert_pem,
                        "ca_cert_pem": ca_cert_pem,
                        "cert_subject": cert_subject,
                        "cert_serial": cert_serial,
                        "cert_fingerprint": cert_fingerprint,
                        "cert_not_after": cert_not_after,
                        "note": if mtls {
                            "device_token issued; client cert signed by proxy CA (ClientAuth EKU)"
                        } else {
                            "device_token issued; omit csr_pem for token-only enroll, or send CSR for mTLS cert"
                        },
                    })
                    .to_string(),
                )
            }
            Err(EnrollError::Revoked) => json_response(
                StatusCode::CONFLICT,
                &serde_json::json!({ "error": EnrollError::Revoked.message() }).to_string(),
            ),
            Err(err) => json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({ "error": err.message() }).to_string(),
            ),
        }
    }
}

#[derive(Clone)]
pub struct ControlApiState {
    metrics: Arc<Metrics>,
    http_cache: Arc<HttpL1Cache>,
    l2_cache: Option<RedisL2Cache>,
    api_token: Option<String>,
    /// When true and `api_token` is unset, non-public `/api/*` returns 401 (#271).
    fail_closed: bool,
    started_at: Instant,
    peer_registry: Option<PeerRegistry>,
    hierarchy_use_htcp: bool,
    upstream_client: UpstreamClientHandle,
    #[cfg(feature = "wasm")]
    wasm_hook: Option<Arc<std::sync::RwLock<crate::wasm_host::WasmHookEngine>>>,
    casb_engine: Arc<crate::casb::CasbEngine>,
    dlp_engine: Arc<crate::dlp::DlpEngine>,
    pinning_registry: Arc<PinningRegistry>,
    auth_manager: Option<Arc<crate::auth::AuthManager>>,
    awg_server: Arc<tokio::sync::RwLock<crate::amneziawg::AwgServerConfig>>,
    session_store: crate::session_store::GlobalSessionStore,
    threat_sync: crate::threat_sync::ThreatSyncEngine,
    admin_console_dir: Option<std::path::PathBuf>,
    device_registry: DeviceRegistry,
    agent_events: AgentEventIngestor,
    agent_crl: AgentCrl,
    policy_hub: PolicyHub,
    /// Bootstrap token for `POST /api/v1/agent/enroll` (`AGENT_ENROLL_TOKEN`).
    /// Falls back to control `api_token` when unset.
    enroll_token: Option<String>,
    /// CA used to sign agent client certs from CSR (shared MITM CA by default).
    cert_cache: Option<CertCache>,
    shutdown_tx: Option<watch::Sender<bool>>,
    acl_api: Option<Arc<AclApiState>>,
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
        casb_engine: Arc<crate::casb::CasbEngine>,
        dlp_engine: Arc<crate::dlp::DlpEngine>,
        pinning_registry: Arc<PinningRegistry>,
        auth_manager: Option<Arc<crate::auth::AuthManager>>,
        session_store: crate::session_store::GlobalSessionStore,
        threat_sync: crate::threat_sync::ThreatSyncEngine,
    ) -> Self {
        let policy_hub = PolicyHub::from_runtime(&pinning_registry);
        Self {
            metrics,
            http_cache,
            l2_cache,
            api_token,
            // Unit tests construct via `new` without env; keep open unless from_env.
            fail_closed: false,
            started_at: Instant::now(),
            peer_registry,
            hierarchy_use_htcp,
            upstream_client,
            #[cfg(feature = "wasm")]
            wasm_hook,
            casb_engine,
            dlp_engine,
            pinning_registry,
            auth_manager,
            awg_server: Arc::new(tokio::sync::RwLock::new(
                crate::amneziawg::AwgServerConfig::default(),
            )),
            session_store,
            threat_sync,
            admin_console_dir: std::env::var("ADMIN_CONSOLE_DIR")
                .ok()
                .map(std::path::PathBuf::from)
                .or_else(|| {
                    let p = std::path::PathBuf::from("./admin-console/dist");
                    if p.exists() {
                        Some(p)
                    } else {
                        None
                    }
                }),
            device_registry: DeviceRegistry::memory_only(),
            agent_events: AgentEventIngestor::memory_only(),
            agent_crl: AgentCrl::memory_only(),
            policy_hub,
            enroll_token: None,
            cert_cache: None,
            shutdown_tx: None,
            acl_api: None,
        }
    }

    /// Attach CertCache so enroll can sign mTLS client certificates from CSR.
    pub fn with_cert_cache(mut self, cert_cache: CertCache) -> Self {
        self.cert_cache = Some(cert_cache);
        self
    }

    pub fn with_config_apply(
        mut self,
        shutdown_tx: watch::Sender<bool>,
        acl_api: Option<Arc<AclApiState>>,
    ) -> Self {
        self.shutdown_tx = Some(shutdown_tx);
        self.acl_api = acl_api;
        self
    }

    /// Attach Kafka and/or HTTP event pipelines so agent telemetry can reach CH.
    pub fn with_event_pipelines(
        mut self,
        #[cfg(feature = "kafka")] kafka: Option<Arc<KafkaEventPipeline>>,
        http: Option<Arc<HttpEventPipeline>>,
    ) -> Self {
        self.agent_events = AgentEventIngestor::with_pipelines(
            #[cfg(feature = "kafka")]
            kafka,
            http,
        );
        self
    }

    #[allow(clippy::too_many_arguments)]
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
        casb_engine: Arc<crate::casb::CasbEngine>,
        dlp_engine: Arc<crate::dlp::DlpEngine>,
        pinning_registry: Arc<PinningRegistry>,
        auth_manager: Option<Arc<crate::auth::AuthManager>>,
        session_store: crate::session_store::GlobalSessionStore,
        threat_sync: crate::threat_sync::ThreatSyncEngine,
    ) -> Self {
        let api_token = crate::security_defaults::control_api_token_from_env();
        let mut state = Self::new(
            metrics,
            http_cache,
            l2_cache,
            api_token,
            peer_registry,
            hierarchy_use_htcp,
            upstream_client,
            #[cfg(feature = "wasm")]
            wasm_hook,
            casb_engine,
            dlp_engine,
            pinning_registry,
            auth_manager,
            session_store,
            threat_sync,
        );
        state.fail_closed = crate::security_defaults::control_api_fail_closed();
        state.device_registry = DeviceRegistry::from_env();
        state.agent_crl = AgentCrl::from_env();
        state.policy_hub = PolicyHub::from_runtime(&state.pinning_registry);
        state.enroll_token = std::env::var("AGENT_ENROLL_TOKEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        state
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
        let query = parts.uri.query().map(|s| s.to_string());
        self.dispatch_with_query(
            &parts.method,
            parts.uri.path(),
            query.as_deref(),
            body,
            &parts.headers,
        )
        .await
    }

    #[cfg(test)]
    async fn dispatch(
        &self,
        method: &Method,
        path: &str,
        body: Bytes,
        headers: &HeaderMap,
    ) -> Response<Body> {
        self.dispatch_with_query(method, path, None, body, headers)
            .await
    }

    async fn dispatch_with_query(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
        body: Bytes,
        headers: &HeaderMap,
    ) -> Response<Body> {
        // API endpoints authorization check
        if path.starts_with("/api/") {
            let public_api = matches!(
                (method, path),
                (&Method::GET, "/api/stats")
                    | (&Method::GET, "/api/hierarchy/peers")
                    | (&Method::GET, "/api/upstream/tls")
            );
            if !public_api {
                let enroll_api = matches!(path, "/api/v1/agent/enroll" | "/api/agent/enroll");
                let agent_api = path.starts_with("/api/v1/agent/")
                    || path.starts_with("/api/agent/")
                    || path == "/api/v1/devices"
                    || path.starts_with("/api/v1/devices/");
                let authorized = if enroll_api {
                    self.is_enroll_authorized(headers)
                } else if agent_api {
                    self.is_agent_authorized(headers)
                } else {
                    self.is_authorized(headers)
                };
                if !authorized {
                    return json_response(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#);
                }
            }
        }

        if method == Method::GET && path == "/api/v1/devices" {
            return self.registered_devices();
        }
        if method == Method::POST {
            if let Some(device_id) = path
                .strip_prefix("/api/v1/devices/")
                .and_then(|path| path.strip_suffix("/revoke"))
            {
                return self.revoke_device(device_id);
            }
        }

        match (method, path) {
            (&Method::GET, "/api/config") => self.config_get(),
            (&Method::POST, "/api/config/apply") => self.config_apply(body).await,
            (&Method::GET, "/api/stats") => self.stats(),
            (&Method::POST, "/api/cache/purge") => self.purge(body).await,
            (&Method::GET, "/api/hierarchy/peers") => self.hierarchy_peers().await,
            (&Method::POST, "/api/hierarchy/reload") => self.hierarchy_reload().await,
            (&Method::GET, "/api/upstream/tls") => self.upstream_tls_status(),
            (&Method::POST, "/api/upstream/tls/reload") => self.upstream_tls_reload(),
            (&Method::GET, "/api/security/casb") => self.casb_domains(),
            (&Method::POST, "/api/security/casb") => self.casb_update(body).await,
            (&Method::GET, "/api/security/dlp") => self.dlp_patterns(),
            (&Method::POST, "/api/security/dlp") => self.dlp_update(body).await,
            (&Method::GET, "/api/auth/basic/users") => self.basic_users_list().await,
            (&Method::POST, "/api/auth/basic/users") => self.basic_users_put(body).await,
            (&Method::DELETE, "/api/auth/basic/users") => self.basic_users_delete(body).await,
            (&Method::GET, "/api/amneziawg/status") => self.amneziawg_status().await,
            (&Method::POST, "/api/amneziawg/config") => self.amneziawg_update(body).await,
            (&Method::POST, "/api/amneziawg/peers") => self.amneziawg_add_peer(body).await,
            (&Method::DELETE, "/api/amneziawg/peers") => self.amneziawg_delete_peer(body).await,
            (&Method::GET, "/api/cluster/session-state") => self.cluster_session_state(),
            (&Method::GET, "/api/threats/sync/peers") => self.threat_sync_peers(),
            (&Method::POST, "/api/threats/sync/broadcast") => {
                self.threat_sync_broadcast(body).await
            }
            (&Method::GET, "/api/pinning/exceptions") => self.pinning_exceptions(),
            (&Method::POST, "/api/pinning/exceptions/reload") => self.pinning_reload(body),
            (&Method::GET, "/api/v1/agent/policy") => self.agent_policy(),
            (&Method::GET, "/api/v1/agent/policy/watch") => self.agent_policy_watch(query).await,
            (&Method::GET, "/api/v1/agent/policy/stream") => self.agent_policy_stream(),
            (&Method::POST, "/api/v1/agent/policy/push") => self.agent_policy_push(body),
            (&Method::POST, "/api/v1/agent/heartbeat") => self.agent_heartbeat(body).await,
            (&Method::POST, "/api/v1/agent/events") => self.agent_events_ingest(body),
            (&Method::GET, "/api/v1/agent/events/recent") => self.agent_events_recent(),
            (&Method::POST, "/api/v1/agent/enroll") => self.agent_enroll(body),
            (&Method::GET, "/api/v1/agent/crl") => self.agent_crl_json(),
            (&Method::GET, "/api/v1/agent/crl.pem") => self.agent_crl_pem(),
            (&Method::GET, "/api/v1/agent/ocsp/status") => self.agent_ocsp_status(query),
            (&Method::GET, "/api/agent/policy") => {
                deprecated_agent_alias(self.agent_policy(), "/api/v1/agent/policy")
            }
            (&Method::POST, "/api/agent/heartbeat") => {
                deprecated_agent_alias(self.agent_heartbeat(body).await, "/api/v1/agent/heartbeat")
            }
            (&Method::POST, "/api/agent/events") => {
                deprecated_agent_alias(self.agent_events_ingest(body), "/api/v1/agent/events")
            }
            (&Method::POST, "/api/agent/enroll") => {
                deprecated_agent_alias(self.agent_enroll(body), "/api/v1/agent/enroll")
            }
            #[cfg(feature = "wasm")]
            (&Method::POST, "/api/wasm/reload") => self.wasm_reload(),
            _ => {
                if method == Method::GET && !path.starts_with("/api/") {
                    self.serve_static_ui(path).await
                } else {
                    json_response(StatusCode::NOT_FOUND, r#"{"error":"not found"}"#)
                }
            }
        }
    }

    pub async fn serve_static_ui(&self, path: &str) -> Response<Body> {
        // Prevent path traversal attacks
        if path.contains("..") || path.contains('\0') {
            return json_response(StatusCode::BAD_REQUEST, r#"{"error":"invalid path"}"#);
        }

        // Admin Console is the canonical operator surface. Keep legacy entry
        // points as redirects so existing bookmarks converge on one UI.
        if path == "/" || path == "/admin" || path == "/trust" || path.starts_with("/trust/") {
            return Response::builder()
                .status(StatusCode::PERMANENT_REDIRECT)
                .header(LOCATION, "/admin/")
                .body(full(Bytes::new()))
                .unwrap_or_else(|_| {
                    json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        r#"{"error":"internal error"}"#,
                    )
                });
        }

        let base_dir = self
            .admin_console_dir
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("./admin-console/dist"));

        let relative_path = path
            .strip_prefix("/admin/")
            .unwrap_or_else(|| path.trim_start_matches('/'));
        let target = if relative_path.is_empty() {
            base_dir.join("index.html")
        } else {
            base_dir.join(relative_path)
        };

        let file_path = if target.is_file() {
            target
        } else {
            base_dir.join("index.html")
        };

        match tokio::fs::read(&file_path).await {
            Ok(content) => {
                let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
                let mime = match ext {
                    "html" | "htm" => "text/html; charset=utf-8",
                    "js" | "mjs" => "application/javascript; charset=utf-8",
                    "css" => "text/css; charset=utf-8",
                    "svg" => "image/svg+xml",
                    "png" => "image/png",
                    "jpg" | "jpeg" => "image/jpeg",
                    "ico" => "image/x-icon",
                    "json" => "application/json",
                    "woff2" => "font/woff2",
                    "woff" => "font/woff",
                    _ => "application/octet-stream",
                };

                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", mime)
                    .body(full(content))
                    .unwrap_or_else(|_| {
                        json_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            r#"{"error":"internal error"}"#,
                        )
                    })
            }
            Err(_) => json_response(StatusCode::NOT_FOUND, r#"{"error":"not found"}"#),
        }
    }

    fn extract_bearer<'a>(&self, headers: &'a HeaderMap) -> Option<&'a str> {
        headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
    }

    fn is_authorized(&self, headers: &HeaderMap) -> bool {
        self.is_authorized_bearer(self.extract_bearer(headers))
    }

    /// Shared auth check for REST and gRPC (`authorization: Bearer …`).
    ///
    /// # Security (#271)
    /// - Token configured → constant-time Bearer match.
    /// - No token + `fail_closed` (production default) → deny.
    /// - No token + open lab mode → allow (legacy / e2e).
    pub fn is_authorized_bearer(&self, bearer: Option<&str>) -> bool {
        match &self.api_token {
            Some(expected) => bearer.is_some_and(|token| {
                crate::security_util::constant_time_eq(token.as_bytes(), expected.as_bytes())
            }),
            None => !self.fail_closed,
        }
    }

    /// Enroll bootstrap: `AGENT_ENROLL_TOKEN` if set, else control API token / open lab.
    fn is_enroll_authorized(&self, headers: &HeaderMap) -> bool {
        let bearer = self.extract_bearer(headers);
        if let Some(expected) = &self.enroll_token {
            return bearer.is_some_and(|token| {
                crate::security_util::constant_time_eq(token.as_bytes(), expected.as_bytes())
            });
        }
        self.is_authorized_bearer(bearer)
    }

    /// Agent contract endpoints: control token **or** enrolled device token.
    fn is_agent_authorized(&self, headers: &HeaderMap) -> bool {
        if self.is_authorized(headers) {
            return true;
        }
        let Some(bearer) = self.extract_bearer(headers) else {
            // Open lab when no control token and not fail-closed.
            return self.api_token.is_none() && !self.fail_closed;
        };
        self.device_registry.device_token_valid(bearer)
    }

    /// Whether a client-cert fingerprint matches a non-revoked enrolled device.
    pub fn cert_fingerprint_enrolled(&self, fingerprint: &str) -> bool {
        self.device_registry.cert_fingerprint_valid(fingerprint)
    }

    /// Whether fingerprint is on the agent CRL.
    pub fn cert_fingerprint_revoked(&self, fingerprint: &str) -> bool {
        self.agent_crl.is_fingerprint_revoked(fingerprint)
    }

    /// Whether non-public control RPCs require a Bearer token.
    pub fn auth_required(&self) -> bool {
        self.api_token.is_some() || self.fail_closed
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

    async fn basic_users_list(&self) -> Response<Body> {
        let Some(auth) = &self.auth_manager else {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"Auth backend not enabled"}"#,
            );
        };
        let users = auth.get_basic_users().await;
        match serde_json::to_string(&users) {
            Ok(body) => json_response(StatusCode::OK, &body),
            Err(_) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"serialization failed"}"#,
            ),
        }
    }

    async fn basic_users_put(&self, body: Bytes) -> Response<Body> {
        let Some(auth) = &self.auth_manager else {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"Auth backend not enabled"}"#,
            );
        };
        #[derive(Deserialize)]
        struct PutReq {
            username: String,
            password: Option<String>,
            role: String,
        }
        let req: PutReq = match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(_) => return json_response(StatusCode::BAD_REQUEST, r#"{"error":"invalid json"}"#),
        };
        if req.username.is_empty() || req.role.is_empty() {
            return json_response(
                StatusCode::BAD_REQUEST,
                r#"{"error":"username and role cannot be empty"}"#,
            );
        }
        match auth
            .put_basic_user(req.username.clone(), req.password, req.role)
            .await
        {
            Ok(_) => json_response(StatusCode::OK, r#"{"status":"ok"}"#),
            Err(e) => {
                let error_json = serde_json::json!({ "error": e });
                json_response(StatusCode::BAD_REQUEST, &error_json.to_string())
            }
        }
    }

    async fn basic_users_delete(&self, body: Bytes) -> Response<Body> {
        let Some(auth) = &self.auth_manager else {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"Auth backend not enabled"}"#,
            );
        };
        #[derive(Deserialize)]
        struct DelReq {
            username: String,
        }
        let req: DelReq = match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(_) => return json_response(StatusCode::BAD_REQUEST, r#"{"error":"invalid json"}"#),
        };
        match auth.remove_basic_user(&req.username).await {
            Ok(true) => json_response(StatusCode::OK, r#"{"status":"ok"}"#),
            Ok(false) => json_response(StatusCode::NOT_FOUND, r#"{"error":"user not found"}"#),
            Err(e) => {
                let error_json = serde_json::json!({ "error": e });
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

fn deprecated_agent_alias(
    mut response: Response<Body>,
    successor_path: &'static str,
) -> Response<Body> {
    response
        .headers_mut()
        .insert("deprecation", HeaderValue::from_static("true"));
    response.headers_mut().insert(
        "link",
        HeaderValue::from_str(&format!("<{successor_path}>; rel=\"successor-version\""))
            .expect("static successor path must produce a valid Link header"),
    );
    response
}

#[cfg(test)]
fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
            Arc::new(crate::casb::CasbEngine::new()),
            Arc::new(crate::dlp::DlpEngine::new()),
            Arc::new(PinningRegistry::from_entries(Vec::new()).unwrap()),
            None,
            crate::session_store::GlobalSessionStore::new(None),
            crate::threat_sync::ThreatSyncEngine::new("test-node".to_string(), None),
        )
    }

    /// #271: production fail-closed denies mutations when no token is configured.
    #[tokio::test]
    async fn fail_closed_denies_mutations_without_token() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let mut state = state_plain(metrics, cache);
        state.fail_closed = true;
        assert!(state.auth_required());
        assert!(!state.is_authorized_bearer(None));

        let resp = state
            .dispatch(
                &Method::POST,
                "/api/cache/purge",
                Bytes::from_static(br#"{"all":true}"#),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Public monitoring stays open.
        let stats = state
            .dispatch(&Method::GET, "/api/stats", Bytes::new(), &HeaderMap::new())
            .await;
        assert_eq!(stats.status(), StatusCode::OK);
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
            Arc::new(crate::casb::CasbEngine::new()),
            Arc::new(crate::dlp::DlpEngine::new()),
            Arc::new(PinningRegistry::from_entries(Vec::new()).unwrap()),
            None,
            crate::session_store::GlobalSessionStore::new(None),
            crate::threat_sync::ThreatSyncEngine::new("test-node".to_string(), None),
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

    #[tokio::test]
    async fn static_ui_path_traversal_rejection() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let state = state_plain(metrics, cache);

        let resp = state.serve_static_ui("/../etc/passwd").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_null = state.serve_static_ui("/index.html\0.png").await;
        assert_eq!(resp_null.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn legacy_ui_entries_redirect_to_admin_console() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let state = state_plain(metrics, cache);

        for path in ["/", "/admin", "/trust", "/trust/", "/trust/devices"] {
            let resp = state.serve_static_ui(path).await;
            assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT, "{path}");
            assert_eq!(resp.headers().get(LOCATION).unwrap(), "/admin/", "{path}");
        }
    }

    #[tokio::test]
    async fn admin_console_serves_prefixed_routes_and_assets() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let mut state = state_plain(metrics, cache);
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("assets")).unwrap();
        std::fs::write(dir.path().join("index.html"), "admin-index").unwrap();
        std::fs::write(dir.path().join("assets/app.js"), "admin-asset").unwrap();
        state.admin_console_dir = Some(dir.path().to_path_buf());

        let index = state.serve_static_ui("/admin/").await;
        assert_eq!(index.status(), StatusCode::OK);
        assert_eq!(
            BodyExt::collect(index.into_body())
                .await
                .unwrap()
                .to_bytes(),
            "admin-index"
        );

        let asset = state.serve_static_ui("/admin/assets/app.js").await;
        assert_eq!(asset.status(), StatusCode::OK);
        assert_eq!(
            BodyExt::collect(asset.into_body())
                .await
                .unwrap()
                .to_bytes(),
            "admin-asset"
        );
    }

    #[tokio::test]
    async fn agent_policy_and_heartbeat_endpoints() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let mut state = state_plain(metrics, cache);

        // Canonical versioned policy endpoint.
        let resp = state
            .dispatch(
                &Method::GET,
                "/api/v1/agent/policy",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let policy_version = v["policy_version"].as_str().unwrap().to_string();
        assert!(
            policy_version.starts_with('v'),
            "policy_version={policy_version}"
        );
        assert_eq!(v["policy_mode"], "selective-mitm");
        assert!(v["pinning_exceptions"].is_array());
        assert!(v["sni_deny_patterns"].is_array());
        assert!(!v["sni_deny_patterns"].as_array().unwrap().is_empty());
        assert!(v["sni_rules"].is_array());
        assert_eq!(v["sni_rules"][0]["action"], "deny");
        assert!(v["sni_rules"][0]["pattern"].as_str().is_some());

        // Policy push + long-poll watch.
        let push = state
            .dispatch(
                &Method::POST,
                "/api/v1/agent/policy/push",
                Bytes::from(r#"{"reason":"unit-test","actor":"test"}"#),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(push.status(), StatusCode::OK);
        let body = BodyExt::collect(push.into_body()).await.unwrap().to_bytes();
        let push_v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(push_v["status"], "pushed");
        let new_version = push_v["policy_version"].as_str().unwrap().to_string();
        assert_ne!(new_version, policy_version);

        let watch = state
            .dispatch(
                &Method::GET,
                "/api/v1/agent/policy/watch",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        // dispatch helper has no query; watch with since=None returns current immediately as changed
        assert_eq!(watch.status(), StatusCode::OK);

        // Canonical versioned heartbeat endpoint.
        let hb_payload = Bytes::from(
            r#"{"device_id":"laptop-001","name":"Alice laptop","ip":"10.0.0.5","device_type":"desktop","status":"healthy","agent_version":"0.1.0","policy_version":"v0.1.0","trust_score":97}"#,
        );
        let resp = state
            .dispatch(
                &Method::POST,
                "/api/v1/agent/heartbeat",
                hb_payload,
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["status"], "acknowledged");
        // Memory-only by default (no AGENT_DEVICES_PATH).
        assert_eq!(v["persisted"], false);

        // Enroll → device_token (lab path).
        let enroll_payload = Bytes::from(
            r#"{"device_id":"laptop-001","platform":"macos","name":"Alice laptop","user_identity":"alice@corp"}"#,
        );
        let resp = state
            .dispatch(
                &Method::POST,
                "/api/v1/agent/enroll",
                enroll_payload,
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["status"], "enrolled");
        assert!(v["device_token"]
            .as_str()
            .unwrap()
            .starts_with("bsdmagent_"));
        assert_eq!(v["mtls"], false);

        // mTLS enroll: CSR → client cert when CA is attached.
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let cache =
            crate::tls::CertCache::from_pem(ca_key.serialize_pem().as_bytes(), b"").unwrap();
        state.cert_cache = Some(cache);
        let agent_key = rcgen::KeyPair::generate().unwrap();
        let mut csr_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        csr_params.distinguished_name = rcgen::DistinguishedName::new();
        csr_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "ignored-csr-cn");
        let csr_pem = csr_params
            .serialize_request(&agent_key)
            .unwrap()
            .pem()
            .unwrap();
        let enroll_mtls = serde_json::json!({
            "device_id": "laptop-mtls",
            "platform": "linux",
            "name": "MTLS box",
            "user_identity": "bob@corp",
            "csr_pem": csr_pem,
            "cert_validity_days": 30
        });
        let resp = state
            .dispatch(
                &Method::POST,
                "/api/v1/agent/enroll",
                Bytes::from(enroll_mtls.to_string()),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["mtls"], true);
        assert!(v["client_cert_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE"));
        assert!(v["ca_cert_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE"));
        assert_eq!(v["cert_fingerprint"].as_str().unwrap().len(), 64);

        // Telemetry batch + recent ring buffer.
        let events_payload = Bytes::from(
            r#"{"device_id":"laptop-001","events":[{"domain":"badsite.test","action":"deny","decision_source":"local-agent","reason":"sni"},{"domain":"slack.com","action":"bypass"}]}"#,
        );
        let resp = state
            .dispatch(
                &Method::POST,
                "/api/v1/agent/events",
                events_payload,
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["status"], "accepted");
        assert_eq!(v["accepted"], 2);
        assert_eq!(v["enqueued"], 0);

        let recent = state
            .dispatch(
                &Method::GET,
                "/api/v1/agent/events/recent",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(recent.status(), StatusCode::OK);
        let body = BodyExt::collect(recent.into_body())
            .await
            .unwrap()
            .to_bytes();
        let recent: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(recent["events"].as_array().unwrap().len(), 2);
        assert_eq!(recent["events"][0]["domain"], "slack.com");

        let devices = state
            .dispatch(
                &Method::GET,
                "/api/v1/devices",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(devices.status(), StatusCode::OK);
        let body = BodyExt::collect(devices.into_body())
            .await
            .unwrap()
            .to_bytes();
        let devices: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let alice = devices
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["id"] == "laptop-001")
            .expect("laptop-001 present");
        assert_eq!(alice["name"], "Alice laptop");
        assert_eq!(alice["status"], "Secured");
        assert_eq!(alice["trustScore"], 97);
        assert!(alice["lastSeen"].as_u64().unwrap() > 0);
        assert!(
            devices
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["id"] == "laptop-mtls"),
            "mtls enroll device listed"
        );

        let revoked = state
            .dispatch(
                &Method::POST,
                "/api/v1/devices/laptop-001/revoke",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(revoked.status(), StatusCode::OK);
        let body = BodyExt::collect(revoked.into_body())
            .await
            .unwrap()
            .to_bytes();
        let revoked_body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(revoked_body["persisted"], false);
        let devices = state
            .dispatch(
                &Method::GET,
                "/api/v1/devices",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        let body = BodyExt::collect(devices.into_body())
            .await
            .unwrap()
            .to_bytes();
        let devices: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let alice = devices
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["id"] == "laptop-001")
            .expect("laptop-001 after revoke");
        assert_eq!(alice["status"], "Revoked");

        // Unversioned v0.1 paths remain aliases for existing agents.
        let legacy_policy = state
            .dispatch(
                &Method::GET,
                "/api/agent/policy",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(legacy_policy.status(), StatusCode::OK);
        assert_eq!(legacy_policy.headers()["deprecation"], "true");
        assert_eq!(
            legacy_policy.headers()["link"],
            "</api/v1/agent/policy>; rel=\"successor-version\""
        );

        let legacy_heartbeat = state
            .dispatch(
                &Method::POST,
                "/api/agent/heartbeat",
                Bytes::from(
                    r#"{"device_id":"legacy-001","status":"healthy","agent_version":"0.1.0"}"#,
                ),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(legacy_heartbeat.status(), StatusCode::OK);
        assert_eq!(legacy_heartbeat.headers()["deprecation"], "true");
        assert_eq!(
            legacy_heartbeat.headers()["link"],
            "</api/v1/agent/heartbeat>; rel=\"successor-version\""
        );

        let unsupported_version = state
            .dispatch(
                &Method::GET,
                "/api/v2/agent/policy",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(unsupported_version.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn agent_devices_persist_across_reload() {
        let dir = std::env::temp_dir().join(format!(
            "bsdm-agent-devices-{}-{}",
            std::process::id(),
            unix_timestamp()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("devices.json");

        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let mut state = state_plain(metrics.clone(), cache.clone());
        state.device_registry = DeviceRegistry::with_path(path.clone());

        let hb_payload = Bytes::from(
            r#"{"device_id":"persist-001","name":"Persist laptop","status":"healthy","agent_version":"0.1.0","policy_version":"v0.1.0","trust_score":88}"#,
        );
        let resp = state
            .dispatch(
                &Method::POST,
                "/api/v1/agent/heartbeat",
                hb_payload,
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["persisted"], true);
        assert!(path.exists());

        // Simulate process restart via file reload.
        let loaded = crate::device_registry::load(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded["persist-001"].name, "Persist laptop");
        assert!(!loaded["persist-001"].revoked);

        let mut reloaded = state_plain(metrics, cache);
        reloaded.device_registry = DeviceRegistry::from_map(loaded, Some(path.clone()));

        let revoke = reloaded
            .dispatch(
                &Method::POST,
                "/api/v1/devices/persist-001/revoke",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(revoke.status(), StatusCode::OK);
        let body = BodyExt::collect(revoke.into_body())
            .await
            .unwrap()
            .to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["persisted"], true);

        let again = crate::device_registry::load(&path).unwrap();
        assert!(again["persist-001"].revoked);

        let _ = std::fs::remove_dir_all(&dir);
    }

    static CONFIG_ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn config_apply_writes_env_and_schedules_restart() {
        let _guard = CONFIG_ENV_MUTEX.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let env_path = temp.path().join("bsdm-proxy.env");
        std::env::set_var("CONFIG_ENV_PATH", env_path.to_string_lossy().to_string());

        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let state = state_plain(metrics, cache).with_config_apply(shutdown_tx, None);

        let payload = Bytes::from(
            r#"{"env":{"HTTP_PORT":"3128","METRICS_PORT":"9090","RKN_SYNC_URL":"https://svn.code.sf.net/p/zapret-info/code/dump.csv"},"restart":true}"#,
        );
        let resp = state
            .dispatch(
                &Method::POST,
                "/api/config/apply",
                payload,
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "applied");
        assert_eq!(json["restart"], "scheduled");

        let written = std::fs::read_to_string(&env_path).unwrap();
        assert!(written.contains("HTTP_PORT=3128"));
        assert!(written.contains("RKN_SYNC_URL="));

        tokio::time::timeout(std::time::Duration::from_secs(2), shutdown_rx.changed())
            .await
            .expect("shutdown signal")
            .expect("channel open");
        assert!(*shutdown_rx.borrow());

        std::env::remove_var("CONFIG_ENV_PATH");
    }

    #[tokio::test]
    async fn config_get_returns_snapshot() {
        let _guard = CONFIG_ENV_MUTEX.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let env_path = temp.path().join("bsdm-proxy.env");
        std::fs::write(&env_path, "HTTP_PORT=3128\nCONTROL_API_TOKEN=secret\n").unwrap();
        std::env::set_var("CONFIG_ENV_PATH", env_path.to_string_lossy().to_string());

        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let state = state_plain(metrics, cache);

        let resp = state
            .dispatch(&Method::GET, "/api/config", Bytes::new(), &HeaderMap::new())
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["env"]["HTTP_PORT"], "3128");
        assert_eq!(json["env"]["CONTROL_API_TOKEN"], "***");

        std::env::remove_var("CONFIG_ENV_PATH");
    }

    #[tokio::test]
    async fn pinning_registry_status_and_reload_validation() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let state = state_plain(metrics, cache);

        let status = state
            .dispatch(
                &Method::GET,
                "/api/pinning/exceptions",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(status.status(), StatusCode::OK);
        let body = BodyExt::collect(status.into_body())
            .await
            .unwrap()
            .to_bytes();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["source"], "environment");
        assert_eq!(payload["count"], 0);

        let reload = state
            .dispatch(
                &Method::POST,
                "/api/pinning/exceptions/reload",
                Bytes::from_static(br#"{"actor":"alice","reason":"SEC-42 approved"}"#),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(reload.status(), StatusCode::BAD_REQUEST);
        let body = BodyExt::collect(reload.into_body())
            .await
            .unwrap()
            .to_bytes();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(payload["error"]
            .as_str()
            .unwrap()
            .contains("PINNING_EXCEPTIONS_PATH"));
    }
}
