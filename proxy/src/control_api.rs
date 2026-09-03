//! Control-plane REST helpers: Lite JSON stats, L1 cache purge, hierarchy peer reload (DX Phase 2).

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, LOCATION};
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::acl_api::AclApiState;
use crate::agent_crl::AgentCrl;
use crate::agent_events::AgentEventIngestor;
use crate::agent_policy_hub::PolicyHub;
use crate::cache_key::http_cache_key;
use crate::device_registry::DeviceRegistry;
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

    fn ebpf_get_config(&self) -> Response<Body> {
        let cfg = self.ebpf_manager.config();
        match serde_json::to_string(&cfg) {
            Ok(json) => json_response(StatusCode::OK, &json),
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(r#"{{"error":"{}"}}"#, e),
            ),
        }
    }

    async fn ebpf_put_config(&self, body: Bytes) -> Response<Body> {
        match serde_json::from_slice::<crate::ebpf::EbpfXdpConfig>(&body) {
            Ok(new_cfg) => match self.ebpf_manager.update_config(new_cfg) {
                Ok(()) => self.ebpf_get_config(),
                Err(err) => json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!(r#"{{"error":"{}"}}"#, err),
                ),
            },
            Err(e) => json_response(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"Invalid eBPF config JSON: {}"}}"#, e),
            ),
        }
    }

    fn ebpf_get_stats(&self) -> Response<Body> {
        let stats = self.ebpf_manager.stats();
        match serde_json::to_string(&stats) {
            Ok(json) => json_response(StatusCode::OK, &json),
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(r#"{{"error":"{}"}}"#, e),
            ),
        }
    }

    fn ebpf_list_ips(&self) -> Response<Body> {
        let ips = self.ebpf_manager.list_blocked_ips();
        match serde_json::to_string(&ips) {
            Ok(json) => json_response(StatusCode::OK, &json),
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(r#"{{"error":"{}"}}"#, e),
            ),
        }
    }

    async fn ebpf_block_ip(&self, body: Bytes) -> Response<Body> {
        #[derive(Deserialize)]
        struct BlockReq {
            ip: String,
            reason: Option<String>,
        }

        match serde_json::from_slice::<BlockReq>(&body) {
            Ok(req) => match req.ip.trim().parse::<std::net::IpAddr>() {
                Ok(ip) => match self.ebpf_manager.block_ip(ip, req.reason) {
                    Ok(entry) => {
                        self.metrics
                            .ebpf_blocked_ips
                            .set(self.ebpf_manager.stats().active_blocked_ips as f64);
                        match serde_json::to_string(&entry) {
                            Ok(json) => json_response(StatusCode::CREATED, &json),
                            Err(e) => json_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                &format!(r#"{{"error":"{}"}}"#, e),
                            ),
                        }
                    }
                    Err(e) => json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!(r#"{{"error":"{}"}}"#, e),
                    ),
                },
                Err(_) => json_response(
                    StatusCode::BAD_REQUEST,
                    r#"{"error":"Invalid IP address format (must be IPv4 or IPv6)"}"#,
                ),
            },
            Err(e) => json_response(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"Invalid block request JSON: {}"}}"#, e),
            ),
        }
    }

    fn ebpf_delete_ip(&self, id_or_ip: &str) -> Response<Body> {
        if self.ebpf_manager.unblock_ip(id_or_ip) {
            self.metrics
                .ebpf_blocked_ips
                .set(self.ebpf_manager.stats().active_blocked_ips as f64);
            json_response(StatusCode::OK, r#"{"status":"deleted"}"#)
        } else {
            json_response(StatusCode::NOT_FOUND, r#"{"error":"Blocked IP not found"}"#)
        }
    }

    fn ebpf_clear_ips(&self) -> Response<Body> {
        self.ebpf_manager.clear();
        self.metrics.ebpf_blocked_ips.set(0.0);
        json_response(StatusCode::OK, r#"{"status":"cleared"}"#)
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
                if let Err(err) = crate::amneziawg::validate_server_config(&config) {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        &serde_json::json!({"error": err}).to_string(),
                    );
                }
                let mut guard = self.awg_server.write().await;
                *guard = config;
                let conf_path = std::env::var("AWG_CONFIG_PATH")
                    .unwrap_or_else(|_| "./certs/awg/awg0.conf".to_string());
                let path = std::path::Path::new(&conf_path);
                let (reload_msg, is_err) =
                    match crate::amneziawg::sync_sidecar_interface(path, &mut guard) {
                        Ok(msg) => (msg, false),
                        Err(err) => (err, true),
                    };
                let status_lbl = if is_err { "error" } else { "success" };
                self.metrics
                    .awg_reloads_total
                    .with_label_values(&[status_lbl])
                    .inc();
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
            Ok(mut peer) => {
                if let Err(e) = crate::amneziawg::validate_key_b64(&peer.public_key) {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        &serde_json::json!({"error": format!("Invalid public key: {e}")})
                            .to_string(),
                    );
                }
                if let Some(psk) = &peer.preshared_key {
                    if !psk.trim().is_empty() {
                        if let Err(e) = crate::amneziawg::validate_key_b64(psk) {
                            return json_response(
                                StatusCode::BAD_REQUEST,
                                &serde_json::json!({"error": format!("Invalid pre-shared key: {e}")}).to_string(),
                            );
                        }
                    }
                }
                peer.name = crate::amneziawg::sanitize_config_string(&peer.name);
                peer.id = crate::amneziawg::sanitize_config_string(&peer.id);
                if peer.id.is_empty() {
                    peer.id = format!("peer-{}", hex::encode(rand::random::<[u8; 4]>()));
                }

                let mut guard = self.awg_server.write().await;
                guard.peers.retain(|p| p.id != peer.id);
                guard.peers.push(peer);
                let conf_path = std::env::var("AWG_CONFIG_PATH")
                    .unwrap_or_else(|_| "./certs/awg/awg0.conf".to_string());
                let path = std::path::Path::new(&conf_path);
                let (reload_msg, is_err) =
                    match crate::amneziawg::sync_sidecar_interface(path, &mut guard) {
                        Ok(msg) => (msg, false),
                        Err(err) => (err, true),
                    };
                let status_lbl = if is_err { "error" } else { "success" };
                self.metrics
                    .awg_reloads_total
                    .with_label_values(&[status_lbl])
                    .inc();
                crate::amneziawg::update_telemetry_metrics(&guard, &self.metrics);
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

    fn amneziawg_generate_psk(&self) -> Response<Body> {
        let psk = crate::amneziawg::generate_preshared_key();
        let payload = serde_json::json!({
            "preshared_key": psk,
        });
        json_response(StatusCode::OK, &payload.to_string())
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
                let (reload_msg, is_err) =
                    match crate::amneziawg::sync_sidecar_interface(path, &mut guard) {
                        Ok(msg) => (msg, false),
                        Err(err) => (err, true),
                    };
                let status_lbl = if is_err { "error" } else { "success" };
                self.metrics
                    .awg_reloads_total
                    .with_label_values(&[status_lbl])
                    .inc();
                crate::amneziawg::update_telemetry_metrics(&guard, &self.metrics);
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

    async fn amneziawg_peer_config(&self, peer_id: &str) -> Response<Body> {
        let guard = self.awg_server.read().await;
        let Some(peer) = guard.peers.iter().find(|p| p.id == peer_id) else {
            return json_response(StatusCode::NOT_FOUND, r#"{"error":"peer not found"}"#);
        };

        let server_endpoint = std::env::var("AWG_SERVER_ENDPOINT")
            .unwrap_or_else(|_| format!("127.0.0.1:{}", guard.listen_port));
        let client_priv = peer
            .private_key
            .as_deref()
            .unwrap_or("CLIENT_PRIVATE_KEY_HERE");
        let conf = crate::amneziawg::generate_client_conf(
            &guard.public_key,
            &server_endpoint,
            peer,
            &guard.obfuscation,
            client_priv,
        );

        Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(
                hyper::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}.conf\"", peer.id),
            )
            .body(full(Bytes::from(conf)))
            .unwrap_or_else(|_| {
                json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    r#"{"error":"conf body error"}"#,
                )
            })
    }

    fn amneziawg_generate_keys(&self) -> Response<Body> {
        let (priv_k, pub_k) = crate::amneziawg::generate_keypair();
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "private_key": priv_k,
                "public_key": pub_k,
            })
            .to_string(),
        )
    }

    async fn amneziawg_telemetry(&self, body: Bytes) -> Response<Body> {
        #[derive(serde::Deserialize)]
        struct TelemetryReq {
            #[serde(default)]
            dump: Option<String>,
        }
        let dump_str = match serde_json::from_slice::<TelemetryReq>(&body) {
            Ok(req) => req.dump.unwrap_or_default(),
            Err(_) => String::from_utf8_lossy(&body).to_string(),
        };

        let telemetry_map = crate::amneziawg::parse_interface_telemetry(&dump_str);
        let mut guard = self.awg_server.write().await;
        for peer in &mut guard.peers {
            if let Some(t) = telemetry_map.get(&peer.public_key) {
                peer.rx_bytes = t.rx_bytes;
                peer.tx_bytes = t.tx_bytes;
                peer.latest_handshake_secs = t.latest_handshake_secs;
            }
        }
        crate::amneziawg::update_telemetry_metrics(&guard, &self.metrics);

        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "status": "updated",
                "peers_updated": telemetry_map.len(),
            })
            .to_string(),
        )
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

    fn circuit_breaker_status(&self) -> Response<Body> {
        let status = self.mitm_circuit_breaker.status();
        match serde_json::to_string(&status) {
            Ok(json) => json_response(StatusCode::OK, &json),
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(r#"{{"error":"{}"}}"#, escape_json(&e.to_string())),
            ),
        }
    }

    fn circuit_breaker_reset(&self, body: Bytes) -> Response<Body> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ResetRequest {
            #[serde(default = "default_all_domains")]
            domain: String,
            actor: String,
            reason: String,
        }
        fn default_all_domains() -> String {
            "*".into()
        }

        let request: ResetRequest = match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(e) => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({
                        "error": format!("invalid reset payload: {e}"),
                    })
                    .to_string(),
                );
            }
        };

        match self
            .mitm_circuit_breaker
            .reset(&request.domain, &request.actor, &request.reason)
        {
            Ok(report) => match serde_json::to_string(&report) {
                Ok(payload) => json_response(StatusCode::OK, &payload),
                Err(e) => json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &serde_json::json!({"error": e.to_string()}).to_string(),
                ),
            },
            Err(error) => json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({"error": error}).to_string(),
            ),
        }
    }

    fn pinning_upsert_exception(&self, body: Bytes) -> Response<Body> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct UpsertRequest {
            actor: String,
            change_reason: String,
            exception: crate::pinning::PinningException,
        }

        let request: UpsertRequest = match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(e) => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({
                        "error": format!("invalid upsert payload: {e}"),
                    })
                    .to_string(),
                );
            }
        };

        match self.pinning_registry.upsert_exception(
            &request.actor,
            &request.change_reason,
            request.exception,
        ) {
            Ok(report) => {
                info!(
                    actor = %request.actor,
                    reason = %request.change_reason,
                    "Pinning exception upserted via control API"
                );
                let _ = self.policy_hub.publish_from_runtime(
                    &self.pinning_registry,
                    &format!("pinning-upsert:{}", request.change_reason),
                );
                match serde_json::to_string(&report) {
                    Ok(payload) => json_response(StatusCode::OK, &payload),
                    Err(e) => json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &serde_json::json!({"error": e.to_string()}).to_string(),
                    ),
                }
            }
            Err(error) => json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({"error": error}).to_string(),
            ),
        }
    }

    fn pinning_delete_exception(&self, body: Bytes) -> Response<Body> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct DeleteRequest {
            actor: String,
            change_reason: String,
            domain: String,
        }

        let request: DeleteRequest = match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(e) => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({
                        "error": format!("invalid delete payload: {e}"),
                    })
                    .to_string(),
                );
            }
        };

        match self.pinning_registry.remove_exception(
            &request.actor,
            &request.change_reason,
            &request.domain,
        ) {
            Ok(report) => {
                info!(
                    actor = %request.actor,
                    reason = %request.change_reason,
                    domain = %request.domain,
                    "Pinning exception deleted via control API"
                );
                let _ = self.policy_hub.publish_from_runtime(
                    &self.pinning_registry,
                    &format!("pinning-delete:{}", request.change_reason),
                );
                match serde_json::to_string(&report) {
                    Ok(payload) => json_response(StatusCode::OK, &payload),
                    Err(e) => json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &serde_json::json!({"error": e.to_string()}).to_string(),
                    ),
                }
            }
            Err(error) => json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({"error": error}).to_string(),
            ),
        }
    }
}

#[derive(Clone)]
pub struct ControlApiState {
    pub(crate) metrics: Arc<Metrics>,
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
    pub(crate) pinning_registry: Arc<PinningRegistry>,
    pub(crate) mitm_circuit_breaker: Arc<crate::mitm_breaker::MitmCircuitBreaker>,
    auth_manager: Option<Arc<crate::auth::AuthManager>>,
    pub(crate) awg_server: Arc<tokio::sync::RwLock<crate::amneziawg::AwgServerConfig>>,
    session_store: crate::session_store::GlobalSessionStore,
    threat_sync: crate::threat_sync::ThreatSyncEngine,
    admin_console_dir: Option<std::path::PathBuf>,
    pub(crate) device_registry: DeviceRegistry,
    pub(crate) agent_events: AgentEventIngestor,
    pub(crate) agent_crl: AgentCrl,
    pub(crate) policy_hub: PolicyHub,
    /// Bootstrap token for `POST /api/v1/agent/enroll` (`AGENT_ENROLL_TOKEN`).
    /// Falls back to control `api_token` when unset.
    enroll_token: Option<String>,
    /// CA used to sign agent client certs from CSR (shared MITM CA by default).
    pub(crate) cert_cache: Option<CertCache>,
    shutdown_tx: Option<watch::Sender<bool>>,
    acl_api: Option<Arc<AclApiState>>,
    rpz_api: Option<Arc<crate::rpz_api::RpzApiState>>,
    pub(crate) ebpf_manager: Arc<crate::ebpf::EbpfXdpManager>,
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
            mitm_circuit_breaker: Arc::new(crate::mitm_breaker::MitmCircuitBreaker::from_env()),
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
            rpz_api: Some(crate::rpz_api::RpzApiState::from_env()),
            ebpf_manager: Arc::new(crate::ebpf::EbpfXdpManager::new(
                crate::ebpf::EbpfXdpConfig::from_env(),
            )),
        }
    }

    /// Attach eBPF XDP manager to ControlApiState.
    pub fn with_ebpf_manager(mut self, manager: Arc<crate::ebpf::EbpfXdpManager>) -> Self {
        self.ebpf_manager = manager;
        self
    }

    /// Attach MitmCircuitBreaker from ProxyService.
    pub fn with_mitm_circuit_breaker(
        mut self,
        breaker: Arc<crate::mitm_breaker::MitmCircuitBreaker>,
    ) -> Self {
        self.mitm_circuit_breaker = breaker;
        self
    }

    /// Attach CertCache so enroll can sign mTLS client certificates from CSR.
    pub fn with_cert_cache(mut self, cert_cache: CertCache) -> Self {
        self.cert_cache = Some(cert_cache);
        self
    }

    /// Attach Redis multi-node backends for device registry + agent CRL.
    pub async fn with_agent_multi_node_redis(
        mut self,
        conn: redis::aio::ConnectionManager,
    ) -> Self {
        if let Err(e) = self.device_registry.attach_redis(conn.clone()).await {
            warn!(error = %e, "Agent device multi-node Redis attach failed");
        }
        if let Err(e) = self.agent_crl.attach_redis(conn).await {
            warn!(error = %e, "Agent CRL multi-node Redis attach failed");
        }
        self
    }

    pub fn agent_devices_multi_node(&self) -> bool {
        self.device_registry.is_multi_node()
    }

    pub fn agent_crl_multi_node(&self) -> bool {
        self.agent_crl.is_multi_node()
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

    pub async fn handle_request(&self, mut req: Request<Incoming>) -> Response<Body> {
        // WebSocket policy push must upgrade before body is consumed.
        let path = req.uri().path();
        if path == "/api/v1/agent/policy/ws"
            && req.method() == Method::GET
            && hyper_tungstenite::is_upgrade_request(&req)
        {
            if !self.is_agent_authorized(req.headers()) {
                return json_response(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#);
            }
            return self.agent_policy_ws_upgrade(&mut req);
        }

        const MAX_CONTROL_API_BODY_BYTES: usize = 16 * 1024 * 1024; // 16 MB cap

        let (parts, body) = req.into_parts();
        let limited = http_body_util::Limited::new(body, MAX_CONTROL_API_BODY_BYTES);
        let body = match BodyExt::collect(limited).await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                warn!("Control API body read error or payload too large: {e}");
                return json_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    r#"{"error":"payload too large or read error"}"#,
                );
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
        let (p, q) = match path.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path, None),
        };
        self.dispatch_with_query(method, p, q, body, headers).await
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
                    // RFC 6960 OCSP is intentionally unauthenticated (status only).
                    | (&Method::POST, "/api/v1/agent/ocsp")
                    | (&Method::GET, "/api/v1/agent/ocsp")
            ) || (*method == Method::OPTIONS
                && (path.starts_with("/api/search") || path == "/api/events"));
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

        if let Some(resp) = self.dispatch_agent(method, path, query, body.clone()).await {
            return resp;
        }

        let query_str = query.unwrap_or("");

        // Same-origin Search/Ingest for Admin Console (optional upstream).
        // OPTIONS preflight is covered by the same paths and handled downstream.
        if path.starts_with("/api/search") || path == "/api/events" {
            return crate::search_proxy::proxy_search_request(
                method,
                path,
                query_str,
                headers,
                body.clone(),
            )
            .await;
        }

        if let Some(rpz) = &self.rpz_api {
            if let Some(resp) = rpz.dispatch(method, path, query_str, body.clone()).await {
                return resp;
            }
        }

        if method == Method::GET {
            if let Some(peer_id) = path.strip_prefix("/api/amneziawg/peers/").and_then(|p| {
                p.strip_suffix("/config")
                    .or_else(|| p.strip_suffix("/conf"))
            }) {
                return self.amneziawg_peer_config(peer_id).await;
            }
        }

        if method == Method::DELETE {
            if let Some(id) = path.strip_prefix("/api/ebpf/ips/") {
                return self.ebpf_delete_ip(id);
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
            (&Method::GET, "/api/ebpf/config") => self.ebpf_get_config(),
            (&Method::PUT, "/api/ebpf/config") => self.ebpf_put_config(body).await,
            (&Method::GET, "/api/ebpf/stats") => self.ebpf_get_stats(),
            (&Method::GET, "/api/ebpf/ips") => self.ebpf_list_ips(),
            (&Method::POST, "/api/ebpf/ips") => self.ebpf_block_ip(body).await,
            (&Method::DELETE, "/api/ebpf/ips") => self.ebpf_clear_ips(),
            (&Method::GET, "/api/auth/basic/users") => self.basic_users_list().await,
            (&Method::POST, "/api/auth/basic/users") => self.basic_users_put(body).await,
            (&Method::DELETE, "/api/auth/basic/users") => self.basic_users_delete(body).await,
            (&Method::GET, "/api/amneziawg/config") | (&Method::GET, "/api/amneziawg/status") => {
                self.amneziawg_status().await
            }
            (&Method::POST, "/api/amneziawg/config") => self.amneziawg_update(body).await,
            (&Method::POST, "/api/amneziawg/peers") => self.amneziawg_add_peer(body).await,
            (&Method::DELETE, "/api/amneziawg/peers") => self.amneziawg_delete_peer(body).await,
            (&Method::POST, "/api/amneziawg/generate-keys") => self.amneziawg_generate_keys(),
            (&Method::POST, "/api/amneziawg/generate-psk") => self.amneziawg_generate_psk(),
            (&Method::POST, "/api/amneziawg/telemetry") => self.amneziawg_telemetry(body).await,
            (&Method::GET, "/api/cluster/session-state") => self.cluster_session_state(),
            (&Method::GET, "/api/threats/sync/peers") => self.threat_sync_peers(),
            (&Method::POST, "/api/threats/sync/broadcast") => {
                self.threat_sync_broadcast(body).await
            }
            (&Method::GET, "/api/pinning/exceptions") => self.pinning_exceptions(),
            (&Method::POST, "/api/pinning/exceptions") => self.pinning_upsert_exception(body),
            (&Method::DELETE, "/api/pinning/exceptions") => self.pinning_delete_exception(body),
            (&Method::POST, "/api/pinning/exceptions/reload") => self.pinning_reload(body),
            (&Method::GET, "/api/mitm/circuit-breaker")
            | (&Method::GET, "/api/pinning/circuit-breaker") => self.circuit_breaker_status(),
            (&Method::POST, "/api/mitm/circuit-breaker/reset")
            | (&Method::POST, "/api/pinning/circuit-breaker/reset") => {
                self.circuit_breaker_reset(body)
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
                    .header("X-Content-Type-Options", "nosniff")
                    .header("X-Frame-Options", "SAMEORIGIN")
                    .header("Referrer-Policy", "strict-origin-when-cross-origin")
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

pub(crate) fn json_response(status: StatusCode, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json; charset=utf-8")
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .header("Referrer-Policy", "no-referrer")
        .header("Cache-Control", "no-store, no-cache, must-revalidate")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'",
        )
        .body(full(Bytes::from(body.to_string())))
        .unwrap_or_else(|_| Response::new(full(Bytes::from_static(b"500 Internal Server Error"))))
}

#[cfg(test)]
fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn escape_json(value: &str) -> String {
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

        let mutating_endpoints = [
            (&Method::POST, "/api/config/apply", "{}"),
            (&Method::POST, "/api/hierarchy/reload", "{}"),
            (&Method::POST, "/api/upstream/tls/reload", "{}"),
            (&Method::POST, "/api/security/casb", "[]"),
            (&Method::POST, "/api/security/dlp", "[]"),
            (&Method::POST, "/api/auth/basic/users", "{}"),
            (&Method::DELETE, "/api/auth/basic/users", "{}"),
            (&Method::POST, "/api/pinning/exceptions", "{}"),
            (&Method::DELETE, "/api/pinning/exceptions", "{}"),
            (&Method::POST, "/api/pinning/exceptions/reload", "{}"),
            (&Method::POST, "/api/mitm/circuit-breaker/reset", "{}"),
        ];

        for (method, path, body) in mutating_endpoints {
            let res = state
                .dispatch(
                    method,
                    path,
                    Bytes::from(body.to_string()),
                    &HeaderMap::new(),
                )
                .await;
            assert_eq!(
                res.status(),
                StatusCode::UNAUTHORIZED,
                "endpoint {method} {path} must deny without token in fail_closed mode"
            );
        }

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
                port: 3128,
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
        // Without an explicit restart command, `schedule_service_restart` falls back
        // to re-executing `current_exe()` — under `cargo test` that is the test
        // binary, so the whole suite forks a fresh copy of itself on every run.
        std::env::set_var("CONFIG_RESTART_CMD", "true");

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

        std::env::remove_var("CONFIG_RESTART_CMD");
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

    #[tokio::test]
    async fn amneziawg_control_api_flow() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let state = state_plain(metrics, cache);

        // 1. Status
        let status = state
            .dispatch(
                &Method::GET,
                "/api/amneziawg/status",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(status.status(), StatusCode::OK);

        // 2. Generate keys
        let gen = state
            .dispatch(
                &Method::POST,
                "/api/amneziawg/generate-keys",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(gen.status(), StatusCode::OK);
        let gen_body = BodyExt::collect(gen.into_body()).await.unwrap().to_bytes();
        let gen_json: serde_json::Value = serde_json::from_slice(&gen_body).unwrap();
        assert!(gen_json["private_key"].as_str().unwrap().len() == 44);
        assert!(gen_json["public_key"].as_str().unwrap().len() == 44);

        // 3. Add Peer
        let add_payload = serde_json::json!({
            "id": "test-awg-peer-1",
            "name": "Test Laptop",
            "public_key": gen_json["public_key"].as_str().unwrap(),
            "private_key": gen_json["private_key"].as_str().unwrap(),
            "allowed_ips": "10.8.0.2/32",
            "assigned_ip": "10.8.0.2",
            "created_at": "2026-08-24",
        });
        let add_resp = state
            .dispatch(
                &Method::POST,
                "/api/amneziawg/peers",
                Bytes::from(add_payload.to_string()),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(add_resp.status(), StatusCode::OK);

        // 4. Download Peer config
        let conf_resp = state
            .dispatch(
                &Method::GET,
                "/api/amneziawg/peers/test-awg-peer-1/config",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(conf_resp.status(), StatusCode::OK);
        let conf_bytes = BodyExt::collect(conf_resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let conf_str = String::from_utf8(conf_bytes.to_vec()).unwrap();
        assert!(conf_str.contains("[Interface]"));
        assert!(conf_str.contains("Address = 10.8.0.2/32"));
        assert!(conf_str.contains("Jc = 4"));
        assert!(conf_str.contains("[Peer]"));

        // 5. Update Telemetry
        let dump_payload = format!(
            "{}\t(none)\t198.51.100.20:51820\t10.8.0.2/32\t1721812900\t1048576\t2097152\t25\n",
            gen_json["public_key"].as_str().unwrap()
        );
        let telem_req = serde_json::json!({ "dump": dump_payload });
        let telem_resp = state
            .dispatch(
                &Method::POST,
                "/api/amneziawg/telemetry",
                Bytes::from(telem_req.to_string()),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(telem_resp.status(), StatusCode::OK);

        // 6. Delete Peer
        let del_resp = state
            .dispatch(
                &Method::DELETE,
                "/api/amneziawg/peers",
                Bytes::from(serde_json::json!({ "id": "test-awg-peer-1" }).to_string()),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(del_resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn agent_enroll_with_tunnel_capability() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let state = state_plain(metrics, cache);

        let enroll_body = serde_json::json!({
            "platform": "macos",
            "name": "Alice MacBook",
            "capabilities": ["local-proxy", "tunnel"],
        });

        let resp = state
            .dispatch(
                &Method::POST,
                "/api/v1/agent/enroll",
                Bytes::from(enroll_body.to_string()),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let device_id = payload["device_id"].as_str().unwrap();

        assert!(payload["tunnel_config"].is_object());
        let tc = &payload["tunnel_config"];
        assert_eq!(tc["assigned_ip"], "10.8.0.2");
        assert!(tc["client_private_key"].as_str().is_some());
        assert!(tc["server_public_key"].as_str().is_some());
        assert!(tc["conf_raw"].as_str().unwrap().contains("[Interface]"));
        assert!(tc["conf_raw"].as_str().unwrap().contains("Jc = 4"));

        // GET /api/v1/agent/tunnel/config
        let get_conf_path = format!("/api/v1/agent/tunnel/config?device_id={device_id}");
        let tunnel_resp = state
            .dispatch(
                &Method::GET,
                &get_conf_path,
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(tunnel_resp.status(), StatusCode::OK);
        let t_body = BodyExt::collect(tunnel_resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let t_json: serde_json::Value = serde_json::from_slice(&t_body).unwrap();
        assert_eq!(t_json["device_id"], device_id);
        assert_eq!(t_json["assigned_ip"], "10.8.0.2");
    }

    #[tokio::test]
    async fn circuit_breaker_control_api_status_and_reset() {
        let state = state_plain(
            Arc::new(Metrics::new().unwrap()),
            Arc::new(HttpL1Cache::new(100, 4)),
        );
        state
            .mitm_circuit_breaker
            .record_attempt("bad.example.com", false, "tls fail");
        state
            .mitm_circuit_breaker
            .record_attempt("bad.example.com", false, "tls fail");
        state
            .mitm_circuit_breaker
            .record_attempt("bad.example.com", false, "tls fail");
        state
            .mitm_circuit_breaker
            .record_attempt("bad.example.com", false, "tls fail");
        state
            .mitm_circuit_breaker
            .record_attempt("bad.example.com", false, "tls fail");

        // GET /api/mitm/circuit-breaker
        let resp = state
            .dispatch(
                &Method::GET,
                "/api/mitm/circuit-breaker",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["tripped_count"], 1);
        assert_eq!(json["tripped_domains"][0]["domain"], "bad.example.com");

        // POST /api/mitm/circuit-breaker/reset
        let reset_payload = serde_json::json!({
            "domain": "bad.example.com",
            "actor": "operator-test",
            "reason": "upstream certificate fixed"
        });
        let reset_resp = state
            .dispatch(
                &Method::POST,
                "/api/mitm/circuit-breaker/reset",
                Bytes::from(reset_payload.to_string()),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(reset_resp.status(), StatusCode::OK);
        let reset_body = BodyExt::collect(reset_resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let reset_json: serde_json::Value = serde_json::from_slice(&reset_body).unwrap();
        assert_eq!(reset_json["status"], "reset");
        assert_eq!(reset_json["reset_domains"][0], "bad.example.com");

        assert!(!state.mitm_circuit_breaker.is_tripped("bad.example.com"));
    }

    #[tokio::test]
    async fn pinning_exceptions_control_api_crud() {
        let state = state_plain(
            Arc::new(Metrics::new().unwrap()),
            Arc::new(HttpL1Cache::new(100, 4)),
        );

        // POST /api/pinning/exceptions
        let add_payload = serde_json::json!({
            "actor": "sec-team",
            "change_reason": "vendor certificate pinning",
            "exception": {
                "domain": "pinned.example.com",
                "reason": "native app pins cert",
                "owner": "sec-ops",
                "ticket": "SEC-555"
            }
        });
        let add_resp = state
            .dispatch(
                &Method::POST,
                "/api/pinning/exceptions",
                Bytes::from(add_payload.to_string()),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(add_resp.status(), StatusCode::OK);
        assert!(state.pinning_registry.matches("pinned.example.com"));

        // GET /api/pinning/exceptions
        let get_resp = state
            .dispatch(
                &Method::GET,
                "/api/pinning/exceptions",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body = BodyExt::collect(get_resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["count"], 1);

        // DELETE /api/pinning/exceptions
        let del_payload = serde_json::json!({
            "actor": "sec-team",
            "change_reason": "exception no longer required",
            "domain": "pinned.example.com"
        });
        let del_resp = state
            .dispatch(
                &Method::DELETE,
                "/api/pinning/exceptions",
                Bytes::from(del_payload.to_string()),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(del_resp.status(), StatusCode::OK);
        assert!(!state.pinning_registry.matches("pinned.example.com"));
    }

    #[tokio::test]
    async fn test_ebpf_control_api_lifecycle() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let mut state = state_plain(metrics, cache);
        state.api_token = Some("secret-token".to_string());
        state.fail_closed = true;

        let mut auth_headers = HeaderMap::new();
        auth_headers.insert(
            AUTHORIZATION,
            "Bearer secret-token".parse().expect("valid header"),
        );

        // 1. GET /api/ebpf/config
        let get_cfg_resp = state
            .dispatch(
                &Method::GET,
                "/api/ebpf/config",
                Bytes::new(),
                &auth_headers,
            )
            .await;
        assert_eq!(get_cfg_resp.status(), StatusCode::OK);
        let body = BodyExt::collect(get_cfg_resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let cfg_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(cfg_json["interface"], "eth0");
        assert_eq!(cfg_json["mode"], "skb");

        // 2. PUT /api/ebpf/config
        let update_cfg = serde_json::json!({
            "enabled": false,
            "interface": "eth1",
            "mode": "driver",
            "mapName": "bsdm_blocked_ips",
            "maxEntries": 32768
        });
        let put_cfg_resp = state
            .dispatch(
                &Method::PUT,
                "/api/ebpf/config",
                Bytes::from(update_cfg.to_string()),
                &auth_headers,
            )
            .await;
        assert_eq!(put_cfg_resp.status(), StatusCode::OK);
        let body = BodyExt::collect(put_cfg_resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let updated_cfg_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(updated_cfg_json["interface"], "eth1");
        assert_eq!(updated_cfg_json["mode"], "driver");

        // 3. GET /api/ebpf/stats
        let stats_resp = state
            .dispatch(&Method::GET, "/api/ebpf/stats", Bytes::new(), &auth_headers)
            .await;
        assert_eq!(stats_resp.status(), StatusCode::OK);
        let body = BodyExt::collect(stats_resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let stats_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(stats_json["activeBlockedIps"], 0);
        assert_eq!(stats_json["packetsDroppedTotal"], 0);

        // 4. POST /api/ebpf/ips with invalid IP -> 400 Bad Request
        let bad_ip_resp = state
            .dispatch(
                &Method::POST,
                "/api/ebpf/ips",
                Bytes::from_static(br#"{"ip":"invalid-ip"}"#),
                &auth_headers,
            )
            .await;
        assert_eq!(bad_ip_resp.status(), StatusCode::BAD_REQUEST);

        // 5. POST /api/ebpf/ips with IPv4 -> 201 Created
        let block_v4 = serde_json::json!({
            "ip": "198.51.100.1",
            "reason": "DDoS flood"
        });
        let block_v4_resp = state
            .dispatch(
                &Method::POST,
                "/api/ebpf/ips",
                Bytes::from(block_v4.to_string()),
                &auth_headers,
            )
            .await;
        assert_eq!(block_v4_resp.status(), StatusCode::CREATED);
        let body = BodyExt::collect(block_v4_resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let v4_entry: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v4_entry["ip"], "198.51.100.1");
        assert_eq!(v4_entry["reason"], "DDoS flood");
        let v4_id = v4_entry["id"].as_str().unwrap().to_string();

        // 6. POST /api/ebpf/ips with IPv6 -> 201 Created
        let block_v6 = serde_json::json!({
            "ip": "2001:db8::99",
            "reason": "Abuse scanning"
        });
        let block_v6_resp = state
            .dispatch(
                &Method::POST,
                "/api/ebpf/ips",
                Bytes::from(block_v6.to_string()),
                &auth_headers,
            )
            .await;
        assert_eq!(block_v6_resp.status(), StatusCode::CREATED);

        // 7. GET /api/ebpf/ips -> 2 entries
        let list_resp = state
            .dispatch(&Method::GET, "/api/ebpf/ips", Bytes::new(), &auth_headers)
            .await;
        assert_eq!(list_resp.status(), StatusCode::OK);
        let body = BodyExt::collect(list_resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let list_json: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(list_json.len(), 2);

        // 8. DELETE /api/ebpf/ips/:id -> 200 OK
        let del_v4_resp = state
            .dispatch(
                &Method::DELETE,
                &format!("/api/ebpf/ips/{}", v4_id),
                Bytes::new(),
                &auth_headers,
            )
            .await;
        assert_eq!(del_v4_resp.status(), StatusCode::OK);

        // 9. DELETE /api/ebpf/ips/:id already deleted -> 404 Not Found
        let del_404_resp = state
            .dispatch(
                &Method::DELETE,
                &format!("/api/ebpf/ips/{}", v4_id),
                Bytes::new(),
                &auth_headers,
            )
            .await;
        assert_eq!(del_404_resp.status(), StatusCode::NOT_FOUND);

        // 10. DELETE /api/ebpf/ips -> clear all
        let clear_resp = state
            .dispatch(
                &Method::DELETE,
                "/api/ebpf/ips",
                Bytes::new(),
                &auth_headers,
            )
            .await;
        assert_eq!(clear_resp.status(), StatusCode::OK);

        let list_after_clear = state
            .dispatch(&Method::GET, "/api/ebpf/ips", Bytes::new(), &auth_headers)
            .await;
        let body = BodyExt::collect(list_after_clear.into_body())
            .await
            .unwrap()
            .to_bytes();
        let list_json: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(list_json.len(), 0);

        // 11. Security check: unauthenticated call should be 401 Unauthorized
        let unauth_resp = state
            .dispatch(
                &Method::POST,
                "/api/ebpf/ips",
                Bytes::from_static(br#"{"ip":"198.51.100.2"}"#),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);
    }
}
