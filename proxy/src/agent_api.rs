//! Agent Contract HTTP surface (control-plane handlers).
//!
//! Extracted from `control_api` so Phase C agent routes (policy, enroll,
//! heartbeat, events, devices, CRL, OCSP) live next to domain modules
//! (`device_registry`, `agent_crl`, …) without bloating the general control API.

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::header::HeaderValue;
use hyper::{Method, Response, StatusCode};
use serde::Deserialize;
use std::time::Duration;
use tracing::{info, warn};

use crate::agent_events::AgentEventBatch;
use crate::agent_ocsp;
use crate::control_api::{escape_json, json_response, ControlApiState};
use crate::device_registry::{EnrollError, EnrollRequest, HeartbeatUpdate, RevokeError};
use crate::http_types::{full, Body};

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
    /// Dispatch Agent Contract + device inventory routes.
    /// Returns `Some` when the path is agent-owned (including 404 for unknown
    /// agent sub-paths is not done here — only known routes).
    pub(crate) async fn dispatch_agent(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
        body: Bytes,
    ) -> Option<Response<Body>> {
        if method == Method::GET && path == "/api/v1/devices" {
            return Some(self.registered_devices());
        }
        if method == Method::POST {
            if let Some(device_id) = path
                .strip_prefix("/api/v1/devices/")
                .and_then(|p| p.strip_suffix("/revoke"))
            {
                return Some(self.revoke_device(device_id));
            }
        }

        let resp = match (method, path) {
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
            (&Method::POST, "/api/v1/agent/ocsp") => self.agent_ocsp_der(body),
            (&Method::GET, "/api/v1/agent/ocsp") => self.agent_ocsp_der_get(query),
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
            _ => return None,
        };
        Some(resp)
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

    /// WebSocket policy push (`GET /api/v1/agent/policy/ws` + Upgrade).
    ///
    /// Protocol: server sends JSON text frames (full policy document). Client may
    /// send `{"type":"ping"}` (optional); server replies `{"type":"pong"}`.
    /// First frame is the current snapshot; later frames on each publish.
    pub(crate) fn agent_policy_ws_upgrade(
        &self,
        req: &mut hyper::Request<hyper::body::Incoming>,
    ) -> Response<Body> {
        use futures_util::{SinkExt, StreamExt};
        use hyper_tungstenite::tungstenite::Message;
        use std::convert::Infallible;

        let hub = self.policy_hub.clone();
        let (response, websocket) = match hyper_tungstenite::upgrade(req, None) {
            Ok(pair) => pair,
            Err(e) => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({ "error": format!("websocket upgrade: {e}") }).to_string(),
                );
            }
        };

        tokio::spawn(async move {
            let mut ws = match websocket.await {
                Ok(ws) => ws,
                Err(e) => {
                    warn!(error = %e, "agent policy websocket handshake failed");
                    return;
                }
            };

            let mut last = hub.snapshot().version;
            let initial = hub.snapshot();
            let payload = initial.document.to_string();
            if ws.send(Message::text(payload)).await.is_err() {
                return;
            }

            let notify = hub.notify_handle();
            let mut ping = tokio::time::interval(Duration::from_secs(20));
            loop {
                tokio::select! {
                    _ = notify.notified() => {
                        let snap = hub.snapshot();
                        if snap.version == last {
                            continue;
                        }
                        last = snap.version.clone();
                        if ws.send(Message::text(snap.document.to_string())).await.is_err() {
                            break;
                        }
                    }
                    msg = ws.next() => {
                        match msg {
                            Some(Ok(Message::Text(t))) => {
                                if t.contains("ping") {
                                    let _ = ws
                                        .send(Message::text(r#"{"type":"pong"}"#))
                                        .await;
                                }
                            }
                            Some(Ok(Message::Ping(p))) => {
                                let _ = ws.send(Message::Pong(p)).await;
                            }
                            Some(Ok(Message::Close(_))) | None => break,
                            Some(Ok(_)) => {}
                            Some(Err(_)) => break,
                        }
                    }
                    _ = ping.tick() => {
                        if ws
                            .send(Message::Ping(Bytes::from_static(b"bsdm")))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        });

        let (parts, body) = response.into_parts();
        let body = body.map_err(|e: Infallible| match e {}).boxed();
        Response::from_parts(parts, body)
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

    /// RFC 6960 DER OCSP responder (`POST application/ocsp-request`).
    fn agent_ocsp_der(&self, body: Bytes) -> Response<Body> {
        let Some(cache) = self.cert_cache.as_ref() else {
            let der = agent_ocsp::error_response_der(x509_ocsp::OcspResponseStatus::InternalError);
            return ocsp_der_response(der);
        };
        match agent_ocsp::respond_der(&body, cache, &self.agent_crl, &self.device_registry) {
            Ok(der) => ocsp_der_response(der),
            Err(e) => {
                warn!(error = %e, "OCSP DER request failed");
                let der =
                    agent_ocsp::error_response_der(x509_ocsp::OcspResponseStatus::MalformedRequest);
                ocsp_der_response(der)
            }
        }
    }

    /// RFC 6960 GET with base64 request: `?b64=` (standard or URL-safe).
    fn agent_ocsp_der_get(&self, query: Option<&str>) -> Response<Body> {
        let mut b64: Option<String> = None;
        if let Some(q) = query {
            for pair in q.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    if k == "b64" && !v.is_empty() {
                        b64 = Some(v.to_string());
                    }
                }
            }
        }
        let Some(b64) = b64 else {
            return json_response(
                StatusCode::BAD_REQUEST,
                r#"{"error":"GET /api/v1/agent/ocsp requires ?b64= (base64 OCSP request); prefer POST"}"#,
            );
        };
        match agent_ocsp::decode_b64_request(&b64) {
            Ok(der) => self.agent_ocsp_der(Bytes::from(der)),
            Err(e) => json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({ "error": e }).to_string(),
            ),
        }
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
                            "policy_ws": "/api/v1/agent/policy/ws",
                            "policy_stream": "/api/v1/agent/policy/stream",
                            "policy_watch": "/api/v1/agent/policy/watch",
                            "heartbeat": "/api/v1/agent/heartbeat",
                            "events": "/api/v1/agent/events",
                            "crl": "/api/v1/agent/crl",
                            "ocsp": "/api/v1/agent/ocsp",
                            "ocsp_status": "/api/v1/agent/ocsp/status",
                        },
                        "ocsp_status_url": cert_fingerprint.as_ref().map(|fp| {
                            format!("/api/v1/agent/ocsp/status?fingerprint={fp}")
                        }),
                        "ocsp_der_url": "/api/v1/agent/ocsp",
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

fn ocsp_der_response(der: Vec<u8>) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/ocsp-response")
        .header("Cache-Control", "max-age=60, public")
        .body(full(Bytes::from(der)))
        .unwrap_or_else(|_| {
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"ocsp response body"}"#,
            )
        })
}
