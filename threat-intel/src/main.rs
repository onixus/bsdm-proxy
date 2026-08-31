//! Threat intelligence feed collector (TASK-TI-001).
//!
//! Fetches phishing/malware IOC feeds on a schedule, parses them through
//! per-source plugins, and writes normalized snapshots plus a run report for the
//! downstream IOC store (TASK-TI-002) and scoring engine (TASK-TI-010).

#![allow(dead_code)]

mod api_auth;
mod collector;
mod config;
mod http;
mod indicator;
mod metrics;
mod ml_reputation;
mod normalizer;
mod rpz;
mod scorer;
mod siem;
mod sink;
mod soar;
mod source;
mod sources;
mod storage;

use api_auth::AdminApiSecurity;
use collector::Collector;
use config::{Config, EnforcementMode};
use http::FeedHttpClient;
use metrics::CollectorMetrics;
use prometheus::{Encoder, TextEncoder};
use sink::{CompositeSink, IndicatorSink, JsonlFileSink, SqliteSink};
use std::sync::Arc;
use storage::SqliteStorage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,threat_intel=info".into()),
        )
        .init();

    let config = Config::from_env().map_err(|e| {
        error!("{e}");
        e
    })?;
    let feeds = sources::build(&config.sources, &Config::source_url).map_err(|e| {
        error!("{e}");
        e
    })?;

    let metrics = CollectorMetrics::new()?;
    // Publish the posture itself, so a monitor can tell "observing" from
    // "enforcing" without waiting for someone to call SOAR (ADR 0008).
    for mode in [EnforcementMode::Shadow, EnforcementMode::Enforce] {
        metrics
            .enforcement_mode
            .with_label_values(&[mode.as_str()])
            .set(i64::from(mode == config.enforcement_mode));
    }

    let storage = if config.storage_enabled {
        let st = SqliteStorage::new(&config.sqlite_path)?;
        info!(
            sqlite_path = %config.sqlite_path.display(),
            ttl_secs = config.ioc_ttl_secs,
            "threat-intel SQLite storage initialized"
        );
        Some(st)
    } else {
        None
    };

    let file_sink = Box::new(JsonlFileSink::new(&config.output_dir)?);
    let sink: Arc<dyn IndicatorSink> = match &storage {
        Some(st) => {
            let sqlite_sink = Box::new(SqliteSink::new(st.clone(), config.ioc_ttl_secs));
            Arc::new(CompositeSink::new(vec![file_sink, sqlite_sink]))
        }
        None => Arc::new(JsonlFileSink::new(&config.output_dir)?),
    };

    let http = FeedHttpClient::new(
        config.http_timeout,
        config.max_body_bytes,
        &config.user_agent,
    )?;

    info!(
        sources = ?config.sources,
        output_dir = %config.output_dir.display(),
        sqlite_enabled = config.storage_enabled,
        rpz_enabled = config.rpz_enabled,
        enforcement_mode = config.enforcement_mode.as_str(),
        rpz_artifact = %config.rpz_artifact_path().display(),
        acl_artifact = %config.acl_artifact_path().display(),
        poll_secs = config.poll_interval.as_secs(),
        max_attempts = config.max_attempts,
        run_once = config.run_once,
        "threat-intel collector started"
    );

    let run_once = config.run_once;
    let metrics_port = config.metrics_port;
    let enforcement_mode = config.enforcement_mode;
    let default_confidence = config.soar_default_confidence;
    let max_confidence = config.soar_max_confidence;
    let rpz_path = config.rpz_artifact_path();
    let api_security = Arc::new(AdminApiSecurity::from_env(&config.output_dir));
    let collector = Arc::new(Collector::new(
        config,
        http,
        sink,
        storage.clone(),
        metrics.clone(),
    ));

    if run_once {
        return collector::run_once(collector, feeds)
            .await
            .map_err(|e| e.into());
    }

    let storage_clone = storage.clone();
    tokio::spawn(async move {
        run_admin_server(
            metrics_port,
            metrics,
            storage_clone,
            enforcement_mode,
            api_security,
            default_confidence,
            max_confidence,
            rpz_path,
        )
        .await;
    });

    let handles = collector::spawn_scheduled(collector, feeds);
    for handle in handles {
        let _ = handle.await;
    }
    Ok(())
}

/// Hard limit on the admin HTTP request size (64 KB).
const MAX_ADMIN_REQUEST_BYTES: usize = 64 * 1024;

#[allow(clippy::too_many_arguments)]
async fn run_admin_server(
    port: u16,
    metrics: Arc<CollectorMetrics>,
    storage: Option<SqliteStorage>,
    mode: EnforcementMode,
    security: Arc<AdminApiSecurity>,
    default_confidence: u8,
    max_confidence: u8,
    rpz_path: std::path::PathBuf,
) {
    // Loopback unless TI_ADMIN_BIND says otherwise: the SOAR API must not be
    // reachable from the network by default.
    let bind_addr = format!("{}:{port}", security.bind_host());
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind threat-intel admin on {bind_addr}: {e}");
            return;
        }
    };
    info!("threat-intel admin on {bind_addr} (/metrics, /health, /api/v1/soar/*, /api/v1/ml/*, /api/v1/rpz/*)");

    loop {
        let Ok((mut socket, peer)) = listener.accept().await else {
            continue;
        };
        let metrics = metrics.clone();
        let storage = storage.clone();
        let security = security.clone();
        let rpz_path = rpz_path.clone();
        tokio::spawn(async move {
            match read_http_request(&mut socket, MAX_ADMIN_REQUEST_BYTES).await {
                Ok(req) => {
                    let response = handle_admin(
                        &req,
                        &metrics,
                        storage.as_ref(),
                        mode,
                        &security,
                        &peer.to_string(),
                        default_confidence,
                        max_confidence,
                        &rpz_path,
                    );
                    let _ = socket.write_all(&response).await;
                }
                Err((status, msg)) => {
                    if status != 0 {
                        let err_body = format!("{{\"error\":\"{}\"}}", msg);
                        let response =
                            http_response(status, "application/json", err_body.as_bytes());
                        let _ = socket.write_all(&response).await;
                    }
                }
            }
        });
    }
}

/// Reads a full HTTP request from a stream, honoring `Content-Length` and `max_bytes` ceiling.
async fn read_http_request<R: AsyncReadExt + Unpin>(
    stream: &mut R,
    max_bytes: usize,
) -> Result<String, (u16, &'static str)> {
    let mut buf = Vec::with_capacity(1024);
    let mut temp = [0u8; 1024];

    // 1. Read until the end of the HTTP headers delimiter (\r\n\r\n or \n\n).
    let (header_end_idx, delimiter_len) = loop {
        if let Some(idx) = find_subslice(&buf, b"\r\n\r\n") {
            break (idx, 4);
        }
        if let Some(idx) = find_subslice(&buf, b"\n\n") {
            break (idx, 2);
        }
        if buf.len() >= max_bytes {
            return Err((413, "Payload Too Large"));
        }
        let n = stream
            .read(&mut temp)
            .await
            .map_err(|_| (400, "Read error"))?;
        if n == 0 {
            if buf.is_empty() {
                return Err((0, "Connection closed"));
            }
            return Err((400, "Incomplete HTTP request"));
        }
        let to_take = n.min(max_bytes.saturating_sub(buf.len()) + 1);
        buf.extend_from_slice(&temp[..to_take]);
        if buf.len() > max_bytes {
            return Err((413, "Payload Too Large"));
        }
    };

    let header_bytes = &buf[..header_end_idx];
    let header_str =
        std::str::from_utf8(header_bytes).map_err(|_| (400, "Invalid UTF-8 in headers"))?;

    // 2. Parse Content-Length header if present.
    let content_length = parse_content_length(header_str)?;
    let total_required = header_end_idx + delimiter_len + content_length;
    if total_required > max_bytes {
        return Err((413, "Payload Too Large"));
    }

    // 3. Read remaining body bytes up to total_required.
    while buf.len() < total_required {
        let n = stream
            .read(&mut temp)
            .await
            .map_err(|_| (400, "Read error"))?;
        if n == 0 {
            return Err((400, "Incomplete request body"));
        }
        let needed = total_required - buf.len();
        let to_take = n.min(needed);
        buf.extend_from_slice(&temp[..to_take]);
    }

    buf.truncate(total_required);
    String::from_utf8(buf).map_err(|_| (400, "Invalid UTF-8 in request body"))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_content_length(headers: &str) -> Result<usize, (u16, &'static str)> {
    for line in headers.lines().skip(1) {
        if line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                let val_str = value.trim();
                let len = val_str
                    .parse::<usize>()
                    .map_err(|_| (400, "Invalid Content-Length"))?;
                return Ok(len);
            }
        }
    }
    Ok(0)
}

#[allow(clippy::too_many_arguments)]
fn handle_admin(
    req: &str,
    metrics: &CollectorMetrics,
    storage: Option<&SqliteStorage>,
    mode: EnforcementMode,
    security: &AdminApiSecurity,
    peer: &str,
    default_confidence: u8,
    max_confidence: u8,
    rpz_path: &std::path::Path,
) -> Vec<u8> {
    let mut lines = req.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

    // SOAR endpoints (/api/v1/soar/*) require token authentication.
    // Mutating endpoints are fail-closed to prevent unauthorized indicator injection;
    // investigate is protected to prevent unauthorized IOC database enumeration.
    let is_soar = path.starts_with("/api/v1/soar/");
    if is_soar && !security.is_request_authorized(req) {
        if method == "POST" {
            let action = if path.starts_with("/api/v1/soar/unblock") {
                "unblock"
            } else {
                "block"
            };
            audit_soar(security, req, peer, action, mode, "denied");
            warn!(peer = %peer, path = %path, "unauthorized SOAR mutation rejected");
        } else {
            warn!(peer = %peer, path = %path, "unauthorized SOAR request rejected");
        }
        return unauthorized_response();
    }

    if method == "GET" && path.starts_with("/metrics") {
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        if encoder
            .encode(&metrics.registry().gather(), &mut buffer)
            .is_err()
        {
            return http_response(500, "text/plain", b"encode error");
        }
        return http_response(200, "text/plain; version=0.0.4", &buffer);
    }

    if method == "GET" && (path == "/health" || path.starts_with("/health?")) {
        return http_response(200, "text/plain", b"ok");
    }

    // SOAR Automated Investigation endpoint: GET /api/v1/soar/investigate?query=<domain|url|ip>
    if method == "GET" && path.starts_with("/api/v1/soar/investigate") {
        let Some(storage) = storage else {
            return http_response(503, "application/json", b"{\"error\":\"Storage disabled\"}");
        };
        let query = extract_query_param(path, "query").unwrap_or_default();
        if query.is_empty() {
            return http_response(
                400,
                "application/json",
                b"{\"error\":\"Missing query parameter\"}",
            );
        }
        return match soar::execute_soar_investigation(storage, &query, None) {
            Ok(result) => {
                let body = serde_json::to_vec_pretty(&result).unwrap_or_default();
                http_response(200, "application/json", &body)
            }
            Err(e) => {
                let err_body = format!("{{\"error\":\"{}\"}}", e);
                http_response(500, "application/json", err_body.as_bytes())
            }
        };
    }

    // ML Domain Reputation endpoint: GET /api/v1/ml/reputation?domain=<domain>
    if method == "GET" && path.starts_with("/api/v1/ml/reputation") {
        let domain = extract_query_param(path, "domain").unwrap_or_default();
        if domain.is_empty() {
            return http_response(
                400,
                "application/json",
                b"{\"error\":\"Missing domain parameter\"}",
            );
        }
        let score = ml_reputation::evaluate_domain_reputation(&domain, None);
        metrics
            .ml_evaluations
            .with_label_values(&["reputation"])
            .inc();
        let body = serde_json::to_vec_pretty(&score).unwrap_or_default();
        return http_response(200, "application/json", &body);
    }

    // ML Domain Anomaly endpoint: GET /api/v1/ml/anomaly?domain=<domain>
    if method == "GET" && path.starts_with("/api/v1/ml/anomaly") {
        let domain = extract_query_param(path, "domain").unwrap_or_default();
        if domain.is_empty() {
            return http_response(
                400,
                "application/json",
                b"{\"error\":\"Missing domain parameter\"}",
            );
        }
        let anomaly = ml_reputation::detect_domain_anomalies(&domain);
        metrics
            .ml_evaluations
            .with_label_values(&["anomaly"])
            .inc();
        let body = serde_json::to_vec_pretty(&anomaly).unwrap_or_default();
        return http_response(200, "application/json", &body);
    }

    // ML Campaign Clustering endpoint: POST /api/v1/ml/cluster
    if method == "POST" && path.starts_with("/api/v1/ml/cluster") {
        let body_str = extract_http_body(req);
        #[derive(serde::Deserialize)]
        struct ClusterRequest {
            domains: Vec<String>,
        }
        let req_payload: Result<ClusterRequest, _> = serde_json::from_str(body_str);
        return match req_payload {
            Ok(payload) => {
                let clusters = ml_reputation::cluster_phishing_campaigns(&payload.domains);
                metrics
                    .ml_evaluations
                    .with_label_values(&["cluster"])
                    .inc();
                let body = serde_json::to_vec_pretty(&clusters).unwrap_or_default();
                http_response(200, "application/json", &body)
            }
            Err(e) => {
                let err = format!("{{\"error\":\"Invalid JSON: {}\"}}", e);
                http_response(400, "application/json", err.as_bytes())
            }
        };
    }

    // SOAR Automated Block endpoint: POST /api/v1/soar/block
    if method == "POST" && path.starts_with("/api/v1/soar/block") {
        let Some(storage) = storage else {
            return http_response(503, "application/json", b"{\"error\":\"Storage disabled\"}");
        };
        let body_str = extract_http_body(req);
        let req_payload: Result<soar::SoarBlockRequest, _> = serde_json::from_str(body_str);
        return match req_payload {
            Ok(payload) => match soar::execute_soar_block_with_limits(
                storage,
                payload,
                mode,
                default_confidence,
                max_confidence,
            ) {
                Ok(resp) => {
                    metrics
                        .soar_blocks
                        .with_label_values(&[mode.as_str()])
                        .inc();
                    audit_soar(security, req, peer, "block", mode, "accepted");
                    let body = serde_json::to_vec_pretty(&resp).unwrap_or_default();
                    // Shadow mode accepts the indicator for observation only:
                    // 202 makes the non-enforcing outcome explicit to callers.
                    let status = if resp.enforced { 200 } else { 202 };
                    http_response(status, "application/json", &body)
                }
                Err(e) => {
                    let err = format!("{{\"error\":\"{}\"}}", e);
                    http_response(500, "application/json", err.as_bytes())
                }
            },
            Err(e) => {
                let err = format!("{{\"error\":\"Invalid JSON: {}\"}}", e);
                http_response(400, "application/json", err.as_bytes())
            }
        };
    }

    // SOAR Automated Unblock endpoint: POST /api/v1/soar/unblock
    if method == "POST" && path.starts_with("/api/v1/soar/unblock") {
        let Some(storage) = storage else {
            return http_response(503, "application/json", b"{\"error\":\"Storage disabled\"}");
        };
        let body_str = extract_http_body(req);
        let req_payload: Result<soar::SoarUnblockRequest, _> = serde_json::from_str(body_str);
        return match req_payload {
            Ok(payload) => match soar::execute_soar_unblock(storage, payload, mode) {
                Ok(resp) => {
                    metrics
                        .soar_unblocks
                        .with_label_values(&[mode.as_str()])
                        .inc();
                    audit_soar(security, req, peer, "unblock", mode, "accepted");
                    let body = serde_json::to_vec_pretty(&resp).unwrap_or_default();
                    http_response(200, "application/json", &body)
                }
                Err(e) => {
                    let err = format!("{{\"error\":\"{}\"}}", e);
                    http_response(500, "application/json", err.as_bytes())
                }
            },
            Err(e) => {
                let err = format!("{{\"error\":\"Invalid JSON: {}\"}}", e);
                http_response(400, "application/json", err.as_bytes())
            }
        };
    }

    // DNS RPZ Zone Status endpoint: GET /api/v1/rpz/status
    if method == "GET" && path.starts_with("/api/v1/rpz/status") {
        let status = rpz::get_rpz_status(rpz_path);
        let body = serde_json::to_vec_pretty(&status).unwrap_or_default();
        return http_response(200, "application/json", &body);
    }

    // DNS RPZ Zone Rollback endpoint: POST /api/v1/rpz/rollback
    if method == "POST" && path.starts_with("/api/v1/rpz/rollback") {
        if !security.is_request_authorized(req) {
            return unauthorized_response();
        }
        return match rpz::rollback_rpz_zone(rpz_path) {
            Ok(true) => {
                metrics.rpz_rollbacks.inc();
                let status = rpz::get_rpz_status(rpz_path);
                #[derive(serde::Serialize)]
                struct RollbackSuccess<'a> {
                    rolled_back: bool,
                    status: &'a rpz::RpzStatus,
                }
                let resp = RollbackSuccess {
                    rolled_back: true,
                    status: &status,
                };
                let body = serde_json::to_vec_pretty(&resp).unwrap_or_default();
                http_response(200, "application/json", &body)
            }
            Ok(false) => http_response(
                404,
                "application/json",
                b"{\"error\":\"No backup file found to rollback\"}",
            ),
            Err(e) => {
                let err = format!("{{\"error\":\"{}\"}}", e);
                http_response(500, "application/json", err.as_bytes())
            }
        };
    }

    http_response(404, "text/plain", b"not found")
}

/// Records a SOAR action (accepted or denied) in the audit trail.
fn audit_soar(
    security: &AdminApiSecurity,
    req: &str,
    peer: &str,
    action: &str,
    mode: EnforcementMode,
    outcome: &str,
) {
    let body: serde_json::Value =
        serde_json::from_str(extract_http_body(req)).unwrap_or(serde_json::Value::Null);
    let field = |name: &str| {
        body.get(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
    };
    if let Err(e) = api_auth::append_soar_audit(
        security.audit_path(),
        security.audit_max_bytes(),
        field("operator"),
        peer,
        action,
        field("indicator"),
        field("reason"),
        mode.as_str(),
        outcome,
    ) {
        warn!("failed to append SOAR audit record: {e}");
    }
}

fn unauthorized_response() -> Vec<u8> {
    let body = b"{\"error\":\"unauthorized\"}";
    let header = format!(
        "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nWWW-Authenticate: Bearer\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut out = header.into_bytes();
    out.extend_from_slice(body);
    out
}

fn extract_query_param(path: &str, key: &str) -> Option<String> {
    let query_start = path.find('?')?;
    let query_str = &path[query_start + 1..];
    for pair in query_str.split('&') {
        let mut kv = pair.split('=');
        if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
            if k == key {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn extract_http_body(req: &str) -> &str {
    if let Some(idx) = req.find("\r\n\r\n") {
        &req[idx + 4..]
    } else if let Some(idx) = req.find("\n\n") {
        &req[idx + 2..]
    } else {
        ""
    }
}

fn http_response(status: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut out = header.into_bytes();
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "127.0.0.1:40000";

    /// Authorized posture with an isolated audit log per test.
    fn test_security(dir: &tempfile::TempDir) -> AdminApiSecurity {
        AdminApiSecurity::for_test(
            Some("test-token"),
            true,
            dir.path().join("soar-audit.jsonl"),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_admin_req(
        req: &str,
        metrics: &CollectorMetrics,
        storage: Option<&SqliteStorage>,
        mode: EnforcementMode,
        security: &AdminApiSecurity,
        peer: &str,
        default_confidence: u8,
        max_confidence: u8,
    ) -> Vec<u8> {
        let dummy = std::path::Path::new("/tmp/test_threats.rpz");
        handle_admin(
            req,
            metrics,
            storage,
            mode,
            security,
            peer,
            default_confidence,
            max_confidence,
            dummy,
        )
    }

    #[test]
    fn serves_health_metrics_soar_and_ml() {
        let metrics = CollectorMetrics::new().unwrap();
        let storage = SqliteStorage::in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let security = test_security(&dir);
        metrics
            .fetches
            .with_label_values(&["openphish", "ok"])
            .inc();

        // 1. Health
        let health = String::from_utf8(handle_admin_req(
            "GET /health HTTP/1.1",
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
            90,
            100,
        ))
        .unwrap();
        assert!(health.starts_with("HTTP/1.1 200 OK"));
        assert!(health.ends_with("ok"));

        // 2. Metrics
        let scraped = String::from_utf8(handle_admin_req(
            "GET /metrics HTTP/1.1",
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
            90,
            100,
        ))
        .unwrap();
        assert!(scraped.contains("threat_intel_fetches_total"));

        // 3. ML reputation
        let ml_res = String::from_utf8(handle_admin_req(
            "GET /api/v1/ml/reputation?domain=gogle.com HTTP/1.1",
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
            90,
            100,
        ))
        .unwrap();
        assert!(ml_res.starts_with("HTTP/1.1 200 OK"));
        assert!(ml_res.contains("\"is_suspicious\": true"));

        // 3a. ML Anomaly
        let anom_res = String::from_utf8(handle_admin_req(
            "GET /api/v1/ml/anomaly?domain=auth.login.verify.update.evil-bank.com HTTP/1.1",
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
            90,
            100,
        ))
        .unwrap();
        assert!(anom_res.starts_with("HTTP/1.1 200 OK"));
        assert!(anom_res.contains("\"is_anomalous\": true"));

        // 3b. ML Cluster
        let cluster_req = "POST /api/v1/ml/cluster HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"domains\":[\"login-microsoft-auth.com\",\"verify-microsoft-security.net\"]}";
        let cluster_res = String::from_utf8(handle_admin_req(
            cluster_req,
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
            90,
            100,
        ))
        .unwrap();
        assert!(cluster_res.starts_with("HTTP/1.1 200 OK"));
        assert!(cluster_res.contains("\"target_brand\": \"microsoft\""));

        // 4. SOAR Block

        let block_req = "POST /api/v1/soar/block HTTP/1.1\r\nContent-Type: application/json\r\nAuthorization: Bearer test-token\r\n\r\n{\"indicator\":\"phish.example.test\",\"kind\":\"domain\",\"reason\":\"Manual SOAR containment\",\"operator\":\"soc1\"}";
        let block_resp = String::from_utf8(handle_admin_req(
            block_req,
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
            90,
            100,
        ))
        .unwrap();
        assert!(block_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(block_resp.contains("\"success\": true"));

        // 5. SOAR Investigate (requires authorization)
        let inv_req = "GET /api/v1/soar/investigate?query=phish.example.test HTTP/1.1\r\nAuthorization: Bearer test-token\r\n\r\n";
        let inv_res = String::from_utf8(handle_admin_req(
            inv_req,
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
            90,
            100,
        ))
        .unwrap();
        assert!(inv_res.starts_with("HTTP/1.1 200 OK"));
        assert!(inv_res.contains("\"found\": true"));

        // 6. SOAR Unblock
        let unblock_req = "POST /api/v1/soar/unblock HTTP/1.1\r\nContent-Type: application/json\r\nAuthorization: Bearer test-token\r\n\r\n{\"indicator\":\"phish.example.test\",\"reason\":\"Investigation closed\"}";
        let unblock_resp = String::from_utf8(handle_admin_req(
            unblock_req,
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
            90,
            100,
        ))
        .unwrap();
        assert!(unblock_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(unblock_resp.contains("\"success\": true"));

        // 7. Not found
        let missing = String::from_utf8(handle_admin_req(
            "GET /nope HTTP/1.1",
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
            90,
            100,
        ))
        .unwrap();
        assert!(missing.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn soar_investigate_requires_a_valid_token() {
        let metrics = CollectorMetrics::new().unwrap();
        let storage = SqliteStorage::in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let security = test_security(&dir);

        // 1. Unauthenticated request -> 401
        let unauth_req = "GET /api/v1/soar/investigate?query=threat.test HTTP/1.1\r\n\r\n";
        let unauth_resp = String::from_utf8(handle_admin_req(
            unauth_req,
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
            90,
            100,
        ))
        .unwrap();
        assert!(unauth_resp.starts_with("HTTP/1.1 401 Unauthorized"));

        // 2. Wrong token -> 401
        let wrong_req = "GET /api/v1/soar/investigate?query=threat.test HTTP/1.1\r\nAuthorization: Bearer wrong-token\r\n\r\n";
        let wrong_resp = String::from_utf8(handle_admin_req(
            wrong_req,
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
            90,
            100,
        ))
        .unwrap();
        assert!(wrong_resp.starts_with("HTTP/1.1 401 Unauthorized"));

        // 3. Valid token -> 200
        let auth_req = "GET /api/v1/soar/investigate?query=threat.test HTTP/1.1\r\nAuthorization: Bearer test-token\r\n\r\n";
        let auth_resp = String::from_utf8(handle_admin_req(
            auth_req,
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
            90,
            100,
        ))
        .unwrap();
        assert!(auth_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(auth_resp.contains("\"found\": false"));
    }

    #[test]
    fn soar_block_in_shadow_mode_returns_202_and_counts_metric() {
        let metrics = CollectorMetrics::new().unwrap();
        let storage = SqliteStorage::in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let security = test_security(&dir);

        let block_req = "POST /api/v1/soar/block HTTP/1.1\r\nContent-Type: application/json\r\nAuthorization: Bearer test-token\r\n\r\n{\"indicator\":\"shadow-api.example.test\",\"kind\":\"domain\",\"reason\":\"SOC triage\",\"operator\":\"soc1\"}";
        let resp = String::from_utf8(handle_admin_req(
            block_req,
            &metrics,
            Some(&storage),
            EnforcementMode::Shadow,
            &security,
            PEER,
            90,
            100,
        ))
        .unwrap();

        assert!(resp.starts_with("HTTP/1.1 202 Accepted"), "got: {resp}");
        assert!(resp.contains("\"mode\": \"shadow\""));
        assert!(resp.contains("\"enforced\": false"));
        assert_eq!(
            metrics.soar_blocks.with_label_values(&["shadow"]).get(),
            1,
            "shadow SOAR blocks must be counted"
        );
        assert_eq!(metrics.soar_blocks.with_label_values(&["enforce"]).get(), 0);
    }

    #[test]
    fn soar_block_confidence_score_defaults_and_clamping() {
        let metrics = CollectorMetrics::new().unwrap();
        let storage = SqliteStorage::in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let security = test_security(&dir);

        // 1. Default confidence (85) when unspecified
        let req1 = "POST /api/v1/soar/block HTTP/1.1\r\nAuthorization: Bearer test-token\r\n\r\n{\"indicator\":\"conf1.test\",\"kind\":\"domain\",\"reason\":\"SOC triage\"}";
        let _ = handle_admin_req(
            req1,
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
            85,
            95,
        );
        let ind1 = soar::execute_soar_investigation(&storage, "conf1.test", None)
            .unwrap()
            .indicator
            .unwrap();
        assert_eq!(ind1.confidence_score, 85);

        // 2. Custom confidence score (92) within ceiling
        let req2 = "POST /api/v1/soar/block HTTP/1.1\r\nAuthorization: Bearer test-token\r\n\r\n{\"indicator\":\"conf2.test\",\"kind\":\"domain\",\"reason\":\"SOC triage\",\"confidence_score\":92}";
        let _ = handle_admin_req(
            req2,
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
            85,
            95,
        );
        let ind2 = soar::execute_soar_investigation(&storage, "conf2.test", None)
            .unwrap()
            .indicator
            .unwrap();
        assert_eq!(ind2.confidence_score, 92);

        // 3. Custom score (100) clamped to ceiling (95)
        let req3 = "POST /api/v1/soar/block HTTP/1.1\r\nAuthorization: Bearer test-token\r\n\r\n{\"indicator\":\"conf3.test\",\"kind\":\"domain\",\"reason\":\"SOC triage\",\"confidence_score\":100}";
        let _ = handle_admin_req(
            req3,
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
            85,
            95,
        );
        let ind3 = soar::execute_soar_investigation(&storage, "conf3.test", None)
            .unwrap()
            .indicator
            .unwrap();
        assert_eq!(ind3.confidence_score, 95);
    }

    #[test]
    fn soar_mutations_require_a_valid_token() {
        let metrics = CollectorMetrics::new().unwrap();
        let storage = SqliteStorage::in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let security = test_security(&dir);

        let body = "{\"indicator\":\"attacker-controlled.test\",\"kind\":\"domain\",\"reason\":\"injected\",\"operator\":\"mallory\"}";
        let cases = [
            // No Authorization header at all.
            format!("POST /api/v1/soar/block HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{body}"),
            // Wrong token.
            format!("POST /api/v1/soar/block HTTP/1.1\r\nAuthorization: Bearer wrong-token\r\n\r\n{body}"),
            // Right token value, wrong scheme.
            format!("POST /api/v1/soar/block HTTP/1.1\r\nAuthorization: Basic test-token\r\n\r\n{body}"),
            // Unblock is equally protected.
            format!("POST /api/v1/soar/unblock HTTP/1.1\r\n\r\n{body}"),
        ];

        for req in &cases {
            let resp = String::from_utf8(handle_admin_req(
                req,
                &metrics,
                Some(&storage),
                EnforcementMode::Shadow,
                &security,
                PEER,
                90,
                100,
            ))
            .unwrap();
            assert!(resp.starts_with("HTTP/1.1 401 Unauthorized"), "got: {resp}");
            assert!(resp.contains("WWW-Authenticate: Bearer"));
        }

        // Nothing reached storage and no block was counted.
        assert!(
            soar::execute_soar_investigation(&storage, "attacker-controlled.test", None)
                .unwrap()
                .indicator
                .is_none()
        );
        assert_eq!(metrics.soar_blocks.with_label_values(&["shadow"]).get(), 0);

        // Every rejected attempt is on the audit trail.
        let audit = std::fs::read_to_string(dir.path().join("soar-audit.jsonl")).unwrap();
        assert_eq!(audit.lines().count(), cases.len());
        let first: serde_json::Value = serde_json::from_str(audit.lines().next().unwrap()).unwrap();
        assert_eq!(first["outcome"], "denied");
        assert_eq!(first["actor"], "mallory");
        assert_eq!(first["indicator"], "attacker-controlled.test");
        assert_eq!(first["peer"], PEER);
    }

    #[test]
    fn read_only_endpoints_stay_open_without_a_token() {
        let metrics = CollectorMetrics::new().unwrap();
        let storage = SqliteStorage::in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        // Fail-closed posture with no token configured at all.
        let security = AdminApiSecurity::for_test(None, true, dir.path().join("soar-audit.jsonl"));

        for path in [
            "GET /health HTTP/1.1",
            "GET /metrics HTTP/1.1",
            "GET /api/v1/ml/reputation?domain=apple.com HTTP/1.1",
        ] {
            let resp = String::from_utf8(handle_admin_req(
                path,
                &metrics,
                Some(&storage),
                EnforcementMode::Shadow,
                &security,
                PEER,
                90,
                100,
            ))
            .unwrap();
            assert!(resp.starts_with("HTTP/1.1 200 OK"), "{path} -> {resp}");
        }

        // ... while SOAR endpoints are refused because no token is configured.
        let blocked = String::from_utf8(handle_admin_req(
            "POST /api/v1/soar/block HTTP/1.1\r\n\r\n{\"indicator\":\"x.test\",\"kind\":\"domain\",\"reason\":\"r\"}",
            &metrics,
            Some(&storage),
            EnforcementMode::Shadow,
            &security,
            PEER,
            90,
            100,
        ))
        .unwrap();
        assert!(blocked.starts_with("HTTP/1.1 401 Unauthorized"));

        let inv_blocked = String::from_utf8(handle_admin_req(
            "GET /api/v1/soar/investigate?query=x.test HTTP/1.1\r\n\r\n",
            &metrics,
            Some(&storage),
            EnforcementMode::Shadow,
            &security,
            PEER,
            90,
            100,
        ))
        .unwrap();
        assert!(inv_blocked.starts_with("HTTP/1.1 401 Unauthorized"));
    }

    #[test]
    fn accepted_block_is_recorded_in_the_audit_trail() {
        let metrics = CollectorMetrics::new().unwrap();
        let storage = SqliteStorage::in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let security = test_security(&dir);

        let req = "POST /api/v1/soar/block HTTP/1.1\r\nAuthorization: Bearer test-token\r\n\r\n{\"indicator\":\"audited.test\",\"kind\":\"domain\",\"reason\":\"C2 beacon\",\"operator\":\"soc1\"}";
        let resp = String::from_utf8(handle_admin_req(
            req,
            &metrics,
            Some(&storage),
            EnforcementMode::Shadow,
            &security,
            PEER,
            90,
            100,
        ))
        .unwrap();
        assert!(resp.starts_with("HTTP/1.1 202 Accepted"), "got: {resp}");

        let audit = std::fs::read_to_string(dir.path().join("soar-audit.jsonl")).unwrap();
        let record: serde_json::Value =
            serde_json::from_str(audit.lines().next().unwrap()).unwrap();
        assert_eq!(record["outcome"], "accepted");
        assert_eq!(record["action"], "block");
        assert_eq!(record["actor"], "soc1");
        assert_eq!(record["indicator"], "audited.test");
        assert_eq!(record["change_reason"], "C2 beacon");
        assert_eq!(record["mode"], "shadow");
    }

    #[tokio::test]
    async fn test_read_http_request_chunked_reads() {
        let payload = "POST /api/v1/soar/block HTTP/1.1\r\nContent-Length: 26\r\n\r\n{\"indicator\":\"chunk.test\"}";
        // Mock stream that delivers 5 bytes at a time
        struct ChunkedStream<'a> {
            data: &'a [u8],
            pos: usize,
            chunk_size: usize,
        }

        impl tokio::io::AsyncRead for ChunkedStream<'_> {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                if self.pos >= self.data.len() {
                    return std::task::Poll::Ready(Ok(()));
                }
                let end = (self.pos + self.chunk_size).min(self.data.len());
                let slice = &self.data[self.pos..end];
                self.pos = end;
                buf.put_slice(slice);
                std::task::Poll::Ready(Ok(()))
            }
        }

        let mut stream = ChunkedStream {
            data: payload.as_bytes(),
            pos: 0,
            chunk_size: 5,
        };

        let result = read_http_request(&mut stream, 64 * 1024).await.unwrap();
        assert_eq!(result, payload);
    }

    #[tokio::test]
    async fn test_read_http_request_payload_too_large() {
        let payload = "POST /api/v1/soar/block HTTP/1.1\r\nContent-Length: 1000\r\n\r\n";
        let mut cursor = std::io::Cursor::new(payload.as_bytes());
        let err = read_http_request(&mut cursor, 50).await.unwrap_err();
        assert_eq!(err.0, 413);
    }

    #[tokio::test]
    async fn test_read_http_request_invalid_content_length() {
        let payload = "POST /api/v1/soar/block HTTP/1.1\r\nContent-Length: not-a-number\r\n\r\n";
        let mut cursor = std::io::Cursor::new(payload.as_bytes());
        let err = read_http_request(&mut cursor, 1024).await.unwrap_err();
        assert_eq!(err.0, 400);
        assert_eq!(err.1, "Invalid Content-Length");
    }

    #[tokio::test]
    async fn test_read_http_request_incomplete_body() {
        let payload = "POST /api/v1/soar/block HTTP/1.1\r\nContent-Length: 100\r\n\r\nshort";
        let mut cursor = std::io::Cursor::new(payload.as_bytes());
        let err = read_http_request(&mut cursor, 1024).await.unwrap_err();
        assert_eq!(err.0, 400);
        assert_eq!(err.1, "Incomplete request body");
    }

    #[test]
    fn serves_rpz_status_and_rollback() {
        let metrics = CollectorMetrics::new().unwrap();
        let storage = SqliteStorage::in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let security = test_security(&dir);
        let rpz_file = dir.path().join("threats.rpz");

        // 1. Initial status when file does not exist
        let req1 = "GET /api/v1/rpz/status HTTP/1.1\r\n\r\n";
        let resp1 = String::from_utf8(handle_admin(
            req1,
            &metrics,
            Some(&storage),
            EnforcementMode::Shadow,
            &security,
            PEER,
            90,
            100,
            &rpz_file,
        ))
        .unwrap();
        assert!(resp1.starts_with("HTTP/1.1 200 OK"));
        assert!(resp1.contains("\"exists\": false"));

        // 2. Write RPZ file generation 1 & generation 2
        let config = rpz::RpzConfig::default();
        let _ = rpz::write_rpz_file(&rpz_file, &["bad-site-1.test".to_string()], &config).unwrap();
        let _ = rpz::write_rpz_file(&rpz_file, &["bad-site-2.test".to_string()], &config).unwrap();

        // 3. Status with active file and backup
        let resp2 = String::from_utf8(handle_admin(
            req1,
            &metrics,
            Some(&storage),
            EnforcementMode::Shadow,
            &security,
            PEER,
            90,
            100,
            &rpz_file,
        ))
        .unwrap();
        assert!(resp2.starts_with("HTTP/1.1 200 OK"));
        assert!(resp2.contains("\"exists\": true"));
        assert!(resp2.contains("\"has_backup\": true"));

        // 4. Rollback without auth -> 401
        let rollback_unauth = "POST /api/v1/rpz/rollback HTTP/1.1\r\n\r\n";
        let resp3 = String::from_utf8(handle_admin(
            rollback_unauth,
            &metrics,
            Some(&storage),
            EnforcementMode::Shadow,
            &security,
            PEER,
            90,
            100,
            &rpz_file,
        ))
        .unwrap();
        assert!(resp3.starts_with("HTTP/1.1 401 Unauthorized"));

        // 5. Rollback with auth -> 200
        let rollback_auth =
            "POST /api/v1/rpz/rollback HTTP/1.1\r\nAuthorization: Bearer test-token\r\n\r\n";
        let resp4 = String::from_utf8(handle_admin(
            rollback_auth,
            &metrics,
            Some(&storage),
            EnforcementMode::Shadow,
            &security,
            PEER,
            90,
            100,
            &rpz_file,
        ))
        .unwrap();
        assert!(resp4.starts_with("HTTP/1.1 200 OK"));
        assert!(resp4.contains("\"rolled_back\": true"));
    }
}
