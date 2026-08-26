//! Threat intelligence feed collector (TASK-TI-001).
//!
//! Fetches phishing/malware IOC feeds on a schedule, parses them through
//! per-source plugins, and writes normalized snapshots plus a run report for the
//! downstream IOC store (TASK-TI-002) and scoring engine (TASK-TI-010).

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
        )
        .await;
    });

    let handles = collector::spawn_scheduled(collector, feeds);
    for handle in handles {
        let _ = handle.await;
    }
    Ok(())
}

async fn run_admin_server(
    port: u16,
    metrics: Arc<CollectorMetrics>,
    storage: Option<SqliteStorage>,
    mode: EnforcementMode,
    security: Arc<AdminApiSecurity>,
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
    info!("threat-intel admin on {bind_addr} (/metrics, /health, /api/v1/soar/*, /api/v1/ml/*)");

    loop {
        let Ok((mut socket, peer)) = listener.accept().await else {
            continue;
        };
        let metrics = metrics.clone();
        let storage = storage.clone();
        let security = security.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16384];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            let req = String::from_utf8_lossy(&buf[..n]);
            let response = handle_admin(
                &req,
                &metrics,
                storage.as_ref(),
                mode,
                &security,
                &peer.to_string(),
            );
            let _ = socket.write_all(&response).await;
        });
    }
}

fn handle_admin(
    req: &str,
    metrics: &CollectorMetrics,
    storage: Option<&SqliteStorage>,
    mode: EnforcementMode,
    security: &AdminApiSecurity,
    peer: &str,
) -> Vec<u8> {
    let mut lines = req.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

    // Mutating SOAR endpoints are fail-closed: an unauthenticated caller could
    // otherwise inject confidence-100 indicators straight into the artifacts.
    let mutating_soar = method == "POST" && path.starts_with("/api/v1/soar/");
    if mutating_soar && !security.is_request_authorized(req) {
        let action = if path.starts_with("/api/v1/soar/unblock") {
            "unblock"
        } else {
            "block"
        };
        audit_soar(security, req, peer, action, mode, "denied");
        warn!(peer = %peer, path = %path, "unauthorized SOAR mutation rejected");
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
        let body = serde_json::to_vec_pretty(&score).unwrap_or_default();
        return http_response(200, "application/json", &body);
    }

    // SOAR Automated Block endpoint: POST /api/v1/soar/block
    if method == "POST" && path.starts_with("/api/v1/soar/block") {
        let Some(storage) = storage else {
            return http_response(503, "application/json", b"{\"error\":\"Storage disabled\"}");
        };
        let body_str = extract_http_body(req);
        let req_payload: Result<soar::SoarBlockRequest, _> = serde_json::from_str(body_str);
        return match req_payload {
            Ok(payload) => match soar::execute_soar_block(storage, payload, mode) {
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
        503 => "Service Unavailable",
        404 => "Not Found",
        500 => "Internal Server Error",
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
        let health = String::from_utf8(handle_admin(
            "GET /health HTTP/1.1",
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
        ))
        .unwrap();
        assert!(health.starts_with("HTTP/1.1 200 OK"));
        assert!(health.ends_with("ok"));

        // 2. Metrics
        let scraped = String::from_utf8(handle_admin(
            "GET /metrics HTTP/1.1",
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
        ))
        .unwrap();
        assert!(scraped.contains("threat_intel_fetches_total"));

        // 3. ML reputation
        let ml_res = String::from_utf8(handle_admin(
            "GET /api/v1/ml/reputation?domain=gogle.com HTTP/1.1",
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
        ))
        .unwrap();
        assert!(ml_res.starts_with("HTTP/1.1 200 OK"));
        assert!(ml_res.contains("\"is_suspicious\": true"));

        // 4. SOAR Block
        let block_req = "POST /api/v1/soar/block HTTP/1.1\r\nContent-Type: application/json\r\nAuthorization: Bearer test-token\r\n\r\n{\"indicator\":\"phish.example.test\",\"kind\":\"domain\",\"reason\":\"Manual SOAR containment\",\"operator\":\"soc1\"}";
        let block_resp = String::from_utf8(handle_admin(
            block_req,
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
        ))
        .unwrap();
        assert!(block_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(block_resp.contains("\"success\": true"));

        // 5. SOAR Investigate
        let inv_res = String::from_utf8(handle_admin(
            "GET /api/v1/soar/investigate?query=phish.example.test HTTP/1.1",
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
        ))
        .unwrap();
        assert!(inv_res.starts_with("HTTP/1.1 200 OK"));
        assert!(inv_res.contains("\"found\": true"));

        // 6. SOAR Unblock
        let unblock_req = "POST /api/v1/soar/unblock HTTP/1.1\r\nContent-Type: application/json\r\nAuthorization: Bearer test-token\r\n\r\n{\"indicator\":\"phish.example.test\",\"reason\":\"Investigation closed\"}";
        let unblock_resp = String::from_utf8(handle_admin(
            unblock_req,
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
        ))
        .unwrap();
        assert!(unblock_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(unblock_resp.contains("\"success\": true"));

        // 7. Not found
        let missing = String::from_utf8(handle_admin(
            "GET /nope HTTP/1.1",
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
            &security,
            PEER,
        ))
        .unwrap();
        assert!(missing.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn soar_block_in_shadow_mode_returns_202_and_counts_metric() {
        let metrics = CollectorMetrics::new().unwrap();
        let storage = SqliteStorage::in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let security = test_security(&dir);

        let block_req = "POST /api/v1/soar/block HTTP/1.1\r\nContent-Type: application/json\r\nAuthorization: Bearer test-token\r\n\r\n{\"indicator\":\"shadow-api.example.test\",\"kind\":\"domain\",\"reason\":\"SOC triage\",\"operator\":\"soc1\"}";
        let resp = String::from_utf8(handle_admin(
            block_req,
            &metrics,
            Some(&storage),
            EnforcementMode::Shadow,
            &security,
            PEER,
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
            let resp = String::from_utf8(handle_admin(
                req,
                &metrics,
                Some(&storage),
                EnforcementMode::Shadow,
                &security,
                PEER,
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

        for path in ["GET /health HTTP/1.1", "GET /metrics HTTP/1.1"] {
            let resp = String::from_utf8(handle_admin(
                path,
                &metrics,
                Some(&storage),
                EnforcementMode::Shadow,
                &security,
                PEER,
            ))
            .unwrap();
            assert!(resp.starts_with("HTTP/1.1 200 OK"), "{path} -> {resp}");
        }

        // ... while mutations are refused because no token is configured.
        let blocked = String::from_utf8(handle_admin(
            "POST /api/v1/soar/block HTTP/1.1\r\n\r\n{\"indicator\":\"x.test\",\"kind\":\"domain\",\"reason\":\"r\"}",
            &metrics,
            Some(&storage),
            EnforcementMode::Shadow,
            &security,
            PEER,
        ))
        .unwrap();
        assert!(blocked.starts_with("HTTP/1.1 401 Unauthorized"));
    }

    #[test]
    fn accepted_block_is_recorded_in_the_audit_trail() {
        let metrics = CollectorMetrics::new().unwrap();
        let storage = SqliteStorage::in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let security = test_security(&dir);

        let req = "POST /api/v1/soar/block HTTP/1.1\r\nAuthorization: Bearer test-token\r\n\r\n{\"indicator\":\"audited.test\",\"kind\":\"domain\",\"reason\":\"C2 beacon\",\"operator\":\"soc1\"}";
        let resp = String::from_utf8(handle_admin(
            req,
            &metrics,
            Some(&storage),
            EnforcementMode::Shadow,
            &security,
            PEER,
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
}
