//! Threat intelligence feed collector (TASK-TI-001).
//!
//! Fetches phishing/malware IOC feeds on a schedule, parses them through
//! per-source plugins, and writes normalized snapshots plus a run report for the
//! downstream IOC store (TASK-TI-002) and scoring engine (TASK-TI-010).

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
use tracing::{error, info};

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
        run_admin_server(metrics_port, metrics, storage_clone, enforcement_mode).await;
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
) {
    let bind_addr = format!("0.0.0.0:{port}");
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind threat-intel admin on {bind_addr}: {e}");
            return;
        }
    };
    info!("threat-intel admin on {bind_addr} (/metrics, /health, /api/v1/soar/*, /api/v1/ml/*)");

    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            continue;
        };
        let metrics = metrics.clone();
        let storage = storage.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16384];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            let req = String::from_utf8_lossy(&buf[..n]);
            let response = handle_admin(&req, &metrics, storage.as_ref(), mode);
            let _ = socket.write_all(&response).await;
        });
    }
}

fn handle_admin(
    req: &str,
    metrics: &CollectorMetrics,
    storage: Option<&SqliteStorage>,
    mode: EnforcementMode,
) -> Vec<u8> {
    let mut lines = req.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

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

    #[test]
    fn serves_health_metrics_soar_and_ml() {
        let metrics = CollectorMetrics::new().unwrap();
        let storage = SqliteStorage::in_memory().unwrap();
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
        ))
        .unwrap();
        assert!(scraped.contains("threat_intel_fetches_total"));

        // 3. ML reputation
        let ml_res = String::from_utf8(handle_admin(
            "GET /api/v1/ml/reputation?domain=gogle.com HTTP/1.1",
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
        ))
        .unwrap();
        assert!(ml_res.starts_with("HTTP/1.1 200 OK"));
        assert!(ml_res.contains("\"is_suspicious\": true"));

        // 4. SOAR Block
        let block_req = "POST /api/v1/soar/block HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"indicator\":\"phish.example.test\",\"kind\":\"domain\",\"reason\":\"Manual SOAR containment\",\"operator\":\"soc1\"}";
        let block_resp = String::from_utf8(handle_admin(
            block_req,
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
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
        ))
        .unwrap();
        assert!(inv_res.starts_with("HTTP/1.1 200 OK"));
        assert!(inv_res.contains("\"found\": true"));

        // 6. SOAR Unblock
        let unblock_req = "POST /api/v1/soar/unblock HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"indicator\":\"phish.example.test\",\"reason\":\"Investigation closed\"}";
        let unblock_resp = String::from_utf8(handle_admin(
            unblock_req,
            &metrics,
            Some(&storage),
            EnforcementMode::Enforce,
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
        ))
        .unwrap();
        assert!(missing.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn soar_block_in_shadow_mode_returns_202_and_counts_metric() {
        let metrics = CollectorMetrics::new().unwrap();
        let storage = SqliteStorage::in_memory().unwrap();

        let block_req = "POST /api/v1/soar/block HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"indicator\":\"shadow-api.example.test\",\"kind\":\"domain\",\"reason\":\"SOC triage\",\"operator\":\"soc1\"}";
        let resp = String::from_utf8(handle_admin(
            block_req,
            &metrics,
            Some(&storage),
            EnforcementMode::Shadow,
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
}
