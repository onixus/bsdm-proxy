mod clickhouse;
mod config;
mod dedupe;
mod metrics;
mod payload;
mod rules;
mod webhook;

use chrono::Utc;
use clickhouse::ClickHouseClient;
use config::Config;
use dedupe::DedupeCache;
use metrics::WorkerMetrics;
use prometheus::{Encoder, TextEncoder};
use rules::{build_queries, findings_from_rows};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use webhook::WebhookClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,alert_worker=info".into()),
        )
        .init();

    let config = Config::from_env().map_err(|e| {
        error!("{e}");
        e
    })?;
    let metrics = WorkerMetrics::new()?;
    let ch = ClickHouseClient::new(&config)?;
    ch.ping().await?;
    let webhook = WebhookClient::new(&config)?;

    {
        let metrics = metrics.clone();
        let port = config.metrics_port;
        tokio::spawn(async move {
            run_admin_server(port, metrics).await;
        });
    }

    info!(
        webhook = %config.webhook_url,
        table = %config.fq_table(),
        poll_secs = config.poll_interval.as_secs(),
        lookback_secs = config.lookback.as_secs(),
        rules = ?config.rules,
        "alert-worker started"
    );

    let mut dedupe = DedupeCache::new();
    loop {
        if let Err(e) = evaluate_once(&config, &ch, &webhook, &mut dedupe, &metrics).await {
            warn!("evaluation cycle failed: {e}");
        }
        tokio::time::sleep(config.poll_interval).await;
    }
}

async fn evaluate_once(
    config: &Config,
    ch: &ClickHouseClient,
    webhook: &WebhookClient,
    dedupe: &mut DedupeCache,
    metrics: &WorkerMetrics,
) -> Result<(), Box<dyn std::error::Error>> {
    let queries = build_queries(config);
    let now = Instant::now();
    let fired_at = Utc::now();

    for (rule, sql) in queries {
        let rows = match ch.query_json_each_row(&sql).await {
            Ok(rows) => rows,
            Err(e) => {
                metrics.clickhouse_errors.inc();
                warn!(%rule, "ClickHouse query failed: {e}");
                continue;
            }
        };
        let findings = findings_from_rows(&rule, &rows, config);
        for finding in findings {
            metrics
                .findings
                .with_label_values(&[finding.rule.as_str()])
                .inc();
            let fingerprint = finding.fingerprint();
            if !dedupe.should_fire(&fingerprint, now, config.dedupe_ttl) {
                metrics.dedupe_suppressed.inc();
                continue;
            }
            let payload = finding.into_payload(&config.source, fired_at);
            match webhook.send(&payload).await {
                Ok(()) => metrics.webhook_sent.inc(),
                Err(e) => {
                    metrics.webhook_errors.inc();
                    warn!(rule = %payload.rule, "webhook send failed: {e}");
                }
            }
        }
    }

    metrics.evaluations.inc();
    info!(dedupe_entries = dedupe.len(), "evaluation cycle complete");
    Ok(())
}

async fn run_admin_server(port: u16, metrics: Arc<WorkerMetrics>) {
    let bind_addr = format!("0.0.0.0:{port}");
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind alert-worker admin on {bind_addr}: {e}");
            return;
        }
    };
    info!("alert-worker admin on {bind_addr} (/metrics, /health)");

    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            continue;
        };
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            let req = String::from_utf8_lossy(&buf[..n]);
            let response = handle_admin(&req, &metrics);
            let _ = socket.write_all(&response).await;
        });
    }
}

fn handle_admin(req: &str, metrics: &WorkerMetrics) -> Vec<u8> {
    let request_line = req.lines().next().unwrap_or("");
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
    http_response(404, "text/plain", b"not found")
}

fn http_response(status: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
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
