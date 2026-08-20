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
mod sink;
mod source;
mod sources;

use collector::Collector;
use config::Config;
use http::FeedHttpClient;
use metrics::CollectorMetrics;
use prometheus::{Encoder, TextEncoder};
use sink::JsonlFileSink;
use std::sync::Arc;
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
    let sink = Arc::new(JsonlFileSink::new(&config.output_dir)?);
    let http = FeedHttpClient::new(
        config.http_timeout,
        config.max_body_bytes,
        &config.user_agent,
    )?;

    info!(
        sources = ?config.sources,
        output_dir = %sink.dir().display(),
        poll_secs = config.poll_interval.as_secs(),
        max_attempts = config.max_attempts,
        run_once = config.run_once,
        "threat-intel collector started"
    );

    let run_once = config.run_once;
    let metrics_port = config.metrics_port;
    let collector = Arc::new(Collector::new(config, http, sink, metrics.clone()));

    if run_once {
        return collector::run_once(collector, feeds)
            .await
            .map_err(|e| e.into());
    }

    tokio::spawn(async move {
        run_admin_server(metrics_port, metrics).await;
    });

    let handles = collector::spawn_scheduled(collector, feeds);
    for handle in handles {
        let _ = handle.await;
    }
    Ok(())
}

async fn run_admin_server(port: u16, metrics: Arc<CollectorMetrics>) {
    let bind_addr = format!("0.0.0.0:{port}");
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind threat-intel admin on {bind_addr}: {e}");
            return;
        }
    };
    info!("threat-intel admin on {bind_addr} (/metrics, /health)");

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

fn handle_admin(req: &str, metrics: &CollectorMetrics) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_health_and_metrics() {
        let metrics = CollectorMetrics::new().unwrap();
        metrics
            .fetches
            .with_label_values(&["openphish", "ok"])
            .inc();

        let health = String::from_utf8(handle_admin("GET /health HTTP/1.1", &metrics)).unwrap();
        assert!(health.starts_with("HTTP/1.1 200 OK"));
        assert!(health.ends_with("ok"));

        let scraped = String::from_utf8(handle_admin("GET /metrics HTTP/1.1", &metrics)).unwrap();
        assert!(scraped.contains("threat_intel_fetches_total"));

        let missing = String::from_utf8(handle_admin("GET /nope HTTP/1.1", &metrics)).unwrap();
        assert!(missing.starts_with("HTTP/1.1 404"));
    }
}
