mod clickhouse;
mod config;
mod dedupe;
mod entropy;
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

    // Seed the freshness gauge so `time() - last_success` measures uptime
    // without a clean cycle instead of the Unix epoch.
    metrics.last_success_timestamp.set(Utc::now().timestamp());

    let mut dedupe = DedupeCache::new();
    let mut degraded_cycles: u32 = 0;
    loop {
        match evaluate_once(&config, &ch, &webhook, &mut dedupe, &metrics).await {
            Ok(CycleOutcome::Healthy) => {
                if degraded_cycles > 0 {
                    info!("ClickHouse recovered, resuming normal poll interval");
                }
                degraded_cycles = 0;
                metrics.clickhouse_degraded.set(0);
                metrics.last_success_timestamp.set(Utc::now().timestamp());
            }
            Ok(CycleOutcome::Degraded) => {
                degraded_cycles = degraded_cycles.saturating_add(1);
                metrics.clickhouse_degraded.set(1);
            }
            Err(e) => {
                degraded_cycles = degraded_cycles.saturating_add(1);
                metrics.clickhouse_degraded.set(1);
                warn!("evaluation cycle failed: {e}");
            }
        }
        let delay = config.backoff_delay(degraded_cycles);
        if degraded_cycles > 0 {
            warn!(
                degraded_cycles,
                next_poll_secs = delay.as_secs(),
                "ClickHouse degraded — backing off next evaluation cycle"
            );
        }
        tokio::time::sleep(delay).await;
    }
}

/// Health of a single evaluation cycle, used to drive the poll backoff.
#[derive(Debug, PartialEq, Eq)]
enum CycleOutcome {
    Healthy,
    Degraded,
}

async fn evaluate_once(
    config: &Config,
    ch: &ClickHouseClient,
    webhook: &WebhookClient,
    dedupe: &mut DedupeCache,
    metrics: &WorkerMetrics,
) -> Result<CycleOutcome, Box<dyn std::error::Error>> {
    let queries = build_queries(config);
    let now = Instant::now();
    let fired_at = Utc::now();
    let mut consecutive_failures: u32 = 0;
    let mut failures: u32 = 0;
    let mut degraded = false;

    for (rule, sql) in queries {
        let outcome = match ch.query_json_each_row(&sql).await {
            Ok(outcome) => {
                consecutive_failures = 0;
                metrics
                    .clickhouse_query_seconds
                    .with_label_values(&[rule.as_str()])
                    .observe(outcome.elapsed.as_secs_f64());
                if outcome.elapsed >= config.clickhouse_slow_query {
                    metrics
                        .clickhouse_slow_queries
                        .with_label_values(&[rule.as_str()])
                        .inc();
                    warn!(
                        %rule,
                        elapsed_ms = outcome.elapsed.as_millis() as u64,
                        threshold_ms = config.clickhouse_slow_query.as_millis() as u64,
                        rows = outcome.rows.len(),
                        "slow ClickHouse rule query"
                    );
                }
                outcome
            }
            Err(e) => {
                failures += 1;
                consecutive_failures += 1;
                metrics.clickhouse_errors.inc();
                metrics
                    .clickhouse_query_errors
                    .with_label_values(&[rule.as_str(), e.kind()])
                    .inc();
                warn!(%rule, kind = e.kind(), "ClickHouse query failed: {e}");
                if consecutive_failures >= config.clickhouse_failure_threshold {
                    metrics.cycles_degraded.inc();
                    warn!(
                        consecutive_failures,
                        threshold = config.clickhouse_failure_threshold,
                        "aborting evaluation cycle — ClickHouse unhealthy"
                    );
                    degraded = true;
                    break;
                }
                continue;
            }
        };
        let rows = outcome.rows;
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
    let cycle_elapsed = now.elapsed();
    metrics
        .cycle_duration_seconds
        .observe(cycle_elapsed.as_secs_f64());
    if cycle_elapsed > config.poll_interval {
        warn!(
            cycle_ms = cycle_elapsed.as_millis() as u64,
            poll_interval_ms = config.poll_interval.as_millis() as u64,
            "evaluation cycle exceeded the poll interval — ClickHouse is the bottleneck"
        );
    }
    info!(
        dedupe_entries = dedupe.len(),
        cycle_ms = cycle_elapsed.as_millis() as u64,
        query_failures = failures,
        "evaluation cycle complete"
    );
    if degraded || failures > 0 {
        Ok(CycleOutcome::Degraded)
    } else {
        Ok(CycleOutcome::Healthy)
    }
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
