mod clickhouse;
mod config;
mod features;
mod metrics;
mod scoring;
mod webhook;

use clickhouse::ClickHouseClient;
use config::Config;
use features::{extract_sql, features_from_row};
use metrics::WorkerMetrics;
use scoring::score_features;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use webhook::WebhookClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,ml_worker=info".into()),
        )
        .init();

    let config = Config::from_env().map_err(|e| {
        error!("{e}");
        e
    })?;
    let metrics = WorkerMetrics::new()?;
    let ch = ClickHouseClient::new(&config)?;
    ch.ping().await?;
    let webhook = match WebhookClient::new(&config) {
        Some(Ok(w)) => Some(w),
        Some(Err(e)) => return Err(e),
        None => None,
    };

    {
        let metrics = metrics.clone();
        let port = config.metrics_port;
        tokio::spawn(async move {
            run_admin_server(port, metrics).await;
        });
    }

    info!(
        source = %config.fq_source(),
        features = %config.fq_features(),
        scores = %config.fq_scores(),
        model = %config.model,
        entities = ?config.entity_types,
        poll_secs = config.poll_interval.as_secs(),
        lookback_secs = config.lookback.as_secs(),
        webhook = webhook.is_some(),
        "ml-worker started (M5.1 feature store + anomaly_stub_v0)"
    );

    loop {
        if let Err(e) = cycle_once(&config, &ch, webhook.as_ref(), &metrics).await {
            metrics.errors.inc();
            warn!("ml-worker cycle failed: {e}");
        }
        tokio::time::sleep(config.poll_interval).await;
    }
}

async fn cycle_once(
    config: &Config,
    ch: &ClickHouseClient,
    webhook: Option<&WebhookClient>,
    metrics: &WorkerMetrics,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut all_features = Vec::new();
    for entity_type in &config.entity_types {
        let sql = extract_sql(config, entity_type);
        let rows = ch.query_json_each_row(&sql).await?;
        for row in rows {
            match features_from_row(&row) {
                Ok(f) => all_features.push(f),
                Err(e) => {
                    warn!("skip feature row: {e}");
                    metrics.errors.inc();
                }
            }
        }
    }

    let feature_jsons: Vec<_> = all_features.iter().map(|f| f.to_insert_json()).collect();
    ch.insert_json_each_row(&config.fq_features(), &feature_jsons)
        .await?;
    metrics.features_written.inc_by(feature_jsons.len() as u64);
    metrics.last_cycle_features.set(feature_jsons.len() as i64);

    let mut score_jsons = Vec::new();
    for f in &all_features {
        let scored = score_features(
            f,
            &config.model,
            config.min_requests,
            config.score_threshold,
        );
        if let Some(wh) = webhook {
            if scored.score >= config.score_threshold {
                if let Err(e) = wh.post_score(&scored).await {
                    warn!("webhook failed for {}: {e}", scored.entity_id);
                    metrics.errors.inc();
                } else {
                    metrics.webhooks_sent.inc();
                }
            }
        }
        score_jsons.push(scored.to_insert_json());
    }
    ch.insert_json_each_row(&config.fq_scores(), &score_jsons)
        .await?;
    metrics.scores_written.inc_by(score_jsons.len() as u64);
    metrics.cycles.inc();

    info!(
        features = feature_jsons.len(),
        scores = score_jsons.len(),
        "cycle complete"
    );
    Ok(())
}

async fn run_admin_server(port: u16, metrics: WorkerMetrics) {
    let addr = format!("0.0.0.0:{port}");
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("metrics bind {addr}: {e}");
            return;
        }
    };
    info!("ml-worker metrics on http://{addr}/metrics");
    let metrics = Arc::new(metrics);
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            continue;
        };
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let req = String::from_utf8_lossy(&buf);
            let (status, body, ctype) = if req.starts_with("GET /health") {
                (
                    "200 OK",
                    r#"{"status":"ok","service":"ml-worker"}"#.to_string(),
                    "application/json",
                )
            } else if req.starts_with("GET /metrics") {
                match metrics.encode() {
                    Ok(b) => ("200 OK", b, "text/plain; version=0.0.4"),
                    Err(_) => ("500 Internal Server Error", String::new(), "text/plain"),
                }
            } else {
                ("404 Not Found", "not found".into(), "text/plain")
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        });
    }
}
