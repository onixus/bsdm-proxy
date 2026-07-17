mod baseline;
mod beacon;
mod clickhouse;
mod config;
mod features;
mod metrics;
mod phishing;
mod scoring;
mod webhook;
mod writeback;

use baseline::{baseline_sql, baselines_from_rows, BaselineSet};
use beacon::{
    extract_sql as beacon_extract_sql, features_from_row as beacon_from_row, score_beacon_pair,
    MODEL_CC_BEACON,
};
use clickhouse::ClickHouseClient;
use config::Config;
use features::{extract_sql, features_from_row};
use metrics::WorkerMetrics;
use phishing::{
    extract_sql as phishing_extract_sql, features_from_row as phishing_from_row, lexical_signals,
    score_domain, MODEL_PHISHING,
};
use scoring::{score_features, ScoreContext, ScoreResult, MODEL_UEBA};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use webhook::WebhookClient;
use writeback::{new_snapshot_store, publish_writeback, snapshot_json, SnapshotStore};

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

    let snapshot = new_snapshot_store();

    {
        let metrics = metrics.clone();
        let port = config.metrics_port;
        let snap = snapshot.clone();
        tokio::spawn(async move {
            run_admin_server(port, metrics, snap).await;
        });
    }

    info!(
        source = %config.fq_source(),
        features = %if config.is_phishing_model() {
            config.fq_phishing_features()
        } else if config.is_beacon_model() {
            config.fq_beacon_features()
        } else {
            config.fq_features()
        },
        scores = %config.fq_scores(),
        model = %config.model,
        entities = ?config.entity_types,
        poll_secs = config.poll_interval.as_secs(),
        lookback_secs = config.lookback.as_secs(),
        baseline_lookback_secs = config.baseline_lookback.as_secs(),
        baseline_path = ?config.baseline_path,
        webhook = webhook.is_some(),
        writeback = config.writeback_enabled,
        "ml-worker started (M5.5 write-back / M5.4 beacon / M5.3 phishing / UEBA)"
    );

    loop {
        if let Err(e) = cycle_once(&config, &ch, webhook.as_ref(), &metrics, &snapshot).await {
            metrics.errors.inc();
            warn!("ml-worker cycle failed: {e}");
        }
        tokio::time::sleep(config.poll_interval).await;
    }
}

async fn load_baselines(
    config: &Config,
    ch: &ClickHouseClient,
) -> Result<BaselineSet, Box<dyn std::error::Error>> {
    if let Some(path) = &config.baseline_path {
        let set = BaselineSet::load_json_file(path)?;
        info!(
            path = %path.display(),
            types = set.baselines.len(),
            "loaded baseline artifact"
        );
        return Ok(set);
    }
    if config.model != MODEL_UEBA {
        return Ok(BaselineSet::default());
    }
    let sql = baseline_sql(config);
    let rows = ch.query_json_each_row(&sql).await?;
    let set = baselines_from_rows(&rows, "clickhouse_live")?;
    info!(
        types = set.baselines.len(),
        lookback_secs = config.baseline_lookback.as_secs(),
        "loaded population baseline from ClickHouse"
    );
    Ok(set)
}

async fn cycle_once(
    config: &Config,
    ch: &ClickHouseClient,
    webhook: Option<&WebhookClient>,
    metrics: &WorkerMetrics,
    snapshot: &SnapshotStore,
) -> Result<(), Box<dyn std::error::Error>> {
    if config.is_phishing_model() {
        return cycle_phishing(config, ch, webhook, metrics, snapshot).await;
    }
    if config.is_beacon_model() {
        return cycle_beacon(config, ch, webhook, metrics, snapshot).await;
    }
    cycle_ueba(config, ch, webhook, metrics, snapshot).await
}

async fn persist_scores(
    config: &Config,
    ch: &ClickHouseClient,
    webhook: Option<&WebhookClient>,
    metrics: &WorkerMetrics,
    snapshot: &SnapshotStore,
    scored: Vec<ScoreResult>,
) -> Result<(), Box<dyn std::error::Error>> {
    for s in &scored {
        if let Some(wh) = webhook {
            if s.score >= config.score_threshold {
                if let Err(e) = wh.post_score(s).await {
                    warn!("webhook failed for {}: {e}", s.entity_id);
                    metrics.errors.inc();
                } else {
                    metrics.webhooks_sent.inc();
                }
            }
        }
    }
    let score_jsons: Vec<_> = scored.iter().map(|s| s.to_insert_json()).collect();
    ch.insert_json_each_row(&config.fq_scores(), &score_jsons)
        .await?;
    metrics.scores_written.inc_by(score_jsons.len() as u64);

    match publish_writeback(config, ch, snapshot, &scored).await {
        Ok(n) if n > 0 => info!("write-back published {n} threat scores"),
        Ok(_) => {}
        Err(e) => {
            warn!("write-back failed: {e}");
            metrics.errors.inc();
        }
    }
    metrics.cycles.inc();
    Ok(())
}

async fn cycle_beacon(
    config: &Config,
    ch: &ClickHouseClient,
    webhook: Option<&WebhookClient>,
    metrics: &WorkerMetrics,
    snapshot: &SnapshotStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let sql = beacon_extract_sql(config);
    let rows = ch.query_json_each_row(&sql).await?;
    let mut pairs = Vec::new();
    for row in rows {
        match beacon_from_row(&row) {
            Ok(f) => pairs.push(f),
            Err(e) => {
                warn!("skip beacon feature row: {e}");
                metrics.errors.inc();
            }
        }
    }

    let feature_jsons: Vec<_> = pairs.iter().map(|f| f.to_insert_json()).collect();
    ch.insert_json_each_row(&config.fq_beacon_features(), &feature_jsons)
        .await?;
    metrics.features_written.inc_by(feature_jsons.len() as u64);
    metrics.last_cycle_features.set(feature_jsons.len() as i64);

    let scored: Vec<_> = pairs.iter().map(|f| score_beacon_pair(f, config)).collect();
    persist_scores(config, ch, webhook, metrics, snapshot, scored).await?;

    info!(
        pairs = feature_jsons.len(),
        model = MODEL_CC_BEACON,
        "beacon cycle complete"
    );
    Ok(())
}

async fn cycle_phishing(
    config: &Config,
    ch: &ClickHouseClient,
    webhook: Option<&WebhookClient>,
    metrics: &WorkerMetrics,
    snapshot: &SnapshotStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let sql = phishing_extract_sql(config);
    let rows = ch.query_json_each_row(&sql).await?;
    let mut domains = Vec::new();
    for row in rows {
        match phishing_from_row(&row) {
            Ok(f) => domains.push(f),
            Err(e) => {
                warn!("skip phishing feature row: {e}");
                metrics.errors.inc();
            }
        }
    }

    let feature_jsons: Vec<_> = domains
        .iter()
        .map(|f| {
            let lex = lexical_signals(&f.domain);
            f.to_insert_json(&lex)
        })
        .collect();
    ch.insert_json_each_row(&config.fq_phishing_features(), &feature_jsons)
        .await?;
    metrics.features_written.inc_by(feature_jsons.len() as u64);
    metrics.last_cycle_features.set(feature_jsons.len() as i64);

    let scored: Vec<_> = domains
        .iter()
        .map(|f| score_domain(f, config.score_threshold))
        .collect();
    persist_scores(config, ch, webhook, metrics, snapshot, scored).await?;

    info!(
        domains = feature_jsons.len(),
        model = MODEL_PHISHING,
        "phishing cycle complete"
    );
    Ok(())
}

async fn cycle_ueba(
    config: &Config,
    ch: &ClickHouseClient,
    webhook: Option<&WebhookClient>,
    metrics: &WorkerMetrics,
    snapshot: &SnapshotStore,
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

    let baselines = load_baselines(config, ch).await?;
    if config.model == MODEL_UEBA && baselines.is_empty() {
        warn!("UEBA baseline empty — falling back to anomaly_stub_v0 until enough history");
    }

    let ctx = ScoreContext {
        model: &config.model,
        min_requests: config.min_requests,
        threshold: config.score_threshold,
        z_clip: config.z_clip,
        baselines: if baselines.is_empty() {
            None
        } else {
            Some(&baselines)
        },
    };

    let scored: Vec<_> = all_features
        .iter()
        .map(|f| score_features(f, &ctx))
        .collect();
    persist_scores(config, ch, webhook, metrics, snapshot, scored).await?;

    info!(
        features = feature_jsons.len(),
        baseline_types = baselines.baselines.len(),
        "cycle complete"
    );
    Ok(())
}

async fn run_admin_server(port: u16, metrics: WorkerMetrics, snapshot: SnapshotStore) {
    let addr = format!("0.0.0.0:{port}");
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("metrics bind {addr}: {e}");
            return;
        }
    };
    info!("ml-worker admin on http://{addr}/metrics · /api/threat-scores");
    let metrics = Arc::new(metrics);
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            continue;
        };
        let metrics = metrics.clone();
        let snapshot = snapshot.clone();
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
            } else if req.starts_with("GET /api/threat-scores") {
                ("200 OK", snapshot_json(&snapshot), "application/json")
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
