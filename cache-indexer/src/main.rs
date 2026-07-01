mod admin_server;
mod clickhouse;
mod kafka;
mod metrics;
mod search_api;

use admin_server::run_admin_server;
use clickhouse::{load_config_from_env, ClickHouseIndexer, ClickHouseWriter};
use metrics::IndexerMetrics;
use search_api::{SearchApi, SearchApiConfig};
use std::sync::Arc;
use tracing::info;

fn metrics_port() -> u16 {
    std::env::var("METRICS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080)
}

fn search_api_enabled() -> bool {
    if let Ok(v) = std::env::var("SEARCH_API_ENABLED") {
        return matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES");
    }
    true
}

async fn bootstrap_clickhouse_writer() -> Result<Arc<ClickHouseWriter>, Box<dyn std::error::Error>>
{
    Ok(Arc::new(
        ClickHouseWriter::bootstrap(load_config_from_env()).await?,
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,cache_indexer=info".into()),
        )
        .init();

    let kafka_brokers = std::env::var("KAFKA_BROKERS").unwrap_or_else(|_| "kafka:9092".to_string());
    let kafka_topic = std::env::var("KAFKA_TOPIC").unwrap_or_else(|_| "cache-events".to_string());
    let kafka_group =
        std::env::var("KAFKA_GROUP_ID").unwrap_or_else(|_| "cache-indexer-group".to_string());
    let metrics = Arc::new(IndexerMetrics::new()?);
    let ch_writer = bootstrap_clickhouse_writer().await?;
    let search_api = if search_api_enabled() {
        Some(Arc::new(SearchApi::new(
            ch_writer.clone(),
            SearchApiConfig::from_env(),
        )))
    } else {
        None
    };
    let port = metrics_port();
    let admin_task = {
        let metrics = metrics.clone();
        let search_api = search_api.clone();
        tokio::spawn(async move {
            run_admin_server(port, metrics, search_api).await;
        })
    };

    info!("Starting cache-indexer (backend=clickhouse)");
    info!("ClickHouse URL: {}", load_config_from_env().url);
    info!("Kafka brokers: {kafka_brokers}");
    info!("Kafka topic: {kafka_topic}");
    info!("Kafka group: {kafka_group}");
    info!("Admin port: {port}");
    if search_api.is_some() {
        info!("Search API enabled on :{port}/api/search");
    }

    let indexer = ClickHouseIndexer::new(
        &kafka_brokers,
        &kafka_topic,
        &kafka_group,
        ch_writer,
        metrics,
    )
    .await?;

    let result = indexer.run().await;
    admin_task.abort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_enabled_by_default() {
        assert!(search_api_enabled());
    }
}
