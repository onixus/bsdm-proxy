mod admin_server;
mod clickhouse;
#[cfg(feature = "kafka")]
mod kafka;
#[cfg(feature = "kafka")]
mod kafka_ingest;
mod metrics;
mod search_api;
mod store;

use admin_server::run_admin_server;
use clickhouse::{load_config_from_env, ClickHouseWriter};
#[cfg(feature = "kafka")]
use kafka_ingest::KafkaStoreIndexer;
use metrics::IndexerMetrics;
use search_api::{SearchApi, SearchApiConfig};
use std::sync::Arc;
use store::EventStore;
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

fn index_store_kind() -> String {
    std::env::var("INDEX_STORE")
        .unwrap_or_else(|_| "clickhouse".into())
        .to_ascii_lowercase()
}

async fn bootstrap_store() -> Result<Arc<EventStore>, Box<dyn std::error::Error>> {
    match index_store_kind().as_str() {
        "clickhouse" => {
            let writer = Arc::new(ClickHouseWriter::bootstrap(load_config_from_env()).await?);
            Ok(Arc::new(EventStore::ClickHouse(writer)))
        }
        "memory" | "sqlite" => store::open_from_env().map_err(|e| e.to_string().into()),
        other => Err(format!("unknown INDEX_STORE={other}").into()),
    }
}

async fn run_http_ingest_only() -> Result<(), Box<dyn std::error::Error>> {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,cache_indexer=info".into()),
        )
        .init();

    let kafka_brokers = std::env::var("KAFKA_BROKERS")
        .ok()
        .filter(|s| !s.is_empty());
    #[cfg(feature = "kafka")]
    let kafka_topic = std::env::var("KAFKA_TOPIC").unwrap_or_else(|_| "cache-events".to_string());
    #[cfg(feature = "kafka")]
    let kafka_group =
        std::env::var("KAFKA_GROUP_ID").unwrap_or_else(|_| "cache-indexer-group".to_string());
    let metrics = Arc::new(IndexerMetrics::new()?);
    let store = bootstrap_store().await?;
    let backend = store.backend_name();

    let search_api = if search_api_enabled() {
        Some(Arc::new(SearchApi::new(
            store.clone(),
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

    info!("Starting cache-indexer (backend={backend})");
    if backend == "clickhouse" {
        info!("ClickHouse URL: {}", load_config_from_env().url);
    }
    info!("Admin port: {port}");
    if search_api.is_some() {
        info!("Search API on :{port}/api/search · ingest POST :{port}/api/events");
    }

    let result = {
        #[cfg(feature = "kafka")]
        {
            if let Some(brokers) = kafka_brokers {
                info!("Kafka brokers: {brokers}");
                info!("Kafka topic: {kafka_topic}");
                info!("Kafka group: {kafka_group}");
                let indexer =
                    KafkaStoreIndexer::new(&brokers, &kafka_topic, &kafka_group, store, metrics)
                        .await?;
                indexer.run().await
            } else {
                info!("KAFKA_BROKERS unset — HTTP ingest only (POST /api/events)");
                run_http_ingest_only().await
            }
        }
        #[cfg(not(feature = "kafka"))]
        {
            if kafka_brokers.is_some() {
                tracing::warn!(
                    "KAFKA_BROKERS is set but cache-indexer was built without the `kafka` feature — HTTP ingest only"
                );
            } else {
                info!("Kafka disabled at compile time — HTTP ingest only (POST /api/events)");
            }
            run_http_ingest_only().await
        }
    };

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
