mod admin_server;
mod clickhouse;
mod dual;
mod kafka;
mod metrics;
mod opensearch;
mod search_api;

use admin_server::run_admin_server;
use bsdm_events::{DEFAULT_ISM_DELETE_DAYS, DEFAULT_ISM_HOT_DAYS, DEFAULT_ISM_POLICY_ID};
use clickhouse::{load_config_from_env, ClickHouseIndexer, ClickHouseWriter};
use dual::DualIndexer;
use metrics::IndexerMetrics;
use opensearch::{OpenSearchIndexer, OpenSearchWriter};
use search_api::{SearchApi, SearchApiConfig};
use std::sync::Arc;
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IndexerBackend {
    OpenSearch,
    ClickHouse,
    Dual,
}

fn parse_backend_name(name: &str) -> IndexerBackend {
    match name.to_ascii_lowercase().as_str() {
        "clickhouse" | "ch" => IndexerBackend::ClickHouse,
        "dual" => IndexerBackend::Dual,
        _ => IndexerBackend::OpenSearch,
    }
}

fn parse_backend() -> IndexerBackend {
    parse_backend_name(
        &std::env::var("INDEXER_BACKEND").unwrap_or_else(|_| "opensearch".to_string()),
    )
}

fn parse_env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn parse_env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(default)
}

fn metrics_port() -> u16 {
    std::env::var("METRICS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080)
}

fn search_api_enabled(backend: IndexerBackend) -> bool {
    if let Ok(v) = std::env::var("SEARCH_API_ENABLED") {
        return matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES");
    }
    matches!(backend, IndexerBackend::ClickHouse | IndexerBackend::Dual)
}

fn needs_clickhouse_writer(backend: IndexerBackend) -> bool {
    matches!(backend, IndexerBackend::ClickHouse | IndexerBackend::Dual)
        || search_api_enabled(backend)
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
    let backend = parse_backend();
    let metrics = Arc::new(IndexerMetrics::new()?);
    let ch_writer = if needs_clickhouse_writer(backend) {
        Some(bootstrap_clickhouse_writer().await?)
    } else {
        None
    };
    let search_api = if search_api_enabled(backend) {
        Some(Arc::new(SearchApi::new(
            ch_writer
                .clone()
                .expect("clickhouse writer required when search api enabled"),
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

    info!("Starting cache-indexer (backend={backend:?})");
    info!("Kafka brokers: {kafka_brokers}");
    info!("Kafka topic: {kafka_topic}");
    info!("Kafka group: {kafka_group}");
    info!("Admin port: {port}");
    if search_api.is_some() {
        info!("Search API enabled on :{port}/api/search");
    }

    let result = match backend {
        IndexerBackend::ClickHouse => {
            let writer = ch_writer.expect("clickhouse writer required");
            info!("ClickHouse URL: {}", load_config_from_env().url);
            let indexer =
                ClickHouseIndexer::new(&kafka_brokers, &kafka_topic, &kafka_group, writer, metrics)
                    .await?;
            indexer.run().await
        }
        IndexerBackend::Dual => {
            let opensearch_url = std::env::var("OPENSEARCH_URL")
                .unwrap_or_else(|_| "http://opensearch:9200".to_string());
            let index_name =
                std::env::var("OPENSEARCH_INDEX").unwrap_or_else(|_| "http-cache".to_string());
            let os_writer = OpenSearchWriter::bootstrap(
                &opensearch_url,
                std::env::var("OPENSEARCH_USERNAME").ok(),
                std::env::var("OPENSEARCH_PASSWORD").ok(),
                parse_env_bool("OPENSEARCH_SSL_VERIFY", true),
                &index_name,
                parse_env_bool("OPENSEARCH_ISM_ENABLED", true),
                std::env::var("OPENSEARCH_ISM_POLICY_ID")
                    .unwrap_or_else(|_| DEFAULT_ISM_POLICY_ID.to_string()),
                parse_env_u32("OPENSEARCH_ISM_HOT_DAYS", DEFAULT_ISM_HOT_DAYS),
                parse_env_u32("OPENSEARCH_ISM_DELETE_DAYS", DEFAULT_ISM_DELETE_DAYS),
            )
            .await?;
            let writer = ch_writer.expect("clickhouse writer required");
            let indexer = DualIndexer::new(
                &kafka_brokers,
                &kafka_topic,
                &kafka_group,
                os_writer,
                writer,
                metrics,
            )
            .await?;
            indexer.run().await
        }
        IndexerBackend::OpenSearch => {
            let opensearch_url = std::env::var("OPENSEARCH_URL")
                .unwrap_or_else(|_| "http://opensearch:9200".to_string());
            let indexer = OpenSearchIndexer::new(
                &kafka_brokers,
                &opensearch_url,
                std::env::var("OPENSEARCH_USERNAME").ok(),
                std::env::var("OPENSEARCH_PASSWORD").ok(),
                parse_env_bool("OPENSEARCH_SSL_VERIFY", true),
                &kafka_topic,
                &kafka_group,
                &std::env::var("OPENSEARCH_INDEX").unwrap_or_else(|_| "http-cache".to_string()),
                parse_env_bool("OPENSEARCH_ISM_ENABLED", true),
                std::env::var("OPENSEARCH_ISM_POLICY_ID")
                    .unwrap_or_else(|_| DEFAULT_ISM_POLICY_ID.to_string()),
                parse_env_u32("OPENSEARCH_ISM_HOT_DAYS", DEFAULT_ISM_HOT_DAYS),
                parse_env_u32("OPENSEARCH_ISM_DELETE_DAYS", DEFAULT_ISM_DELETE_DAYS),
                metrics,
            )
            .await?;
            indexer.run().await
        }
    };

    admin_task.abort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_backend_variants() {
        assert_eq!(parse_backend_name("clickhouse"), IndexerBackend::ClickHouse);
        assert_eq!(parse_backend_name("dual"), IndexerBackend::Dual);
        assert_eq!(parse_backend_name("opensearch"), IndexerBackend::OpenSearch);
    }

    #[test]
    fn search_enabled_for_clickhouse_by_default() {
        assert!(search_api_enabled(IndexerBackend::ClickHouse));
        assert!(!search_api_enabled(IndexerBackend::OpenSearch));
    }
}
