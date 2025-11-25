use opensearch::{
    http::transport::TransportBuilder,
    BulkParts, OpenSearch,
};
use rdkafka::{
    config::ClientConfig,
    consumer::{CommitMode, Consumer, StreamConsumer},
    message::Message,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{error, info, warn};

// ... (остальной код Indexer и CacheEvent — без изменений)

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let kafka_brokers = std::env::var("KAFKA_BROKERS").unwrap_or_else(|_| "kafka:9092".to_string());
    let opensearch_url = std::env::var("OPENSEARCH_URL").unwrap_or_else(|_| "http://opensearch:9200".to_string());
    let kafka_topic = std::env::var("KAFKA_TOPIC").unwrap_or_else(|_| "cache-events".to_string());
    let kafka_group = std::env::var("KAFKA_GROUP_ID").unwrap_or_else(|_| "cache-indexer-group".to_string());
    let index_name = "http-cache";

    info!("Starting cache-indexer");
    info!("Kafka brokers: {}", kafka_brokers);
    info!("OpenSearch URL: {}", opensearch_url);
    info!("Kafka topic: {}", kafka_topic);
    info!("Kafka group: {}", kafka_group);

    let indexer = Indexer::new(
        &kafka_brokers,
        &opensearch_url,
        &kafka_topic,
        &kafka_group,
        index_name,
    ).await?;

    indexer.run().await
}
