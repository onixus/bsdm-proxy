use opensearch::{http::transport::TransportBuilder, BulkParts, OpenSearch};
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

#[derive(Debug, Deserialize, Serialize)]
struct CacheEvent {
    url: String,
    method: String,
    status: u16,
    cache_key: String,
    timestamp: u64,
    headers: HashMap<String, String>,
    body: String,
    // New fields for user analytics
    user_id: Option<String>,
    username: Option<String>,
    client_ip: String,
    domain: String,
    response_size: u64,
    request_duration_ms: u64,
    content_type: Option<String>,
    user_agent: Option<String>,
}

struct Indexer {
    opensearch: OpenSearch,
    consumer: StreamConsumer,
    index_name: String,
}

impl Indexer {
    async fn new(
        kafka_brokers: &str,
        opensearch_url: &str,
        kafka_topic: &str,
        kafka_group: &str,
        index_name: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("group.id", kafka_group)
            .set("bootstrap.servers", kafka_brokers)
            .set("enable.auto.commit", "false")
            .set("auto.offset.reset", "earliest")
            .set("session.timeout.ms", "30000")
            .create()?;

        consumer.subscribe(&[kafka_topic])?;
        info!("Subscribed to Kafka topic: {}", kafka_topic);

        let transport = TransportBuilder::new(
            opensearch::http::transport::SingleNodeConnectionPool::new(opensearch_url.parse()?),
        )
        .build()?;

        let opensearch = OpenSearch::new(transport);

        Ok(Self {
            opensearch,
            consumer,
            index_name: index_name.to_string(),
        })
    }

    async fn ensure_index_exists(&self) -> Result<(), Box<dyn std::error::Error>> {
        let index_body = json!({
            "mappings": {
                "properties": {
                    "url": {
                        "type": "text",
                        "fields": {
                            "keyword": {
                                "type": "keyword",
                                "ignore_above": 256
                            }
                        }
                    },
                    "method": { "type": "keyword" },
                    "status": { "type": "short" },
                    "cache_key": { "type": "keyword" },
                    "timestamp": { "type": "date", "format": "epoch_second" },
                    "headers": { "type": "object" },
                    "body": { "type": "text" },
                    // New fields for user analytics
                    "user_id": { "type": "keyword" },
                    "username": { "type": "keyword" },
                    "client_ip": { "type": "ip" },
                    "domain": { "type": "keyword" },
                    "response_size": { "type": "long" },
                    "request_duration_ms": { "type": "long" },
                    "content_type": { "type": "keyword" },
                    "user_agent": {
                        "type": "text",
                        "fields": {
                            "keyword": {
                                "type": "keyword",
                                "ignore_above": 256
                            }
                        }
                    }
                }
            },
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            }
        });

        match self
            .opensearch
            .indices()
            .exists(opensearch::indices::IndicesExistsParts::Index(&[
                &self.index_name
            ]))
            .send()
            .await
        {
            Ok(response) => {
                if response.status_code().is_success() {
                    info!("Index '{}' already exists", self.index_name);
                    return Ok(());
                }
            }
            Err(e) => {
                warn!("Error checking index existence: {}", e);
            }
        }

        match self
            .opensearch
            .indices()
            .create(opensearch::indices::IndicesCreateParts::Index(
                &self.index_name,
            ))
            .body(index_body)
            .send()
            .await
        {
            Ok(_) => {
                info!("Created index '{}'", self.index_name);
                Ok(())
            }
            Err(e) => {
                error!("Failed to create index: {}", e);
                Err(Box::new(e))
            }
        }
    }

    async fn process_events(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch: Vec<CacheEvent> = Vec::new();
        let batch_size = 50;
        let batch_timeout = Duration::from_secs(5);
        let last_commit = tokio::time::Instant::now();

        loop {
            match tokio::time::timeout(batch_timeout, self.consumer.recv()).await {
                Ok(Ok(message)) => {
                    if let Some(payload) = message.payload() {
                        match serde_json::from_slice::<CacheEvent>(payload) {
                            Ok(event) => {
                                batch.push(event);

                                if batch.len() >= batch_size {
                                    self.index_batch(&batch).await?;
                                    batch.clear();
                                    self.consumer.commit_consumer_state(CommitMode::Async)?;
                                }
                            }
                            Err(e) => {
                                warn!("Failed to parse event: {}", e);
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!("Kafka error: {}", e);
                }
                Err(_) => {
                    if !batch.is_empty() {
                        self.index_batch(&batch).await?;
                        batch.clear();
                        self.consumer.commit_consumer_state(CommitMode::Async)?;
                    }
                }
            }

            if last_commit.elapsed() > Duration::from_secs(30) && !batch.is_empty() {
                self.index_batch(&batch).await?;
                batch.clear();
                self.consumer.commit_consumer_state(CommitMode::Async)?;
            }
        }
    }

    async fn index_batch(&self, events: &[CacheEvent]) -> Result<(), Box<dyn std::error::Error>> {
        if events.is_empty() {
            return Ok(());
        }

        let mut body_lines: Vec<String> = Vec::new();

        for event in events {
            let action = json!({
                "index": {
                    "_index": &self.index_name,
                    "_id": &event.cache_key
                }
            });
            body_lines.push(serde_json::to_string(&action)?);

            body_lines.push(serde_json::to_string(&event)?);
        }

        let body_str = body_lines.join("\n") + "\n";

        let body = vec![body_str.into_bytes()];

        match self
            .opensearch
            .bulk(BulkParts::None)
            .body(body)
            .send()
            .await
        {
            Ok(response) => {
                if response.status_code().is_success() {
                    info!("Indexed {} events to OpenSearch", events.len());
                } else {
                    warn!(
                        "Bulk index returned non-success status: {}",
                        response.status_code()
                    );
                }
                Ok(())
            }
            Err(e) => {
                error!("Failed to bulk index: {}", e);
                Err(Box::new(e))
            }
        }
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.ensure_index_exists().await?;
        self.process_events().await
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let kafka_brokers = std::env::var("KAFKA_BROKERS").unwrap_or_else(|_| "kafka:9092".to_string());
    let opensearch_url =
        std::env::var("OPENSEARCH_URL").unwrap_or_else(|_| "http://opensearch:9200".to_string());
    let kafka_topic = std::env::var("KAFKA_TOPIC").unwrap_or_else(|_| "cache-events".to_string());
    let kafka_group =
        std::env::var("KAFKA_GROUP_ID").unwrap_or_else(|_| "cache-indexer-group".to_string());
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
    )
    .await?;

    indexer.run().await
}
