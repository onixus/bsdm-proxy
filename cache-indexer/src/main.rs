use opensearch::{
    auth::Credentials,
    cert::CertificateValidation,
    http::transport::{SingleNodeConnectionPool, TransportBuilder},
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

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CacheEvent {
    url: String,
    method: String,
    status: u16,
    cache_key: String,
    timestamp: u64,
    #[serde(default)] // ИСПРАВЛЕНИЕ: делаем поле опциональным
    headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    cache_status: Option<String>,
    // New fields for user analytics
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    client_ip: String,
    domain: String,
    response_size: u64,
    request_duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    categories: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    event_id: Option<String>,
}

fn document_id(event: &CacheEvent) -> String {
    if let Some(id) = event.event_id.as_deref() {
        if !id.is_empty() {
            return id.to_string();
        }
    }

    format!(
        "{}:{}:{}:{}",
        event.timestamp, event.request_duration_ms, event.client_ip, event.cache_key
    )
}

struct Indexer {
    opensearch: OpenSearch,
    consumer: StreamConsumer,
    index_name: String,
}

impl Indexer {
    #[allow(clippy::too_many_arguments)]
    async fn new(
        kafka_brokers: &str,
        opensearch_url: &str,
        opensearch_username: Option<String>,
        opensearch_password: Option<String>,
        ssl_verify: bool,
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

        // Создаём транспорт с аутентификацией
        let mut transport_builder =
            TransportBuilder::new(SingleNodeConnectionPool::new(opensearch_url.parse()?));

        // Добавляем credentials если указаны
        if let (Some(username), Some(password)) = (opensearch_username, opensearch_password) {
            info!("Using authentication for OpenSearch: {}", username);
            transport_builder = transport_builder.auth(Credentials::Basic(username, password));
        }

        // Отключаем проверку SSL если нужно
        if !ssl_verify {
            warn!("SSL certificate verification is disabled!");
            transport_builder = transport_builder.cert_validation(CertificateValidation::None);
        }

        let transport = transport_builder.build()?;
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
                    "cache_status": { "type": "keyword" },
                    "timestamp": { "type": "date", "format": "epoch_second" },
                    "headers": { "type": "object" },
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
                    },
                    "categories": { "type": "keyword" },
                    "event_id": { "type": "keyword" }
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
        let mut last_commit = tokio::time::Instant::now();

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
                                    last_commit = tokio::time::Instant::now();
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to parse event: {} - Payload: {}",
                                    e,
                                    String::from_utf8_lossy(payload)
                                );
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
                        last_commit = tokio::time::Instant::now();
                    }
                }
            }

            if last_commit.elapsed() > Duration::from_secs(30) && !batch.is_empty() {
                self.index_batch(&batch).await?;
                batch.clear();
                self.consumer.commit_consumer_state(CommitMode::Async)?;
                last_commit = tokio::time::Instant::now();
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
                    "_id": document_id(event)
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
                    info!("✅ Indexed {} events to OpenSearch", events.len());
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
    let opensearch_username = std::env::var("OPENSEARCH_USERNAME").ok();
    let opensearch_password = std::env::var("OPENSEARCH_PASSWORD").ok();
    let ssl_verify = std::env::var("OPENSEARCH_SSL_VERIFY")
        .unwrap_or_else(|_| "true".to_string())
        .parse::<bool>()
        .unwrap_or(true);
    let kafka_topic = std::env::var("KAFKA_TOPIC").unwrap_or_else(|_| "cache-events".to_string());
    let kafka_group =
        std::env::var("KAFKA_GROUP_ID").unwrap_or_else(|_| "cache-indexer-group".to_string());
    let index_name = std::env::var("OPENSEARCH_INDEX").unwrap_or_else(|_| "http-cache".to_string());

    info!("🚀 Starting cache-indexer");
    info!("📡 Kafka brokers: {}", kafka_brokers);
    info!("🔍 OpenSearch URL: {}", opensearch_url);
    info!("🔐 SSL verification: {}", ssl_verify);
    info!("📨 Kafka topic: {}", kafka_topic);
    info!("👥 Kafka group: {}", kafka_group);
    info!("📇 OpenSearch index: {}", index_name);

    let indexer = Indexer::new(
        &kafka_brokers,
        &opensearch_url,
        opensearch_username,
        opensearch_password,
        ssl_verify,
        &kafka_topic,
        &kafka_group,
        &index_name,
    )
    .await?;

    indexer.run().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_id_prefers_event_id() {
        let event = CacheEvent {
            url: "https://example.com".to_string(),
            method: "GET".to_string(),
            status: 200,
            cache_key: "abc123".to_string(),
            timestamp: 1700000001,
            headers: HashMap::new(),
            cache_status: Some("HIT".to_string()),
            user_id: None,
            username: None,
            client_ip: "127.0.0.1".to_string(),
            domain: "example.com".to_string(),
            response_size: 100,
            request_duration_ms: 5,
            content_type: None,
            user_agent: None,
            categories: vec!["malware".to_string()],
            event_id: Some("evt-unique-1".to_string()),
        };

        assert_eq!(document_id(&event), "evt-unique-1");
    }

    #[test]
    fn document_id_differs_for_same_second_and_cache_key() {
        let base = CacheEvent {
            url: "https://example.com".to_string(),
            method: "GET".to_string(),
            status: 200,
            cache_key: "abc123".to_string(),
            timestamp: 1700000001,
            headers: HashMap::new(),
            cache_status: Some("MISS".to_string()),
            user_id: None,
            username: None,
            client_ip: "127.0.0.1".to_string(),
            domain: "example.com".to_string(),
            response_size: 100,
            request_duration_ms: 5,
            content_type: None,
            user_agent: None,
            categories: vec![],
            event_id: None,
        };

        let mut other = base.clone();
        other.request_duration_ms = 9;

        assert_ne!(document_id(&base), document_id(&other));
    }

    #[test]
    fn deserializes_categories_from_proxy_event() {
        let json_data = r#"{
            "url": "https://example.com",
            "method": "GET",
            "status": 200,
            "cache_key": "key123",
            "timestamp": 1700000000,
            "headers": {},
            "cache_status": "MISS",
            "client_ip": "10.0.0.1",
            "domain": "example.com",
            "response_size": 512,
            "request_duration_ms": 42,
            "categories": ["phishing", "malware"],
            "event_id": "evt-proxy-1"
        }"#;

        let event: CacheEvent = serde_json::from_str(json_data).unwrap();
        assert_eq!(event.categories, vec!["phishing", "malware"]);
        assert_eq!(event.event_id.as_deref(), Some("evt-proxy-1"));
    }
}
