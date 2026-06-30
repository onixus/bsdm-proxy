use bsdm_events::{
    document_id, index_mappings, index_template_body, ism_policy_body, CacheEvent,
    DEFAULT_ISM_DELETE_DAYS, DEFAULT_ISM_HOT_DAYS, DEFAULT_ISM_POLICY_ID,
};
use opensearch::{
    auth::Credentials,
    cert::CertificateValidation,
    http::headers::HeaderMap,
    http::request::JsonBody,
    http::transport::{SingleNodeConnectionPool, TransportBuilder},
    http::Method,
    indices::{IndicesCreateParts, IndicesExistsParts},
    BulkParts, OpenSearch,
};
use rdkafka::{
    config::ClientConfig,
    consumer::{CommitMode, Consumer, StreamConsumer},
    message::Message,
};
use serde_json::json;
use std::time::Duration;
use tracing::{error, info, warn};

struct IndexerConfig {
    index_name: String,
    index_pattern: String,
    ism_enabled: bool,
    ism_policy_id: String,
    ism_hot_days: u32,
    ism_delete_days: u32,
}

struct Indexer {
    opensearch: OpenSearch,
    consumer: StreamConsumer,
    config: IndexerConfig,
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
        ism_enabled: bool,
        ism_policy_id: String,
        ism_hot_days: u32,
        ism_delete_days: u32,
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

        let mut transport_builder =
            TransportBuilder::new(SingleNodeConnectionPool::new(opensearch_url.parse()?));

        if let (Some(username), Some(password)) = (opensearch_username, opensearch_password) {
            info!("Using authentication for OpenSearch: {}", username);
            transport_builder = transport_builder.auth(Credentials::Basic(username, password));
        }

        if !ssl_verify {
            warn!("SSL certificate verification is disabled!");
            transport_builder = transport_builder.cert_validation(CertificateValidation::None);
        }

        let transport = transport_builder.build()?;
        let opensearch = OpenSearch::new(transport);
        let index_pattern = format!("{index_name}*");

        Ok(Self {
            opensearch,
            consumer,
            config: IndexerConfig {
                index_name: index_name.to_string(),
                index_pattern,
                ism_enabled,
                ism_policy_id,
                ism_hot_days,
                ism_delete_days,
            },
        })
    }

    async fn send_json(
        &self,
        method: Method,
        path: &str,
        body: serde_json::Value,
    ) -> Result<opensearch::http::response::Response, opensearch::Error> {
        self.opensearch
            .send(
                method,
                path,
                HeaderMap::new(),
                None::<&()>,
                Some(JsonBody::new(body)),
                None,
            )
            .await
    }

    async fn ensure_index_template(&self) -> Result<(), Box<dyn std::error::Error>> {
        let template_name = "bsdm-http-cache";
        let body = index_template_body(&self.config.index_pattern);

        match self
            .opensearch
            .indices()
            .put_index_template(opensearch::indices::IndicesPutIndexTemplateParts::Name(
                template_name,
            ))
            .body(body)
            .send()
            .await
        {
            Ok(response) if response.status_code().is_success() => {
                info!(
                    "Index template '{}' applied for pattern '{}'",
                    template_name, self.config.index_pattern
                );
                Ok(())
            }
            Ok(response) => {
                warn!(
                    "Index template upsert returned status {}",
                    response.status_code()
                );
                Ok(())
            }
            Err(e) => {
                warn!("Failed to upsert index template: {}", e);
                Ok(())
            }
        }
    }

    async fn ensure_ism_policy(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.config.ism_enabled {
            info!("OpenSearch ISM disabled");
            return Ok(());
        }

        let policy = ism_policy_body(
            &self.config.index_pattern,
            &self.config.ism_policy_id,
            self.config.ism_hot_days,
            self.config.ism_delete_days,
        );
        let path = format!("/_plugins/_ism/policies/{}", self.config.ism_policy_id);

        match self.send_json(Method::Put, &path, policy).await {
            Ok(response) if response.status_code().is_success() => {
                info!(
                    "ISM policy '{}' applied (hot={}d, delete={}d)",
                    self.config.ism_policy_id,
                    self.config.ism_hot_days,
                    self.config.ism_delete_days
                );
                Ok(())
            }
            Ok(response) => {
                warn!(
                    "ISM policy upsert returned status {}",
                    response.status_code()
                );
                Ok(())
            }
            Err(e) => {
                warn!("Failed to upsert ISM policy: {}", e);
                Ok(())
            }
        }
    }

    async fn attach_ism_policy_to_index(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.config.ism_enabled {
            return Ok(());
        }

        let path = format!("/_plugins/_ism/add/{}", self.config.index_name);
        let body = json!({ "policy_id": self.config.ism_policy_id });

        match self.send_json(Method::Post, &path, body).await {
            Ok(response) if response.status_code().is_success() => {
                info!(
                    "ISM policy '{}' attached to index '{}'",
                    self.config.ism_policy_id, self.config.index_name
                );
                Ok(())
            }
            Ok(response) => {
                warn!(
                    "ISM attach for index '{}' returned status {}",
                    self.config.index_name,
                    response.status_code()
                );
                Ok(())
            }
            Err(e) => {
                warn!(
                    "Failed to attach ISM policy to index '{}': {}",
                    self.config.index_name, e
                );
                Ok(())
            }
        }
    }

    async fn ensure_index_exists(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut settings = json!({
            "number_of_shards": 1,
            "number_of_replicas": 0
        });
        if self.config.ism_enabled {
            settings["plugins.index_state_management.policy_id"] = json!(self.config.ism_policy_id);
        }

        let index_body = json!({
            "mappings": index_mappings(),
            "settings": settings
        });

        match self
            .opensearch
            .indices()
            .exists(IndicesExistsParts::Index(&[&self.config.index_name]))
            .send()
            .await
        {
            Ok(response) if response.status_code().is_success() => {
                info!("Index '{}' already exists", self.config.index_name);
                return Ok(());
            }
            Ok(_) => {}
            Err(e) => warn!("Error checking index existence: {}", e),
        }

        match self
            .opensearch
            .indices()
            .create(IndicesCreateParts::Index(&self.config.index_name))
            .body(index_body)
            .send()
            .await
        {
            Ok(_) => {
                info!("Created index '{}'", self.config.index_name);
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
                    "_index": &self.config.index_name,
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
            Ok(response) if response.status_code().is_success() => {
                info!("Indexed {} events to OpenSearch", events.len());
                Ok(())
            }
            Ok(response) => {
                warn!(
                    "Bulk index returned non-success status: {}",
                    response.status_code()
                );
                Ok(())
            }
            Err(e) => {
                error!("Failed to bulk index: {}", e);
                Err(Box::new(e))
            }
        }
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.ensure_ism_policy().await?;
        self.ensure_index_template().await?;
        self.ensure_index_exists().await?;
        self.attach_ism_policy_to_index().await?;
        self.process_events().await
    }
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,cache_indexer=info".into()),
        )
        .init();

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
    let ism_enabled = parse_env_bool("OPENSEARCH_ISM_ENABLED", true);
    let ism_policy_id = std::env::var("OPENSEARCH_ISM_POLICY_ID")
        .unwrap_or_else(|_| DEFAULT_ISM_POLICY_ID.to_string());
    let ism_hot_days = parse_env_u32("OPENSEARCH_ISM_HOT_DAYS", DEFAULT_ISM_HOT_DAYS);
    let ism_delete_days = parse_env_u32("OPENSEARCH_ISM_DELETE_DAYS", DEFAULT_ISM_DELETE_DAYS);

    info!("Starting cache-indexer");
    info!("Kafka brokers: {}", kafka_brokers);
    info!("OpenSearch URL: {}", opensearch_url);
    info!("SSL verification: {}", ssl_verify);
    info!("Kafka topic: {}", kafka_topic);
    info!("Kafka group: {}", kafka_group);
    info!("OpenSearch index: {}", index_name);
    info!(
        "OpenSearch ISM: enabled={}, policy={}, hot={}d, delete={}d",
        ism_enabled, ism_policy_id, ism_hot_days, ism_delete_days
    );

    let indexer = Indexer::new(
        &kafka_brokers,
        &opensearch_url,
        opensearch_username,
        opensearch_password,
        ssl_verify,
        &kafka_topic,
        &kafka_group,
        &index_name,
        ism_enabled,
        ism_policy_id,
        ism_hot_days,
        ism_delete_days,
    )
    .await?;

    indexer.run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample_event(event_id: &str) -> CacheEvent {
        CacheEvent {
            url: "https://example.com".to_string(),
            method: "GET".to_string(),
            status: 200,
            cache_key: "abc123".to_string(),
            cache_status: "HIT".to_string(),
            timestamp: 1700000001,
            headers: HashMap::new(),
            user_id: None,
            username: None,
            client_ip: "127.0.0.1".to_string(),
            domain: "example.com".to_string(),
            response_size: 100,
            request_duration_ms: 5,
            content_type: None,
            user_agent: None,
            categories: vec!["malware".to_string()],
            threat_sources: vec!["urlhaus".to_string()],
            acl_action: None,
            event_id: event_id.to_string(),
        }
    }

    #[test]
    fn document_id_prefers_event_id() {
        assert_eq!(document_id(&sample_event("evt-unique-1")), "evt-unique-1");
    }

    #[test]
    fn document_id_differs_for_same_second_and_cache_key() {
        let base = sample_event("");
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
            "threat_sources": ["phishtank"],
            "acl_action": "deny",
            "event_id": "evt-proxy-1"
        }"#;

        let event: CacheEvent = serde_json::from_str(json_data).unwrap();
        assert_eq!(event.categories, vec!["phishing", "malware"]);
        assert_eq!(event.threat_sources, vec!["phishtank"]);
        assert_eq!(event.acl_action.as_deref(), Some("deny"));
        assert_eq!(event.event_id, "evt-proxy-1");
    }

    #[test]
    fn parse_env_bool_defaults() {
        assert!(parse_env_bool("MISSING_VAR", true));
        assert!(!parse_env_bool("MISSING_VAR", false));
    }
}
