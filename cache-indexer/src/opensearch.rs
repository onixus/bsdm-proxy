//! OpenSearch backend for cache-indexer (default `INDEXER_BACKEND=opensearch`).

use bsdm_events::{document_id, index_mappings, index_template_body, ism_policy_body, CacheEvent};
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
use rdkafka::consumer::{CommitMode, Consumer, StreamConsumer};
use rdkafka::message::Message;
use serde_json::json;
use tracing::{error, info, warn};

use crate::kafka::create_consumer;

struct IndexerConfig {
    index_name: String,
    index_pattern: String,
    ism_enabled: bool,
    ism_policy_id: String,
    ism_hot_days: u32,
    ism_delete_days: u32,
}

pub struct OpenSearchIndexer {
    opensearch: OpenSearch,
    consumer: StreamConsumer,
    config: IndexerConfig,
}

impl OpenSearchIndexer {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
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
        let consumer = create_consumer(kafka_brokers, kafka_topic, kafka_group)?;
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

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.ensure_ism_policy().await?;
        self.ensure_index_template().await?;
        self.ensure_index_exists().await?;
        self.attach_ism_policy_to_index().await?;

        let mut batch: Vec<CacheEvent> = Vec::new();
        let batch_size = 50;
        let batch_timeout = std::time::Duration::from_secs(5);
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

            if last_commit.elapsed() > std::time::Duration::from_secs(30) && !batch.is_empty() {
                self.index_batch(&batch).await?;
                batch.clear();
                self.consumer.commit_consumer_state(CommitMode::Async)?;
                last_commit = tokio::time::Instant::now();
            }
        }
    }
}
