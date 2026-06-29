//! Kafka cache-event pipeline.

use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord, Producer};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, warn};

use crate::metrics::Metrics;

#[derive(Serialize, Clone, Debug)]
pub struct CacheEvent {
    pub url: String,
    pub method: String,
    pub status: u16,
    pub cache_key: String,
    pub cache_status: &'static str,
    pub timestamp: u64,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub client_ip: String,
    pub domain: String,
    pub response_size: u64,
    pub request_duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    pub event_id: String,
}

pub fn new_event_id() -> String {
    hex::encode(rand::random::<u128>().to_be_bytes())
}

pub fn create_kafka_producer(brokers: &str) -> Option<Arc<FutureProducer>> {
    ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .set("message.timeout.ms", "5000")
        .set("compression.type", "snappy")
        .set("batch.size", "32768")
        .set("linger.ms", "5")
        .set("acks", "1")
        .create()
        .ok()
        .map(Arc::new)
}

pub fn send_to_kafka_async(
    producer: Arc<FutureProducer>,
    topic: String,
    metrics: Arc<Metrics>,
    event: CacheEvent,
) {
    tokio::spawn(async move {
        match serde_json::to_string(&event) {
            Ok(payload) => {
                let record = FutureRecord::to(&topic)
                    .payload(&payload)
                    .key(&event.event_id);
                match producer.send(record, Duration::ZERO).await {
                    Ok(_) => metrics.kafka_events_sent.inc(),
                    Err((e, _)) => {
                        warn!("Kafka send failed: {}", e);
                        metrics.kafka_send_errors.inc();
                    }
                }
            }
            Err(e) => {
                error!("Event serialization failed: {}", e);
                metrics.kafka_send_errors.inc();
            }
        }
    });
}

pub async fn flush_kafka(producer: Arc<FutureProducer>, timeout: Duration) {
    tracing::info!("Flushing Kafka producer...");
    match tokio::task::spawn_blocking(move || producer.flush(timeout)).await {
        Ok(Ok(())) => tracing::info!("Kafka producer flushed"),
        Ok(Err(e)) => warn!("Kafka flush error: {}", e),
        Err(e) => error!("Kafka flush task failed: {}", e),
    }
}
