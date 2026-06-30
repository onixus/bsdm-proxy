//! Kafka cache-event pipeline.

use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord, Producer};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, warn};

use crate::metrics::Metrics;

pub use bsdm_events::CacheEvent;

pub fn new_event_id() -> String {
    hex::encode(rand::random::<u128>().to_be_bytes())
}

pub fn create_kafka_producer(brokers: &str) -> Option<Arc<FutureProducer>> {
    let acks = std::env::var("KAFKA_ACKS").unwrap_or_else(|_| "1".to_string());
    ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .set("message.timeout.ms", "5000")
        .set("compression.type", "snappy")
        .set("batch.size", "32768")
        .set("linger.ms", "5")
        .set("acks", &acks)
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
