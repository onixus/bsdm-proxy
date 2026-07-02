//! Kafka cache-event pipeline with bounded in-memory queue (#106).

use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord, Producer};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::metrics::Metrics;

pub use bsdm_events::CacheEvent;

pub fn new_event_id() -> String {
    hex::encode(rand::random::<u128>().to_be_bytes())
}

pub fn create_kafka_producer(brokers: &str) -> Option<Arc<FutureProducer>> {
    let acks = std::env::var("KAFKA_ACKS").unwrap_or_else(|_| "1".to_string());
    let queue_buffering_max_ms =
        std::env::var("KAFKA_QUEUE_BUFFERING_MAX_MS").unwrap_or_else(|_| "5".to_string());
    let batch_size = std::env::var("KAFKA_BATCH_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32_768)
        .to_string();
    ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .set("message.timeout.ms", "5000")
        .set("compression.type", "snappy")
        .set("batch.size", &batch_size)
        .set("linger.ms", &queue_buffering_max_ms)
        .set("acks", &acks)
        .create()
        .ok()
        .map(Arc::new)
}

fn queue_capacity_from_env() -> usize {
    std::env::var("KAFKA_QUEUE_CAPACITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(8_192)
}

/// Non-blocking Kafka enqueue: bounded channel + background sender (no await on hot path).
pub struct KafkaEventPipeline {
    sender: mpsc::Sender<CacheEvent>,
    producer: Arc<FutureProducer>,
}

impl KafkaEventPipeline {
    pub fn spawn(brokers: &str, topic: String, metrics: Arc<Metrics>) -> Option<Arc<Self>> {
        let producer = create_kafka_producer(brokers)?;
        let capacity = queue_capacity_from_env();
        let (sender, mut receiver) = mpsc::channel::<CacheEvent>(capacity);
        let producer_worker = producer.clone();
        let metrics_worker = metrics.clone();

        tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                match serde_json::to_string(&event) {
                    Ok(payload) => {
                        let record = FutureRecord::to(&topic)
                            .payload(&payload)
                            .key(&event.event_id);
                        match producer_worker.send(record, Duration::ZERO).await {
                            Ok(_) => metrics_worker.kafka_events_sent.inc(),
                            Err((e, _)) => {
                                warn!("Kafka send failed: {}", e);
                                metrics_worker.kafka_send_errors.inc();
                            }
                        }
                    }
                    Err(e) => {
                        error!("Event serialization failed: {}", e);
                        metrics_worker.kafka_send_errors.inc();
                    }
                }
            }
        });

        info!(
            "Kafka event pipeline started (queue capacity={}, drop=policy:drop_new)",
            capacity
        );

        Some(Arc::new(Self { sender, producer }))
    }

    /// Enqueue without blocking the request hot path. Drops when queue is full (drop-new).
    pub fn try_enqueue(&self, event: CacheEvent, metrics: &Metrics) {
        match self.sender.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                metrics.kafka_queue_dropped_total.inc();
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                metrics.kafka_send_errors.inc();
            }
        }
    }

    pub fn producer(&self) -> Arc<FutureProducer> {
        self.producer.clone()
    }
}

/// Legacy helper — prefer `KafkaEventPipeline::try_enqueue`.
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
    info!("Flushing Kafka producer...");
    match tokio::task::spawn_blocking(move || producer.flush(timeout)).await {
        Ok(Ok(())) => info!("Kafka producer flushed"),
        Ok(Err(e)) => warn!("Kafka flush error: {}", e),
        Err(e) => error!("Kafka flush task failed: {}", e),
    }
}
