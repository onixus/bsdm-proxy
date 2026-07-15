//! Kafka → EventStore consumer (optional when KAFKA_BROKERS is set).

use crate::kafka::create_consumer;
use crate::metrics::IndexerMetrics;
use crate::store::EventStore;
use bsdm_events::CacheEvent;
use rdkafka::consumer::{CommitMode, Consumer, StreamConsumer};
use rdkafka::message::Message;
use std::sync::Arc;
use std::time::Instant;
use tracing::{error, warn};

pub struct KafkaStoreIndexer {
    store: Arc<EventStore>,
    consumer: StreamConsumer,
    metrics: Arc<IndexerMetrics>,
}

impl KafkaStoreIndexer {
    pub async fn new(
        kafka_brokers: &str,
        kafka_topic: &str,
        kafka_group: &str,
        store: Arc<EventStore>,
        metrics: Arc<IndexerMetrics>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let consumer = create_consumer(kafka_brokers, kafka_topic, kafka_group)?;
        Ok(Self {
            store,
            consumer,
            metrics,
        })
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch: Vec<CacheEvent> = Vec::new();
        let batch_size = 50;
        let batch_timeout = std::time::Duration::from_secs(5);
        let mut last_commit = tokio::time::Instant::now();
        let backend = self.store.backend_name();

        loop {
            match tokio::time::timeout(batch_timeout, self.consumer.recv()).await {
                Ok(Ok(message)) => {
                    if let Some(payload) = message.payload() {
                        match serde_json::from_slice::<CacheEvent>(payload) {
                            Ok(event) => {
                                batch.push(event);
                                if batch.len() >= batch_size {
                                    self.flush_batch(&batch, backend).await?;
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
                        self.flush_batch(&batch, backend).await?;
                        batch.clear();
                        self.consumer.commit_consumer_state(CommitMode::Async)?;
                        last_commit = tokio::time::Instant::now();
                    }
                }
            }

            if last_commit.elapsed() > std::time::Duration::from_secs(30) && !batch.is_empty() {
                self.flush_batch(&batch, backend).await?;
                batch.clear();
                self.consumer.commit_consumer_state(CommitMode::Async)?;
                last_commit = tokio::time::Instant::now();
            }
        }
    }

    async fn flush_batch(
        &self,
        batch: &[CacheEvent],
        backend: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let started = Instant::now();
        match self.store.insert_batch(batch).await {
            Ok(()) => {
                self.metrics.record_success(backend, batch.len(), started);
                Ok(())
            }
            Err(e) => {
                self.metrics.record_error(backend);
                Err(e.to_string().into())
            }
        }
    }
}
