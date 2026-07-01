//! Dual-write backend: Kafka → OpenSearch + ClickHouse (migration validation).

use bsdm_events::CacheEvent;
use rdkafka::consumer::{CommitMode, Consumer, StreamConsumer};
use rdkafka::message::Message;
use std::sync::Arc;
use std::time::Instant;
use tracing::{error, info, warn};

use crate::clickhouse::ClickHouseWriter;
use crate::metrics::IndexerMetrics;
use crate::opensearch::OpenSearchWriter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChFailPolicy {
    /// Log CH errors; commit Kafka if OpenSearch succeeded.
    Warn,
    /// Fail batch if either backend fails.
    Fail,
}

impl ChFailPolicy {
    pub fn from_env() -> Self {
        match std::env::var("DUAL_WRITE_CH_FAIL_POLICY")
            .unwrap_or_else(|_| "warn".to_string())
            .to_ascii_lowercase()
            .as_str()
        {
            "fail" => Self::Fail,
            _ => Self::Warn,
        }
    }
}

pub struct DualIndexer {
    opensearch: OpenSearchWriter,
    clickhouse: ClickHouseWriter,
    consumer: StreamConsumer,
    metrics: Arc<IndexerMetrics>,
    ch_fail_policy: ChFailPolicy,
}

impl DualIndexer {
    pub async fn new(
        kafka_brokers: &str,
        kafka_topic: &str,
        kafka_group: &str,
        opensearch: OpenSearchWriter,
        clickhouse: ClickHouseWriter,
        metrics: Arc<IndexerMetrics>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let consumer = crate::kafka::create_consumer(kafka_brokers, kafka_topic, kafka_group)?;
        let ch_fail_policy = ChFailPolicy::from_env();
        info!(
            "Dual-write indexer ready (ch_fail_policy={:?})",
            ch_fail_policy
        );
        Ok(Self {
            opensearch,
            clickhouse,
            consumer,
            metrics,
            ch_fail_policy,
        })
    }

    async fn flush_batch(&self, batch: &[CacheEvent]) -> Result<(), Box<dyn std::error::Error>> {
        if batch.is_empty() {
            return Ok(());
        }

        let os_started = Instant::now();
        let os_result = self.opensearch.index_batch(batch).await;
        let os_ok = os_result.is_ok();
        match &os_result {
            Ok(()) => self
                .metrics
                .record_success("opensearch", batch.len(), os_started),
            Err(_) => self.metrics.record_error("opensearch"),
        }

        let ch_started = Instant::now();
        let ch_result = self.clickhouse.insert_batch(batch).await;
        let ch_ok = ch_result.is_ok();
        if ch_ok {
            self.metrics
                .record_success("clickhouse", batch.len(), ch_started);
        } else {
            self.metrics.record_error("clickhouse");
            if self.ch_fail_policy == ChFailPolicy::Warn {
                if let Err(ref e) = ch_result {
                    warn!("ClickHouse insert failed (dual-write warn policy): {e}");
                }
            }
        }

        os_result?;
        if self.ch_fail_policy == ChFailPolicy::Fail {
            ch_result?;
        }
        info!(
            "Dual-write flushed {} events (os_ok={}, ch_ok={})",
            batch.len(),
            os_ok,
            ch_ok
        );
        Ok(())
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
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
                                    self.flush_batch(&batch).await?;
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
                        self.flush_batch(&batch).await?;
                        batch.clear();
                        self.consumer.commit_consumer_state(CommitMode::Async)?;
                        last_commit = tokio::time::Instant::now();
                    }
                }
            }

            if last_commit.elapsed() > std::time::Duration::from_secs(30) && !batch.is_empty() {
                self.flush_batch(&batch).await?;
                batch.clear();
                self.consumer.commit_consumer_state(CommitMode::Async)?;
                last_commit = tokio::time::Instant::now();
            }
        }
    }
}
