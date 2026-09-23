//! HTTP and Kafka cache-event pipelines with bounded in-memory queue (#106).

use futures_util::stream::{FuturesUnordered, StreamExt};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::metrics::Metrics;

pub use bsdm_events::CacheEvent;

#[cfg(feature = "kafka")]
const DEFAULT_KAFKA_MAX_IN_FLIGHT: usize = 256;
const DEFAULT_HTTP_MAX_IN_FLIGHT: usize = 16;

pub fn new_event_id() -> String {
    hex::encode(rand::random::<u128>().to_be_bytes())
}

fn positive_usize_from_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

fn queue_capacity_from_env() -> usize {
    positive_usize_from_env("KAFKA_QUEUE_CAPACITY", 8_192)
}

/// Drain a bounded input channel with at most `max_in_flight` asynchronous
/// deliveries. The channel still provides the request-path backpressure bound;
/// this second bound prevents slow sinks from creating an unbounded future set.
/// All delivery futures are polled by one pipeline task, avoiding one Tokio task
/// allocation and scheduler hop per event.
async fn run_bounded_workers<T, F, Fut>(
    mut receiver: mpsc::Receiver<T>,
    max_in_flight: usize,
    handler: F,
) where
    T: Send + 'static,
    F: Fn(T) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let max_in_flight = max_in_flight.max(1);
    let mut in_flight = FuturesUnordered::new();

    loop {
        if in_flight.len() >= max_in_flight {
            let _ = in_flight.next().await;
            continue;
        }

        tokio::select! {
            biased;
            _ = in_flight.next(), if !in_flight.is_empty() => {}
            event = receiver.recv() => {
                let Some(event) = event else {
                    break;
                };
                in_flight.push(handler(event));
            }
        }
    }

    // Preserve the previous graceful-drain behavior when all senders are
    // dropped: queued deliveries finish before the pipeline task exits.
    while in_flight.next().await.is_some() {}
}

/// Enqueue cache events to Kafka (if enabled) or HTTP sink.
pub fn dispatch_cache_event(
    #[cfg(feature = "kafka")] kafka: Option<&KafkaEventPipeline>,
    http: Option<&HttpEventPipeline>,
    event: CacheEvent,
    metrics: &Metrics,
) {
    #[cfg(feature = "kafka")]
    if let Some(pipeline) = kafka {
        pipeline.try_enqueue(event, metrics);
        return;
    }
    if let Some(pipeline) = http {
        pipeline.try_enqueue(event, metrics);
    }
}

#[cfg(feature = "kafka")]
mod kafka_pipeline {
    use super::*;
    use rdkafka::config::ClientConfig;
    use rdkafka::producer::{FutureProducer, FutureRecord, Producer};

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

    /// Non-blocking Kafka enqueue: bounded channel + bounded concurrent sender
    /// set (no network await on the request hot path).
    pub struct KafkaEventPipeline {
        sender: mpsc::Sender<CacheEvent>,
        producer: Arc<FutureProducer>,
    }

    impl KafkaEventPipeline {
        pub fn spawn(brokers: &str, topic: String, metrics: Arc<Metrics>) -> Option<Arc<Self>> {
            let producer = create_kafka_producer(brokers)?;
            let capacity = queue_capacity_from_env();
            let max_in_flight =
                positive_usize_from_env("KAFKA_MAX_IN_FLIGHT", DEFAULT_KAFKA_MAX_IN_FLIGHT);
            let (sender, receiver) = mpsc::channel::<CacheEvent>(capacity);
            let producer_worker = producer.clone();
            let metrics_worker = metrics.clone();
            let topic_worker: Arc<str> = Arc::from(topic);

            tokio::spawn(run_bounded_workers(receiver, max_in_flight, move |event| {
                let producer = producer_worker.clone();
                let metrics = metrics_worker.clone();
                let topic = Arc::clone(&topic_worker);
                async move {
                    match serde_json::to_string(&event) {
                        Ok(payload) => {
                            let record = FutureRecord::to(topic.as_ref())
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
                }
            }));

            info!(
                "Kafka event pipeline started (queue capacity={}, max in-flight={}, drop=policy:drop_new)",
                capacity, max_in_flight
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

    pub async fn flush_kafka(producer: Arc<FutureProducer>, timeout: Duration) {
        info!("Flushing Kafka producer...");
        match tokio::task::spawn_blocking(move || producer.flush(timeout)).await {
            Ok(Ok(())) => info!("Kafka producer flushed"),
            Ok(Err(e)) => warn!("Kafka flush error: {}", e),
            Err(e) => error!("Kafka flush task failed: {}", e),
        }
    }
}

#[cfg(feature = "kafka")]
pub use kafka_pipeline::{flush_kafka, KafkaEventPipeline};

/// HTTP POST sink for Lite indexer (`EVENT_SINK_URL` → POST /api/events).
pub struct HttpEventPipeline {
    sender: mpsc::Sender<CacheEvent>,
}

impl HttpEventPipeline {
    pub fn spawn(url: String, token: Option<String>, metrics: Arc<Metrics>) -> Option<Arc<Self>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .ok()?;
        let capacity = queue_capacity_from_env();
        let max_in_flight =
            positive_usize_from_env("EVENT_SINK_MAX_IN_FLIGHT", DEFAULT_HTTP_MAX_IN_FLIGHT);
        let (sender, receiver) = mpsc::channel::<CacheEvent>(capacity);
        let metrics_worker = metrics.clone();
        let url_worker: Arc<str> = Arc::from(url.clone());
        let token_worker = token.map(Arc::<str>::from);

        tokio::spawn(run_bounded_workers(receiver, max_in_flight, move |event| {
            let client = client.clone();
            let metrics = metrics_worker.clone();
            let url = Arc::clone(&url_worker);
            let token = token_worker.clone();
            async move {
                match serde_json::to_vec(&event) {
                    Ok(payload) => {
                        let mut req = client
                            .post(url.as_ref())
                            .header("Content-Type", "application/json")
                            .body(payload);
                        if let Some(token) = token.as_deref() {
                            req = req.bearer_auth(token);
                        }
                        match req.send().await {
                            Ok(resp)
                                if resp.status().is_success() || resp.status().as_u16() == 202 =>
                            {
                                metrics.kafka_events_sent.inc();
                            }
                            Ok(resp) => {
                                warn!("EVENT_SINK_URL HTTP {}", resp.status());
                                metrics.kafka_send_errors.inc();
                            }
                            Err(e) => {
                                warn!("EVENT_SINK_URL send failed: {e}");
                                metrics.kafka_send_errors.inc();
                            }
                        }
                    }
                    Err(e) => {
                        error!("Event serialization failed: {}", e);
                        metrics.kafka_send_errors.inc();
                    }
                }
            }
        }));

        info!(
            "HTTP event sink started (url={url}, queue capacity={capacity}, max in-flight={max_in_flight}, drop=policy:drop_new)"
        );
        Some(Arc::new(Self { sender }))
    }

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn bounded_workers_cap_concurrency_and_drain() {
        let (sender, receiver) = mpsc::channel(32);
        for value in 0..12 {
            sender.send(value).await.expect("queue test value");
        }
        drop(sender);

        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));

        let active_worker = Arc::clone(&active);
        let peak_worker = Arc::clone(&peak);
        let completed_worker = Arc::clone(&completed);
        run_bounded_workers(receiver, 3, move |_| {
            let active = Arc::clone(&active_worker);
            let peak = Arc::clone(&peak_worker);
            let completed = Arc::clone(&completed_worker);
            async move {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
                active.fetch_sub(1, Ordering::SeqCst);
                completed.fetch_add(1, Ordering::SeqCst);
            }
        })
        .await;

        assert_eq!(peak.load(Ordering::SeqCst), 3);
        assert_eq!(completed.load(Ordering::SeqCst), 12);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}
