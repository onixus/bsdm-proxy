//! Shared Kafka consumer setup for cache-indexer backends.

use rdkafka::{
    config::ClientConfig,
    consumer::{Consumer, StreamConsumer},
};
use tracing::info;

pub fn create_consumer(
    kafka_brokers: &str,
    kafka_topic: &str,
    kafka_group: &str,
) -> Result<StreamConsumer, Box<dyn std::error::Error>> {
    let consumer: StreamConsumer = ClientConfig::new()
        .set("group.id", kafka_group)
        .set("bootstrap.servers", kafka_brokers)
        .set("enable.auto.commit", "false")
        .set("auto.offset.reset", "earliest")
        .set("session.timeout.ms", "30000")
        .create()?;

    consumer.subscribe(&[kafka_topic])?;
    info!("Subscribed to Kafka topic: {}", kafka_topic);
    Ok(consumer)
}
