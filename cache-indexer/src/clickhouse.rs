//! ClickHouse backend for cache-indexer (`INDEXER_BACKEND=clickhouse`).

use bsdm_events::json_each_row_lines;
use bsdm_events::CacheEvent;
use rdkafka::consumer::{CommitMode, Consumer, StreamConsumer};
use rdkafka::message::Message;
use reqwest::Client;
use tracing::{error, info, warn};

use crate::kafka::create_consumer;

pub struct ClickHouseConfig {
    pub url: String,
    pub database: String,
    pub table: String,
    pub user: Option<String>,
    pub password: Option<String>,
}

pub struct ClickHouseIndexer {
    client: Client,
    consumer: StreamConsumer,
    config: ClickHouseConfig,
}

impl ClickHouseIndexer {
    pub async fn new(
        kafka_brokers: &str,
        kafka_topic: &str,
        kafka_group: &str,
        config: ClickHouseConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let consumer = create_consumer(kafka_brokers, kafka_topic, kafka_group)?;
        let client = Client::builder().build()?;
        let indexer = Self {
            client,
            consumer,
            config,
        };
        indexer.ensure_ready().await?;
        Ok(indexer)
    }

    async fn ensure_ready(&self) -> Result<(), Box<dyn std::error::Error>> {
        let ping_url = format!("{}/ping", self.config.url.trim_end_matches('/'));
        let mut req = self.client.get(&ping_url);
        if let (Some(user), Some(password)) = (&self.config.user, &self.config.password) {
            req = req.basic_auth(user, Some(password));
        }
        let response = req.send().await?;
        if !response.status().is_success() {
            return Err(format!("ClickHouse ping failed: HTTP {}", response.status()).into());
        }

        let query = format!(
            "SELECT 1 FROM system.tables WHERE database = '{}' AND name = '{}'",
            self.config.database, self.config.table
        );
        let body = self.query(&query).await?;
        if body.trim() != "1" {
            return Err(format!(
                "ClickHouse table {}.{} not found (run scripts/clickhouse/http_cache.sql)",
                self.config.database, self.config.table
            )
            .into());
        }

        info!(
            "ClickHouse ready: {}.{}, url={}",
            self.config.database, self.config.table, self.config.url
        );
        Ok(())
    }

    async fn query(&self, sql: &str) -> Result<String, Box<dyn std::error::Error>> {
        let base = self.config.url.trim_end_matches('/');
        let mut req = self.client.post(base).query(&[("query", sql)]).body("");
        if let (Some(user), Some(password)) = (&self.config.user, &self.config.password) {
            req = req.basic_auth(user, Some(password));
        }
        let response = req.send().await?;
        let status = response.status();
        let body = response.text().await?;
        if status.is_success() {
            Ok(body)
        } else {
            Err(format!("ClickHouse query failed (HTTP {status}): {body}").into())
        }
    }

    async fn insert_batch(&self, events: &[CacheEvent]) -> Result<(), Box<dyn std::error::Error>> {
        if events.is_empty() {
            return Ok(());
        }

        let body = json_each_row_lines(events)?;
        let sql = format!(
            "INSERT INTO {}.{} FORMAT JSONEachRow",
            self.config.database, self.config.table
        );
        let base = self.config.url.trim_end_matches('/');
        let mut req = self
            .client
            .post(base)
            .query(&[("query", &sql)])
            .header("Content-Type", "application/json")
            .body(body);
        if let (Some(user), Some(password)) = (&self.config.user, &self.config.password) {
            req = req.basic_auth(user, Some(password));
        }

        let response = req.send().await?;
        let status = response.status();
        if status.is_success() {
            info!("Inserted {} events into ClickHouse", events.len());
            Ok(())
        } else {
            let err_body = response.text().await.unwrap_or_default();
            error!("ClickHouse insert failed (HTTP {}): {}", status, err_body);
            Err(format!("ClickHouse insert failed: {err_body}").into())
        }
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
                                    self.insert_batch(&batch).await?;
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
                        self.insert_batch(&batch).await?;
                        batch.clear();
                        self.consumer.commit_consumer_state(CommitMode::Async)?;
                        last_commit = tokio::time::Instant::now();
                    }
                }
            }

            if last_commit.elapsed() > std::time::Duration::from_secs(30) && !batch.is_empty() {
                self.insert_batch(&batch).await?;
                batch.clear();
                self.consumer.commit_consumer_state(CommitMode::Async)?;
                last_commit = tokio::time::Instant::now();
            }
        }
    }
}

pub fn load_config_from_env() -> ClickHouseConfig {
    ClickHouseConfig {
        url: std::env::var("CLICKHOUSE_URL")
            .unwrap_or_else(|_| "http://clickhouse:8123".to_string()),
        database: std::env::var("CLICKHOUSE_DATABASE").unwrap_or_else(|_| "bsdm".to_string()),
        table: std::env::var("CLICKHOUSE_TABLE").unwrap_or_else(|_| "http_cache".to_string()),
        user: std::env::var("CLICKHOUSE_USER").ok(),
        password: std::env::var("CLICKHOUSE_PASSWORD").ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_config_defaults() {
        let cfg = ClickHouseConfig {
            url: "http://localhost:8123".to_string(),
            database: "bsdm".to_string(),
            table: "http_cache".to_string(),
            user: None,
            password: None,
        };
        assert_eq!(cfg.database, "bsdm");
        assert_eq!(cfg.table, "http_cache");
    }
}
