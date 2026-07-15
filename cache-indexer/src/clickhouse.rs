//! ClickHouse backend for cache-indexer.

use bsdm_events::json_each_row_lines;
use bsdm_events::CacheEvent;
use reqwest::Client;
use tracing::{error, info};

pub struct ClickHouseConfig {
    pub url: String,
    pub database: String,
    pub table: String,
    pub user: Option<String>,
    pub password: Option<String>,
}

pub struct ClickHouseWriter {
    client: Client,
    config: ClickHouseConfig,
}

impl ClickHouseWriter {
    pub fn database(&self) -> &str {
        &self.config.database
    }

    pub fn table(&self) -> &str {
        &self.config.table
    }

    pub async fn bootstrap(config: ClickHouseConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::builder().build()?;
        let writer = Self { client, config };
        writer.ensure_ready().await?;
        Ok(writer)
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

    pub async fn query_with_params(
        &self,
        sql: &str,
        params: &[(&str, String)],
    ) -> Result<String, Box<dyn std::error::Error>> {
        let base = self.config.url.trim_end_matches('/');
        let mut req = self.client.post(base).query(&[("query", sql)]).body("");
        for (name, value) in params {
            req = req.query(&[(format!("param_{name}"), value.as_str())]);
        }
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

    async fn query(&self, sql: &str) -> Result<String, Box<dyn std::error::Error>> {
        self.query_with_params(sql, &[]).await
    }

    pub async fn insert_batch(
        &self,
        events: &[CacheEvent],
    ) -> Result<(), Box<dyn std::error::Error>> {
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
