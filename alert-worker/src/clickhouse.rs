//! Minimal ClickHouse HTTP query client.

use crate::config::Config;
use reqwest::Client;
use tracing::info;

pub struct ClickHouseClient {
    client: Client,
    url: String,
    user: Option<String>,
    password: Option<String>,
}

impl ClickHouseClient {
    pub fn new(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client,
            url: config.clickhouse_url.trim_end_matches('/').to_string(),
            user: config.clickhouse_user.clone(),
            password: config.clickhouse_password.clone(),
        })
    }

    pub async fn ping(&self) -> Result<(), Box<dyn std::error::Error>> {
        let ping_url = format!("{}/ping", self.url);
        let mut req = self.client.get(&ping_url);
        if let (Some(user), Some(password)) = (&self.user, &self.password) {
            req = req.basic_auth(user, Some(password));
        }
        let response = req.send().await?;
        if !response.status().is_success() {
            return Err(format!("ClickHouse ping failed: HTTP {}", response.status()).into());
        }
        info!("ClickHouse reachable at {}", self.url);
        Ok(())
    }

    pub async fn query_json_each_row(
        &self,
        sql: &str,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let mut req = self
            .client
            .post(&self.url)
            .query(&[("query", sql)])
            .body("");
        if let (Some(user), Some(password)) = (&self.user, &self.password) {
            req = req.basic_auth(user, Some(password));
        }
        let response = req.send().await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(format!("ClickHouse query failed (HTTP {status}): {body}").into());
        }
        parse_json_each_row(&body)
    }
}

pub fn parse_json_each_row(
    body: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut rows = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        rows.push(serde_json::from_str(line)?);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_each_row() {
        let body = r#"{"client_ip":"10.0.0.1","value":12}
{"client_ip":"10.0.0.2","value":3}
"#;
        let rows = parse_json_each_row(body).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["value"], 12);
    }
}
