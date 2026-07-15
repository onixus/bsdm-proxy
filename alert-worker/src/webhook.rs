//! HTTP POST webhook delivery.

use crate::config::Config;
use crate::payload::AlertPayload;
use reqwest::Client;
use tracing::{info, warn};

pub struct WebhookClient {
    client: Client,
    url: String,
    headers: Vec<(String, String)>,
}

impl WebhookClient {
    pub fn new(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::builder().timeout(config.webhook_timeout).build()?;
        let headers = config
            .webhook_headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Ok(Self {
            client,
            url: config.webhook_url.clone(),
            headers,
        })
    }

    pub async fn send(&self, payload: &AlertPayload) -> Result<(), Box<dyn std::error::Error>> {
        let mut req = self.client.post(&self.url).json(payload);
        for (k, v) in &self.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let response = req.send().await?;
        let status = response.status();
        if status.is_success() {
            info!(
                rule = %payload.rule,
                fingerprint = %payload.fingerprint,
                "webhook delivered"
            );
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            warn!(%status, %body, "webhook rejected");
            Err(format!("webhook HTTP {status}: {body}").into())
        }
    }
}
