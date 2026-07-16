//! Optional SIEM webhook (compatible payload shape with alert-worker).

use crate::config::Config;
use crate::scoring::ScoreResult;
use reqwest::Client;
use uuid::Uuid;

pub struct WebhookClient {
    client: Client,
    url: String,
    source: String,
}

impl WebhookClient {
    pub fn new(config: &Config) -> Option<Result<Self, Box<dyn std::error::Error>>> {
        let url = config.webhook_url.as_ref()?;
        let client = match Client::builder().timeout(config.webhook_timeout).build() {
            Ok(c) => c,
            Err(e) => return Some(Err(e.into())),
        };
        Some(Ok(Self {
            client,
            url: url.clone(),
            source: config.source.clone(),
        }))
    }

    pub async fn post_score(
        &self,
        score: &ScoreResult,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let body = serde_json::json!({
            "alert_id": Uuid::new_v4().to_string(),
            "rule": "ml_anomaly",
            "model": score.model,
            "severity": score.severity,
            "score": score.score,
            "entity_type": score.entity_type,
            "entity_id": score.entity_id,
            "window_start": score.window_start.to_rfc3339(),
            "scored_at": score.scored_at.to_rfc3339(),
            "source": self.source,
            "features": serde_json::from_str::<serde_json::Value>(&score.features_json)
                .unwrap_or(serde_json::json!({})),
        });
        let response = self.client.post(&self.url).json(&body).send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(format!("webhook HTTP {status}: {text}").into());
        }
        Ok(())
    }
}
