//! Control-plane client: policy pull, heartbeat, sync loop.

use crate::policy::{evaluate_domain, LocalDecision, LocalPolicy, RemotePolicyDto};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn};

pub struct AgentEngine {
    device_id: String,
    device_name: String,
    device_type: String,
    device_ip: Option<String>,
    control_plane_url: String,
    control_api_token: Option<String>,
    heartbeat_interval: Duration,
    policy: Arc<RwLock<LocalPolicy>>,
}

impl AgentEngine {
    pub fn new(
        device_id: String,
        device_name: String,
        device_type: String,
        device_ip: Option<String>,
        control_plane_url: String,
        control_api_token: Option<String>,
        heartbeat_interval: Duration,
    ) -> Self {
        Self {
            device_id,
            device_name,
            device_type,
            device_ip,
            control_plane_url,
            control_api_token,
            heartbeat_interval,
            policy: Arc::new(RwLock::new(LocalPolicy::default())),
        }
    }

    pub async fn policy_version(&self) -> String {
        self.policy.read().await.policy_version.clone()
    }

    /// Evaluate policy locally on-device without calling central proxy data plane.
    pub async fn evaluate_domain(&self, domain: &str) -> LocalDecision {
        let policy = self.policy.read().await;
        evaluate_domain(&policy, domain)
    }

    fn apply_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = &self.control_api_token {
            request.bearer_auth(token)
        } else {
            request
        }
    }

    /// Pull policy from control plane (`GET /api/v1/agent/policy`).
    /// On failure keeps the previous (or offline default) policy.
    pub async fn pull_policy(&self, client: &reqwest::Client) -> Result<(), String> {
        let policy_url = format!(
            "{}/api/v1/agent/policy",
            self.control_plane_url.trim_end_matches('/')
        );
        let request = self.apply_auth(client.get(&policy_url));
        let resp = request
            .send()
            .await
            .map_err(|e| format!("policy pull transport: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("policy pull HTTP {status}"));
        }
        let dto: RemotePolicyDto = resp
            .json()
            .await
            .map_err(|e| format!("policy pull decode: {e}"))?;
        let mapped = LocalPolicy::from_remote(dto);
        info!(
            policy_version = %mapped.policy_version,
            policy_mode = %mapped.policy_mode,
            sni_deny = mapped.sni_deny_patterns.len(),
            pinning = mapped.pinning_exceptions.len(),
            "Pulled agent policy from control plane"
        );
        *self.policy.write().await = mapped;
        Ok(())
    }

    /// Single heartbeat to `POST /api/v1/agent/heartbeat`.
    pub async fn send_heartbeat(&self, client: &reqwest::Client) -> Result<(), String> {
        let policy_version = self.policy_version().await;
        let heartbeat_url = format!(
            "{}/api/v1/agent/heartbeat",
            self.control_plane_url.trim_end_matches('/')
        );
        let body = serde_json::json!({
            "device_id": self.device_id,
            "name": self.device_name,
            "device_type": self.device_type,
            "ip": self.device_ip,
            "status": "healthy",
            "agent_version": env!("CARGO_PKG_VERSION"),
            "policy_version": policy_version,
            "trust_score": 90_u8,
        });
        let request = self.apply_auth(client.post(&heartbeat_url).json(&body));
        let resp = request
            .send()
            .await
            .map_err(|e| format!("heartbeat transport: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("heartbeat HTTP {status}"));
        }
        info!(
            device_id = %self.device_id,
            "Agent heartbeat ACK from control plane ({})",
            self.control_plane_url
        );
        Ok(())
    }

    /// Heartbeat & policy pull loop.
    pub async fn run_heartbeat_loop(&self) {
        let client = reqwest::Client::new();
        let mut interval = tokio::time::interval(self.heartbeat_interval);
        loop {
            interval.tick().await;
            info!(device_id = %self.device_id, "Agent control-plane sync...");
            if let Err(e) = self.pull_policy(&client).await {
                warn!("Policy pull failed (keeping previous policy): {e}");
            }
            if let Err(e) = self.send_heartbeat(&client).await {
                warn!("Heartbeat failed: {e}");
            }
        }
    }

    /// One-shot: pull → evaluate sample domains → heartbeat (pilot smoke).
    pub async fn run_once(&self) -> Result<(), String> {
        let client = reqwest::Client::new();
        self.pull_policy(&client).await?;
        demo_evaluate(self).await;
        self.send_heartbeat(&client).await?;
        Ok(())
    }
}

pub async fn demo_evaluate(agent: &AgentEngine) {
    let test_domains = [
        "google.com",
        "slack.com",
        "phish-test.com",
        "badsite.test",
        "sub.evil.com",
    ];
    info!("--- Executing Local Policy Decisions ---");
    for domain in test_domains {
        let decision = agent.evaluate_domain(domain).await;
        info!(
            domain = %domain,
            decision = ?decision,
            decision_source = "local-agent",
            "Local policy decision evaluated"
        );
    }
}
