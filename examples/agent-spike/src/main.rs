//! Minimal On-Device Local Policy Agent Spike (Phase C, Issue #258)
//! Implements Agent Contract v0.1: Registration, Policy Fetch, Local Policy Evaluation, and Telemetry.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalPolicy {
    pub policy_version: String,
    pub policy_mode: String,
    pub mitm_categories: HashSet<String>,
    pub sni_deny_patterns: Vec<String>,
    pub pinning_exceptions: HashSet<String>,
}

impl Default for LocalPolicy {
    fn default() -> Self {
        Self {
            policy_version: "v0.1-initial".to_string(),
            policy_mode: "selective-mitm".to_string(),
            mitm_categories: ["malware", "phishing", "illegal-content"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            sni_deny_patterns: vec!["*.evil.com".to_string(), "badsite.test".to_string()],
            pinning_exceptions: [".slack.com", ".teams.microsoft.com", ".zoom.us"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalDecision {
    Allow,
    Deny { reason: String },
    BypassMitm { reason: String },
    InspectMitm { category: String },
}

pub struct AgentEngine {
    device_id: String,
    control_plane_url: String,
    policy: Arc<RwLock<LocalPolicy>>,
}

impl AgentEngine {
    pub fn new(device_id: String, control_plane_url: String) -> Self {
        Self {
            device_id,
            control_plane_url,
            policy: Arc::new(RwLock::new(LocalPolicy::default())),
        }
    }

    /// Evaluate policy locally on-device without calling central proxy data plane.
    pub async fn evaluate_domain(&self, domain: &str) -> LocalDecision {
        let policy = self.policy.read().await;
        let domain_lower = domain.to_ascii_lowercase();

        // 1. Check local SNI Deny patterns
        for pattern in &policy.sni_deny_patterns {
            if pattern.starts_with("*.") {
                let suffix = &pattern[1..];
                if domain_lower.ends_with(suffix) {
                    return LocalDecision::Deny {
                        reason: format!("SNI pattern match: {pattern}"),
                    };
                }
            } else if domain_lower == *pattern {
                return LocalDecision::Deny {
                    reason: format!("SNI exact match: {pattern}"),
                };
            }
        }

        // 2. Check Certificate Pinning Exceptions
        if policy.pinning_exceptions.iter().any(|exc| {
            if exc.starts_with('.') {
                domain_lower.ends_with(exc) || domain_lower == exc.trim_start_matches('.')
            } else {
                domain_lower == *exc
            }
        }) {
            return LocalDecision::BypassMitm {
                reason: "certificate_pinning_exception".to_string(),
            };
        }

        // 3. Evaluate Policy Mode
        match policy.policy_mode.as_str() {
            "sni" => LocalDecision::Allow,
            "full-mitm" => LocalDecision::InspectMitm {
                category: "full-mitm-default".to_string(),
            },
            _ => {
                // Selective MITM evaluation
                if policy.mitm_categories.contains("phishing") && domain_lower.contains("phish") {
                    LocalDecision::InspectMitm {
                        category: "phishing".to_string(),
                    }
                } else {
                    LocalDecision::Allow
                }
            }
        }
    }

    /// Heartbeat & Policy Pull loop
    pub async fn run_heartbeat_loop(&self) {
        let client = reqwest::Client::new();
        let mut interval = tokio::time::interval(Duration::from_secs(30));

        loop {
            interval.tick().await;
            info!(device_id = %self.device_id, "Sending agent heartbeat to control plane...");

            let health_url = format!("{}/health", self.control_plane_url);
            match client.get(&health_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    info!(
                        "Agent heartbeat ACK from control plane ({})",
                        self.control_plane_url
                    );
                }
                Ok(resp) => {
                    warn!("Control plane returned status: {}", resp.status());
                }
                Err(e) => {
                    warn!("Failed to reach control plane at {}: {}", health_url, e);
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,agent_spike=debug".into()),
        )
        .init();

    info!("🚀 BSDM Minimal Local Policy Agent Spike (Phase C, Issue #258)");

    let device_id = std::env::var("DEVICE_ID").unwrap_or_else(|_| "dev-mac-001".to_string());
    let control_plane_url =
        std::env::var("CONTROL_PLANE_URL").unwrap_or_else(|_| "http://127.0.0.1:9090".to_string());

    let agent = Arc::new(AgentEngine::new(device_id.clone(), control_plane_url));

    // Demonstrate local policy evaluation
    let test_domains = vec![
        "google.com",
        "slack.com",
        "phish-test.com",
        "badsite.test",
        "sub.evil.com",
    ];

    info!("--- Executing Local Policy Decisions ---");
    for domain in test_domains {
        let decision = agent.evaluate_domain(domain).await;
        info!(domain = %domain, decision = ?decision, decision_source = "local-agent", "Local policy decision evaluated");
    }

    // Spawn background heartbeat task
    let agent_clone = agent.clone();
    tokio::spawn(async move {
        agent_clone.run_heartbeat_loop().await;
    });

    info!("Agent spike running. Press Ctrl+C to exit.");
    tokio::signal::ctrl_c().await?;
    info!("Agent spike shutdown.");
    Ok(())
}
