//! Minimal On-Device Local Policy Agent Spike (Phase C, Issue #258 / #273)
//! Implements Agent Contract v0.1: Policy Fetch, Local Policy Evaluation, Heartbeat.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
            policy_version: "v0.1-offline".to_string(),
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

/// Control-plane `GET /api/v1/agent/policy` payload (Agent Contract v0.1 + spike fields).
#[derive(Debug, Clone, Deserialize)]
pub struct RemotePolicyDto {
    pub policy_version: String,
    pub policy_mode: String,
    #[serde(default)]
    pub mitm_categories: Vec<String>,
    #[serde(default)]
    pub pinning_exceptions: Vec<String>,
    #[serde(default)]
    pub sni_deny_patterns: Vec<String>,
    #[serde(default)]
    pub sni_rules: Vec<SniRuleDto>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SniRuleDto {
    pub pattern: String,
    #[serde(default)]
    pub action: String,
}

impl LocalPolicy {
    /// Map control-plane JSON onto the on-device engine.
    pub fn from_remote(dto: RemotePolicyDto) -> Self {
        let mut sni_deny = dto.sni_deny_patterns;
        if sni_deny.is_empty() {
            for rule in &dto.sni_rules {
                let action = rule.action.to_ascii_lowercase();
                if action.is_empty() || action == "deny" {
                    sni_deny.push(rule.pattern.clone());
                }
            }
        }
        if sni_deny.is_empty() {
            sni_deny = LocalPolicy::default().sni_deny_patterns;
        }
        Self {
            policy_version: dto.policy_version,
            policy_mode: dto.policy_mode,
            mitm_categories: dto.mitm_categories.into_iter().collect(),
            sni_deny_patterns: sni_deny,
            pinning_exceptions: dto.pinning_exceptions.into_iter().collect(),
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
        evaluate_domain_with_policy(&policy, domain)
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

    /// Heartbeat & Policy Pull loop
    pub async fn run_heartbeat_loop(&self) {
        let client = reqwest::Client::new();
        let mut interval = tokio::time::interval(self.heartbeat_interval);
        // First tick completes immediately — still pull once before waiting.
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

    /// One-shot: pull → evaluate sample domains → heartbeat (for pilot smoke).
    pub async fn run_once(&self) -> Result<(), String> {
        let client = reqwest::Client::new();
        self.pull_policy(&client).await?;
        demo_evaluate(self).await;
        self.send_heartbeat(&client).await?;
        Ok(())
    }
}

fn evaluate_domain_with_policy(policy: &LocalPolicy, domain: &str) -> LocalDecision {
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
            // Selective MITM evaluation (heuristic spike — not full categorization)
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

async fn demo_evaluate(agent: &AgentEngine) {
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

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,agent_spike=debug".into()),
        )
        .init();

    info!("🚀 BSDM Minimal Local Policy Agent Spike (Phase C, Issue #258/#273)");

    let device_id = std::env::var("DEVICE_ID").unwrap_or_else(|_| "dev-mac-001".to_string());
    let device_name =
        std::env::var("DEVICE_NAME").unwrap_or_else(|_| format!("agent-{device_id}"));
    let device_type = std::env::var("DEVICE_TYPE").unwrap_or_else(|_| "desktop".to_string());
    let device_ip = std::env::var("DEVICE_IP").ok().filter(|s| !s.is_empty());
    let control_plane_url =
        std::env::var("CONTROL_PLANE_URL").unwrap_or_else(|_| "http://127.0.0.1:9090".to_string());
    let control_api_token = std::env::var("CONTROL_API_TOKEN")
        .ok()
        .filter(|token| !token.is_empty());
    let heartbeat_secs: u64 = std::env::var("HEARTBEAT_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30)
        .max(5);
    let once = env_flag("AGENT_ONCE") || std::env::args().any(|a| a == "--once");

    let agent = Arc::new(AgentEngine::new(
        device_id.clone(),
        device_name,
        device_type,
        device_ip,
        control_plane_url.clone(),
        control_api_token,
        Duration::from_secs(heartbeat_secs),
    ));

    if once {
        info!(%control_plane_url, "Agent once-mode: pull + evaluate + heartbeat");
        agent.run_once().await?;
        info!("Agent once-mode complete.");
        return Ok(());
    }

    // Best-effort initial pull (offline defaults if control plane is down)
    let client = reqwest::Client::new();
    if let Err(e) = agent.pull_policy(&client).await {
        warn!("Initial policy pull failed — using offline defaults: {e}");
    }
    demo_evaluate(&agent).await;

    let agent_clone = agent.clone();
    tokio::spawn(async move {
        agent_clone.run_heartbeat_loop().await;
    });

    info!("Agent spike running. Press Ctrl+C to exit.");
    tokio::signal::ctrl_c().await?;
    info!("Agent spike shutdown.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluates_sni_deny_wildcard_and_exact() {
        let policy = LocalPolicy::default();
        assert!(matches!(
            evaluate_domain_with_policy(&policy, "sub.evil.com"),
            LocalDecision::Deny { .. }
        ));
        assert!(matches!(
            evaluate_domain_with_policy(&policy, "badsite.test"),
            LocalDecision::Deny { .. }
        ));
        assert_eq!(
            evaluate_domain_with_policy(&policy, "google.com"),
            LocalDecision::Allow
        );
    }

    #[test]
    fn evaluates_pinning_exception_suffix() {
        let policy = LocalPolicy::default();
        assert_eq!(
            evaluate_domain_with_policy(&policy, "hooks.slack.com"),
            LocalDecision::BypassMitm {
                reason: "certificate_pinning_exception".to_string()
            }
        );
        assert_eq!(
            evaluate_domain_with_policy(&policy, "slack.com"),
            LocalDecision::BypassMitm {
                reason: "certificate_pinning_exception".to_string()
            }
        );
    }

    #[test]
    fn evaluates_selective_mitm_phishing_heuristic() {
        let policy = LocalPolicy::default();
        assert_eq!(
            evaluate_domain_with_policy(&policy, "login-phish.example"),
            LocalDecision::InspectMitm {
                category: "phishing".to_string()
            }
        );
    }

    #[test]
    fn maps_remote_policy_with_sni_rules() {
        let dto = RemotePolicyDto {
            policy_version: "v0.1.0".into(),
            policy_mode: "sni".into(),
            mitm_categories: vec!["malware".into()],
            pinning_exceptions: vec![".zoom.us".into()],
            sni_deny_patterns: vec![],
            sni_rules: vec![SniRuleDto {
                pattern: "*.bad.example".into(),
                action: "deny".into(),
            }],
        };
        let policy = LocalPolicy::from_remote(dto);
        assert_eq!(policy.policy_version, "v0.1.0");
        assert_eq!(policy.policy_mode, "sni");
        assert!(policy.sni_deny_patterns.contains(&"*.bad.example".into()));
        assert!(policy.pinning_exceptions.contains(".zoom.us"));
        assert_eq!(
            evaluate_domain_with_policy(&policy, "x.bad.example"),
            LocalDecision::Deny {
                reason: "SNI pattern match: *.bad.example".into()
            }
        );
        // sni mode → allow (no MITM inspect)
        assert_eq!(
            evaluate_domain_with_policy(&policy, "phish-test.com"),
            LocalDecision::Allow
        );
    }

    #[test]
    fn prefers_flat_sni_deny_patterns_over_rules() {
        let dto = RemotePolicyDto {
            policy_version: "v9".into(),
            policy_mode: "selective-mitm".into(),
            mitm_categories: vec![],
            pinning_exceptions: vec![],
            sni_deny_patterns: vec!["only.flat".into()],
            sni_rules: vec![SniRuleDto {
                pattern: "from.rules".into(),
                action: "deny".into(),
            }],
        };
        let policy = LocalPolicy::from_remote(dto);
        assert_eq!(policy.sni_deny_patterns, vec!["only.flat".to_string()]);
    }
}
