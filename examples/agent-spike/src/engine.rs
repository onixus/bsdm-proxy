//! Control-plane client: policy pull, heartbeat, events, sync loop.

use crate::policy::{evaluate_domain, LocalDecision, LocalPolicy, RemotePolicyDto};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn};

fn decision_action(decision: &LocalDecision) -> (&'static str, Option<String>) {
    match decision {
        LocalDecision::Allow => ("allow", None),
        LocalDecision::Deny { reason } => ("deny", Some(reason.clone())),
        LocalDecision::BypassMitm { reason } => ("bypass", Some(reason.clone())),
        LocalDecision::InspectMitm { category } => ("inspect", Some(category.clone())),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub struct AgentEngine {
    device_id: String,
    device_name: String,
    device_type: String,
    device_ip: Option<String>,
    platform: String,
    control_plane_url: String,
    /// Token used for agent API calls (device_token after enroll, or control token).
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
        platform: String,
        control_plane_url: String,
        control_api_token: Option<String>,
        heartbeat_interval: Duration,
    ) -> Self {
        Self {
            device_id,
            device_name,
            device_type,
            device_ip,
            platform,
            control_plane_url,
            control_api_token,
            heartbeat_interval,
            policy: Arc::new(RwLock::new(LocalPolicy::default())),
        }
    }

    pub fn set_api_token(&mut self, token: Option<String>) {
        self.control_api_token = token;
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

    /// Bootstrap enroll → device Bearer token; optional mTLS CSR → client cert PEMs.
    ///
    /// Returns `(device_id, device_token, optional client_cert_pem, optional ca_cert_pem)`.
    pub async fn enroll(
        &self,
        client: &reqwest::Client,
        enroll_token: Option<&str>,
        with_mtls: bool,
    ) -> Result<(String, String, Option<String>, Option<String>), String> {
        let enroll_url = format!(
            "{}/api/v1/agent/enroll",
            self.control_plane_url.trim_end_matches('/')
        );

        let mut body = serde_json::json!({
            "device_id": self.device_id,
            "name": self.device_name,
            "platform": self.platform,
            "device_type": self.device_type,
            "capabilities": ["local-proxy"],
        });

        // Key material kept only for CSR generation; private key is printed for lab storage.
        let mut private_key_pem: Option<String> = None;
        if with_mtls {
            let key = rcgen::KeyPair::generate().map_err(|e| format!("agent keygen: {e}"))?;
            private_key_pem = Some(key.serialize_pem());
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
                .map_err(|e| format!("csr params: {e}"))?;
            params.distinguished_name = rcgen::DistinguishedName::new();
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, &self.device_id);
            let csr = params
                .serialize_request(&key)
                .map_err(|e| format!("csr serialize: {e}"))?;
            let csr_pem = csr.pem().map_err(|e| format!("csr pem: {e}"))?;
            body["csr_pem"] = serde_json::Value::String(csr_pem);
            body["cert_validity_days"] = serde_json::json!(90);
        }

        let mut request = client.post(&enroll_url).json(&body);
        if let Some(token) = enroll_token.filter(|t| !t.is_empty()) {
            request = request.bearer_auth(token);
        } else if let Some(token) = &self.control_api_token {
            request = request.bearer_auth(token);
        }
        let resp = request
            .send()
            .await
            .map_err(|e| format!("enroll transport: {e}"))?;
        let status = resp.status();
        let text = resp.text().await.map_err(|e| format!("enroll body: {e}"))?;
        if !status.is_success() {
            return Err(format!("enroll HTTP {status}: {text}"));
        }
        let v: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("enroll decode: {e}"))?;
        let device_id = v["device_id"]
            .as_str()
            .unwrap_or(&self.device_id)
            .to_string();
        let device_token = v["device_token"]
            .as_str()
            .ok_or_else(|| "enroll response missing device_token".to_string())?
            .to_string();
        let client_cert = v["client_cert_pem"].as_str().map(str::to_string);
        let ca_cert = v["ca_cert_pem"].as_str().map(str::to_string);
        let mtls = v["mtls"].as_bool().unwrap_or(false);
        info!(%device_id, mtls, "Agent enrolled (device_token issued)");
        if let Some(key_pem) = private_key_pem {
            if client_cert.is_some() {
                println!("DEVICE_KEY_PEM_BEGIN");
                print!("{key_pem}");
                println!("DEVICE_KEY_PEM_END");
            }
        }
        if let Some(cert) = &client_cert {
            println!("DEVICE_CERT_PEM_BEGIN");
            print!("{cert}");
            println!("DEVICE_CERT_PEM_END");
        }
        if let Some(ca) = &ca_cert {
            println!("CA_CERT_PEM_BEGIN");
            print!("{ca}");
            println!("CA_CERT_PEM_END");
        }
        Ok((device_id, device_token, client_cert, ca_cert))
    }

    /// POST local decisions to `POST /api/v1/agent/events`.
    pub async fn send_events(
        &self,
        client: &reqwest::Client,
        events: Vec<serde_json::Value>,
    ) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        let events_url = format!(
            "{}/api/v1/agent/events",
            self.control_plane_url.trim_end_matches('/')
        );
        let body = serde_json::json!({
            "device_id": self.device_id,
            "events": events,
        });
        let request = self.apply_auth(client.post(&events_url).json(&body));
        let resp = request
            .send()
            .await
            .map_err(|e| format!("events transport: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("events HTTP {status}: {text}"));
        }
        info!(
            device_id = %self.device_id,
            count = body["events"].as_array().map(|a| a.len()).unwrap_or(0),
            "Agent events batch accepted"
        );
        Ok(())
    }

    /// One-shot: pull → evaluate + events → heartbeat (pilot smoke).
    pub async fn run_once(&self) -> Result<(), String> {
        let client = reqwest::Client::new();
        self.pull_policy(&client).await?;
        let events = demo_evaluate(self).await;
        self.send_events(&client, events).await?;
        self.send_heartbeat(&client).await?;
        Ok(())
    }
}

/// Evaluate sample domains; returns JSON event items for control-plane ingest.
pub async fn demo_evaluate(agent: &AgentEngine) -> Vec<serde_json::Value> {
    let test_domains = [
        "google.com",
        "slack.com",
        "phish-test.com",
        "badsite.test",
        "sub.evil.com",
    ];
    let policy_version = agent.policy_version().await;
    let mut events = Vec::with_capacity(test_domains.len());
    info!("--- Executing Local Policy Decisions ---");
    for domain in test_domains {
        let decision = agent.evaluate_domain(domain).await;
        let (action, reason) = decision_action(&decision);
        info!(
            domain = %domain,
            decision = ?decision,
            decision_source = "local-agent",
            "Local policy decision evaluated"
        );
        events.push(serde_json::json!({
            "domain": domain,
            "action": action,
            "decision_source": "local-agent",
            "timestamp": unix_now(),
            "reason": reason,
            "policy_version": policy_version,
        }));
    }
    events
}
