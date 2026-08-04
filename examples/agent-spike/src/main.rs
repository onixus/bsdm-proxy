//! Minimal On-Device Local Policy Agent Spike (Phase C, Issue #258 / #273)
//! Implements Agent Contract v0.1: Policy Fetch, Local Policy Evaluation, Heartbeat.

mod engine;
mod policy;

use engine::{demo_evaluate, AgentEngine};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

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
    let device_name = std::env::var("DEVICE_NAME").unwrap_or_else(|_| format!("agent-{device_id}"));
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
