//! Minimal On-Device Local Policy Agent Spike (Phase C, Issue #258 / #273)
//! Implements Agent Contract v0.1: Enroll, Policy Fetch, Local Evaluate, Events, Heartbeat.

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
    let platform = std::env::var("DEVICE_PLATFORM").unwrap_or_else(|_| {
        if cfg!(target_os = "macos") {
            "macos".into()
        } else if cfg!(target_os = "windows") {
            "windows".into()
        } else {
            "linux".into()
        }
    });
    let control_plane_url =
        std::env::var("CONTROL_PLANE_URL").unwrap_or_else(|_| "http://127.0.0.1:9090".to_string());
    let control_api_token = std::env::var("CONTROL_API_TOKEN")
        .ok()
        .filter(|token| !token.is_empty());
    let enroll_token = std::env::var("AGENT_ENROLL_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .or_else(|| control_api_token.clone());
    let device_token = std::env::var("DEVICE_TOKEN").ok().filter(|t| !t.is_empty());
    let with_mtls = env_flag("AGENT_MTLS") || std::env::args().any(|a| a == "--mtls");
    let do_enroll = env_flag("AGENT_ENROLL")
        || std::env::args().any(|a| a == "--enroll")
        || with_mtls
        || device_token.is_none();
    let heartbeat_secs: u64 = std::env::var("HEARTBEAT_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30)
        .max(5);
    let once = env_flag("AGENT_ONCE") || std::env::args().any(|a| a == "--once");

    // Prefer DEVICE_TOKEN for agent APIs; control token still works for operator paths.
    let api_token = device_token.or_else(|| control_api_token.clone());

    let mut agent = AgentEngine::new(
        device_id.clone(),
        device_name,
        device_type,
        device_ip,
        platform,
        control_plane_url.clone(),
        api_token,
        Duration::from_secs(heartbeat_secs),
    );

    let client = reqwest::Client::new();

    if do_enroll {
        info!(
            %control_plane_url,
            with_mtls,
            "Enrolling device with control plane..."
        );
        match agent
            .enroll(&client, enroll_token.as_deref(), with_mtls)
            .await
        {
            Ok((_id, token, client_cert, _ca)) => {
                info!("DEVICE_TOKEN issued — store securely for subsequent runs");
                println!("DEVICE_TOKEN={token}");
                if client_cert.is_some() {
                    info!("mTLS client certificate issued (see DEVICE_CERT_PEM_* blocks)");
                }
                agent.set_api_token(Some(token));
            }
            Err(e) => {
                if once {
                    return Err(format!("enroll failed: {e}").into());
                }
                warn!("Enroll failed — continuing with existing credentials: {e}");
            }
        }
    }

    let agent = Arc::new(agent);

    if once {
        info!(%control_plane_url, "Agent once-mode: policy + evaluate + events + heartbeat");
        agent.run_once().await?;
        info!("Agent once-mode complete.");
        return Ok(());
    }

    if let Err(e) = agent.pull_policy(&client).await {
        warn!("Initial policy pull failed — using offline defaults: {e}");
    }
    let events = demo_evaluate(&agent).await;
    if let Err(e) = agent.send_events(&client, events).await {
        warn!("Initial events batch failed (control plane may be down): {e}");
    }
    if let Err(e) = agent.send_heartbeat(&client).await {
        warn!("Initial heartbeat failed: {e}");
    }

    let agent_clone = agent.clone();
    tokio::spawn(async move {
        agent_clone.run_heartbeat_loop().await;
    });

    info!("Agent spike running. Press Ctrl+C to exit.");
    tokio::signal::ctrl_c().await?;
    info!("Agent spike shutdown.");
    Ok(())
}
