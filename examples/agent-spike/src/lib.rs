//! Minimal On-Device Local Policy Agent Spike (Phase C, Issue #258 / #273)
//! Implements Agent Contract v0.1: Enroll, Policy Fetch, Local Evaluate, Events, Heartbeat.
//! Optional multi-OS system-proxy apply/clear for pilot installers.

pub mod engine;
pub mod pac;
pub mod policy;
pub mod router;
pub mod system_proxy;
pub mod tunnel;
pub mod ui_server;

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

fn has_arg(flag: &str) -> bool {
    std::env::args().any(|a| a == flag)
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,agent_spike=debug".into()),
        )
        .init();

    info!("🚀 BSDM Minimal Local Policy Agent Spike (Phase C, Issue #258/#273)");

    // Standalone system-proxy commands (installers use these).
    let dry_run = env_flag("SYSTEM_PROXY_DRY_RUN") || has_arg("--dry-run");
    if has_arg("--set-system-proxy") || env_flag("AGENT_SET_SYSTEM_PROXY") {
        let ep = system_proxy::ProxyEndpoint::from_env();
        match system_proxy::set_system_proxy(&ep, dry_run) {
            Ok(msg) => {
                info!(%msg, platform = system_proxy::platform_tag(), "System proxy applied");
                println!("{msg}");
                return Ok(());
            }
            Err(e) => return Err(format!("set-system-proxy: {e}").into()),
        }
    }
    if has_arg("--clear-system-proxy") || env_flag("AGENT_CLEAR_SYSTEM_PROXY") {
        match system_proxy::clear_system_proxy(dry_run) {
            Ok(msg) => {
                info!(%msg, platform = system_proxy::platform_tag(), "System proxy cleared");
                println!("{msg}");
                return Ok(());
            }
            Err(e) => return Err(format!("clear-system-proxy: {e}").into()),
        }
    }

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
    let with_tunnel = env_flag("AGENT_TUNNEL")
        || std::env::args().any(|a| a == "--tunnel" || a == "--with-tunnel");
    let do_enroll = env_flag("AGENT_ENROLL")
        || std::env::args().any(|a| a == "--enroll")
        || with_mtls
        || with_tunnel
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
            with_tunnel,
            "Enrolling device with control plane..."
        );
        match agent
            .enroll(&client, enroll_token.as_deref(), with_mtls, with_tunnel)
            .await
        {
            Ok(res) => {
                info!("DEVICE_TOKEN issued — store securely for subsequent runs");
                println!("DEVICE_TOKEN={}", res.device_token);
                if res.client_cert_pem.is_some() {
                    info!("mTLS client certificate issued (see DEVICE_CERT_PEM_* blocks)");
                }
                if let Some(t_conf) = &res.tunnel_config {
                    info!("AmneziaWG tunnel configured on server");
                    if let Ok(c_conf) =
                        serde_json::from_value::<tunnel::AwgClientConfig>(t_conf.clone())
                    {
                        let conf_path = std::env::var("AWG_CLIENT_CONFIG_PATH")
                            .unwrap_or_else(|_| "./certs/awg/client.conf".to_string());
                        if let Err(e) = c_conf.save_conf(std::path::Path::new(&conf_path)) {
                            warn!("Failed to save client tunnel config: {e}");
                        } else {
                            info!(%conf_path, "Saved AmneziaWG client configuration");
                        }
                    }
                }
                agent.set_api_token(Some(res.device_token));
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

    // Optional policy push: WebSocket (AGENT_POLICY_WS=1) or long-poll (default).
    let policy_push = !matches!(
        std::env::var("AGENT_POLICY_PUSH").as_deref(),
        Ok("0") | Ok("false") | Ok("FALSE") | Ok("no") | Ok("off")
    ) && !std::env::args().any(|a| a == "--no-policy-push");
    let policy_ws = env_flag("AGENT_POLICY_WS") || std::env::args().any(|a| a == "--policy-ws");
    if policy_push {
        let agent_watch = agent.clone();
        if policy_ws {
            tokio::spawn(async move {
                agent_watch.watch_policy_ws_loop().await;
            });
            info!("Policy WebSocket push loop enabled");
        } else {
            let timeout_secs: u64 = std::env::var("AGENT_POLICY_WATCH_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(25);
            tokio::spawn(async move {
                agent_watch.watch_policy_loop(timeout_secs).await;
            });
            info!(timeout_secs, "Policy push watch loop enabled");
        }
    }

    // Optional: point OS at data-plane proxy for the lifetime of this process.
    let manage_proxy = env_flag("AGENT_MANAGE_SYSTEM_PROXY") || has_arg("--manage-system-proxy");
    if manage_proxy {
        let ep = system_proxy::ProxyEndpoint::from_env();
        match system_proxy::set_system_proxy(&ep, false) {
            Ok(msg) => info!(%msg, "System proxy enabled for agent session"),
            Err(e) => warn!("Could not set system proxy (continuing): {e}"),
        }
    }

    info!("Agent spike running. Press Ctrl+C to exit.");
    tokio::signal::ctrl_c().await?;

    if manage_proxy {
        match system_proxy::clear_system_proxy(false) {
            Ok(msg) => info!(%msg, "System proxy cleared on shutdown"),
            Err(e) => warn!("Could not clear system proxy on shutdown: {e}"),
        }
    }
    info!("Agent spike shutdown.");
    Ok(())
}
