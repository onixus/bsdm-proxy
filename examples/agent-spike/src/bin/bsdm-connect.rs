//! BSDM Connect — Alternative Native Rust Client for AmneziaWG & BSDM Secure Web Gateway
//!
//! Provides enrollment, AmneziaWG obfuscated tunnel lifecycle management (up/down/status),
//! domain-based route steering (Split Routing / PAC generation), Web/Mobile UI server,
//! real-time policy synchronization via WebSocket/long-poll, and client telemetry reporting.

use agent_spike::engine::{demo_evaluate, AgentEngine, AgentState};
use agent_spike::pac::generate_pac;
use agent_spike::router::{RouteRule, RouteTable, RouteTarget};
use agent_spike::tunnel::{tunnel_down, tunnel_status, tunnel_up, AwgClientConfig};
use agent_spike::ui_server::{run_ui_server, UiServerState};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

fn default_state_path() -> PathBuf {
    if let Ok(p) = std::env::var("BSDM_STATE_FILE") {
        return PathBuf::from(p);
    }
    if let Some(home) = dirs_home() {
        home.join(".bsdm").join("state.json")
    } else {
        PathBuf::from("./state.json")
    }
}

fn default_conf_path() -> PathBuf {
    if let Ok(p) = std::env::var("AWG_CLIENT_CONFIG_PATH") {
        return PathBuf::from(p);
    }
    if let Some(home) = dirs_home() {
        home.join(".bsdm").join("awg0.conf")
    } else {
        PathBuf::from("./awg0.conf")
    }
}

fn default_routes_path() -> PathBuf {
    if let Ok(p) = std::env::var("BSDM_ROUTES_FILE") {
        return PathBuf::from(p);
    }
    if let Some(home) = dirs_home() {
        home.join(".bsdm").join("routes.json")
    } else {
        PathBuf::from("./routes.json")
    }
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn print_usage() {
    println!(
        r#"BSDM Connect — Native Rust Client for AmneziaWG & BSDM Secure Web Gateway

USAGE:
    bsdm-connect <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    enroll             Enroll this device with the BSDM Control Plane
    ui                 Start Agent Web/Mobile UI and PAC server (default port 8765)
    routes             Manage local domain split-routing table (list, add, delete, export-pac)
    tunnel up          Activate AmneziaWG tunnel interface
    tunnel down        Deactivate AmneziaWG tunnel interface
    tunnel status      Show current tunnel interface status and telemetry
    tunnel get-config  Download latest tunnel configuration from control plane
    run / daemon       Run continuous agent with UI server, policy sync, tunnel, and heartbeats
    help               Print this help message

OPTIONS (Global / Command-specific):
    --control-url <URL>    Control plane URL (default: $CONTROL_PLANE_URL or http://127.0.0.1:9090)
    --token <TOKEN>        Enrollment or Device Bearer token (default: $AGENT_ENROLL_TOKEN / $DEVICE_TOKEN)
    --device-id <ID>       Unique device identifier (default: $DEVICE_ID)
    --device-name <NAME>   Human-readable device name (default: $DEVICE_NAME)
    --state-file <PATH>    Path to local JSON state file (default: ~/.bsdm/state.json)
    --routes-file <PATH>   Path to domain routes file (default: ~/.bsdm/routes.json)
    --config <PATH>        Path to AmneziaWG .conf file (default: ~/.bsdm/awg0.conf)
    --interface <NAME>     AmneziaWG interface name for status query (default: awg0)
    --port <PORT>          UI & PAC server port (default: 8765)
    --format <FORMAT>      Config export format: 'conf' or 'json' (default: conf)
    --dry-run              Print commands without modifying system network interfaces
    --with-tunnel          Request AmneziaWG VPN tunnel provisioning during enroll
    --with-mtls            Generate CSR and request mTLS client certificate during enroll
"#
    );
}

fn get_arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|idx| args.get(idx + 1).cloned())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,bsdm_connect=debug,agent_spike=info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || has_flag(&args, "--help") || has_flag(&args, "-h") || args[1] == "help" {
        print_usage();
        return Ok(());
    }

    let subcommand = args[1].as_str();

    match subcommand {
        "enroll" => cmd_enroll(&args).await?,
        "ui" => cmd_ui(&args).await?,
        "routes" => {
            if args.len() < 3 {
                eprintln!("Error: 'routes' requires a sub-action: list, add, delete, export-pac");
                print_usage();
                std::process::exit(1);
            }
            match args[2].as_str() {
                "list" => cmd_routes_list(&args)?,
                "add" => cmd_routes_add(&args)?,
                "delete" => cmd_routes_delete(&args)?,
                "export-pac" => cmd_routes_export_pac(&args)?,
                other => {
                    eprintln!("Unknown routes action: '{other}'");
                    print_usage();
                    std::process::exit(1);
                }
            }
        }
        "tunnel" => {
            if args.len() < 3 {
                eprintln!("Error: 'tunnel' requires a sub-action: up, down, status, get-config");
                print_usage();
                std::process::exit(1);
            }
            match args[2].as_str() {
                "up" => cmd_tunnel_up(&args)?,
                "down" => cmd_tunnel_down(&args)?,
                "status" => cmd_tunnel_status(&args)?,
                "get-config" => cmd_tunnel_get_config(&args).await?,
                other => {
                    eprintln!("Unknown tunnel action: '{other}'");
                    print_usage();
                    std::process::exit(1);
                }
            }
        }
        "run" | "daemon" => cmd_daemon(&args).await?,
        other => {
            eprintln!("Unknown subcommand: '{other}'");
            print_usage();
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn cmd_ui(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let port: u16 = get_arg_value(args, "--port")
        .or_else(|| std::env::var("AGENT_UI_PORT").ok())
        .and_then(|p| p.parse().ok())
        .unwrap_or(8765);

    let state_file = get_arg_value(args, "--state-file")
        .map(PathBuf::from)
        .unwrap_or_else(default_state_path);

    let state = if state_file.exists() {
        AgentState::load(&state_file).ok()
    } else {
        None
    };

    let control_url = get_arg_value(args, "--control-url")
        .or_else(|| state.as_ref().map(|s| s.control_plane_url.clone()))
        .unwrap_or_else(|| "http://127.0.0.1:9090".to_string());

    let device_id = state
        .as_ref()
        .map(|s| s.device_id.clone())
        .unwrap_or_else(|| "agent-local".to_string());

    let routes_path = get_arg_value(args, "--routes-file")
        .map(PathBuf::from)
        .unwrap_or_else(default_routes_path);

    let routes = Arc::new(RwLock::new(RouteTable::load_or_default(&routes_path)));
    let conf_path = default_conf_path();

    let ui_state = Arc::new(UiServerState {
        routes,
        routes_path,
        conf_path,
        control_url,
        proxy_authority: "127.0.0.1:3128".to_string(),
        tunnel_active: Arc::new(RwLock::new(false)),
        device_id,
    });

    let bind_addr = SocketAddr::from(([127, 0, 0, 1], port));
    info!("🚀 Launching BSDM Connect Agent UI at http://127.0.0.1:{port}");
    println!("Web / Mobile UI running at: http://127.0.0.1:{port}");
    println!("PAC Proxy script running at: http://127.0.0.1:{port}/proxy.pac");

    run_ui_server(bind_addr, ui_state).await?;
    Ok(())
}

fn cmd_routes_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let routes_path = get_arg_value(args, "--routes-file")
        .map(PathBuf::from)
        .unwrap_or_else(default_routes_path);

    let table = RouteTable::load_or_default(&routes_path);
    let json = serde_json::to_string_pretty(&table)?;
    println!("{json}");
    Ok(())
}

fn cmd_routes_add(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let pattern = get_arg_value(args, "--pattern")
        .ok_or("Missing --pattern (e.g. --pattern '*.corp.com')")?;
    let target_str = get_arg_value(args, "--target").unwrap_or_else(|| "proxy".to_string());
    let comment = get_arg_value(args, "--comment");

    let target = match target_str.to_ascii_lowercase().as_str() {
        "direct" => RouteTarget::Direct,
        "tunnel" | "vpn" => RouteTarget::Tunnel,
        "block" | "deny" => RouteTarget::Block,
        _ => RouteTarget::Proxy,
    };

    let routes_path = get_arg_value(args, "--routes-file")
        .map(PathBuf::from)
        .unwrap_or_else(default_routes_path);

    let mut table = RouteTable::load_or_default(&routes_path);
    let id = format!("rule-{}", hex::encode(rand::random::<[u8; 3]>()));

    table.upsert_rule(RouteRule {
        id: id.clone(),
        pattern,
        target,
        enabled: true,
        comment,
    })?;

    table.save(&routes_path)?;
    println!("Added route rule {id} -> {target}");
    Ok(())
}

fn cmd_routes_delete(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() < 4 {
        eprintln!("Usage: bsdm-connect routes delete <RULE_ID>");
        std::process::exit(1);
    }
    let id = &args[3];

    let routes_path = get_arg_value(args, "--routes-file")
        .map(PathBuf::from)
        .unwrap_or_else(default_routes_path);

    let mut table = RouteTable::load_or_default(&routes_path);
    if table.remove_rule(id) {
        table.save(&routes_path)?;
        println!("Deleted route rule {id}");
    } else {
        println!("Route rule {id} not found");
    }
    Ok(())
}

fn cmd_routes_export_pac(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let routes_path = get_arg_value(args, "--routes-file")
        .map(PathBuf::from)
        .unwrap_or_else(default_routes_path);

    let proxy = get_arg_value(args, "--proxy").unwrap_or_else(|| "127.0.0.1:3128".to_string());
    let table = RouteTable::load_or_default(&routes_path);
    let pac = generate_pac(&table, &proxy, None);

    if let Some(out) = get_arg_value(args, "--output").map(PathBuf::from) {
        std::fs::write(&out, &pac)?;
        println!("PAC script exported to {}", out.display());
    } else {
        print!("{pac}");
    }
    Ok(())
}

async fn cmd_enroll(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let control_url = get_arg_value(args, "--control-url")
        .or_else(|| std::env::var("CONTROL_PLANE_URL").ok())
        .unwrap_or_else(|| "http://127.0.0.1:9090".to_string());

    let token = get_arg_value(args, "--token")
        .or_else(|| std::env::var("AGENT_ENROLL_TOKEN").ok())
        .or_else(|| std::env::var("CONTROL_API_TOKEN").ok());

    let device_id = get_arg_value(args, "--device-id")
        .or_else(|| std::env::var("DEVICE_ID").ok())
        .unwrap_or_else(|| format!("dev-{}", hex::encode(rand::random::<[u8; 4]>())));

    let device_name = get_arg_value(args, "--device-name")
        .or_else(|| std::env::var("DEVICE_NAME").ok())
        .unwrap_or_else(|| format!("bsdm-client-{device_id}"));

    let state_file = get_arg_value(args, "--state-file")
        .map(PathBuf::from)
        .unwrap_or_else(default_state_path);

    let conf_file = get_arg_value(args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(default_conf_path);

    let with_tunnel = has_flag(args, "--with-tunnel") || std::env::var("AGENT_TUNNEL").is_ok();
    let with_mtls = has_flag(args, "--with-mtls") || std::env::var("AGENT_MTLS").is_ok();

    info!(%control_url, %device_id, with_tunnel, with_mtls, "Enrolling client with BSDM Control Plane...");

    let agent = AgentEngine::new(
        device_id.clone(),
        device_name.clone(),
        "desktop".to_string(),
        None,
        std::env::consts::OS.to_string(),
        control_url.clone(),
        None,
        Duration::from_secs(30),
    );

    let client = reqwest::Client::new();
    let res = agent
        .enroll(&client, token.as_deref(), with_mtls, with_tunnel)
        .await
        .map_err(|e| format!("Enrollment failed: {e}"))?;

    info!(device_id = %res.device_id, "Device successfully enrolled");
    println!("DEVICE_ID={}", res.device_id);
    println!("DEVICE_TOKEN={}", res.device_token);

    let mut saved_conf_path = None;
    if let Some(t_val) = &res.tunnel_config {
        if let Ok(c_conf) = serde_json::from_value::<AwgClientConfig>(t_val.clone()) {
            if let Err(e) = c_conf.save_conf(&conf_file) {
                warn!("Failed to save client tunnel configuration: {e}");
            } else {
                info!(path = %conf_file.display(), "AmneziaWG client configuration saved with 0600 permissions");
                println!("AWG_CONFIG_PATH={}", conf_file.display());
                saved_conf_path = Some(conf_file.to_string_lossy().to_string());
            }
        }
    }

    let state = AgentState {
        device_id: res.device_id,
        device_name,
        device_type: "desktop".to_string(),
        platform: std::env::consts::OS.to_string(),
        control_plane_url: control_url,
        device_token: Some(res.device_token),
        client_cert_pem: res.client_cert_pem,
        ca_cert_pem: res.ca_cert_pem,
        tunnel_conf_path: saved_conf_path,
        updated_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    state.save(&state_file)?;
    info!(state_file = %state_file.display(), "Client state persisted");
    Ok(())
}

fn cmd_tunnel_up(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let conf_path = get_arg_value(args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(default_conf_path);

    let dry_run = has_flag(args, "--dry-run") || std::env::var("AWG_DRY_RUN").is_ok();
    let msg = tunnel_up(&conf_path, dry_run)?;
    println!("{msg}");
    Ok(())
}

fn cmd_tunnel_down(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let conf_path = get_arg_value(args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(default_conf_path);

    let dry_run = has_flag(args, "--dry-run") || std::env::var("AWG_DRY_RUN").is_ok();
    let msg = tunnel_down(&conf_path, dry_run)?;
    println!("{msg}");
    Ok(())
}

fn cmd_tunnel_status(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let iface = get_arg_value(args, "--interface")
        .or_else(|| std::env::var("AWG_INTERFACE").ok())
        .unwrap_or_else(|| "awg0".to_string());

    let status = tunnel_status(&iface);
    let json = serde_json::to_string_pretty(&status)?;
    println!("{json}");
    Ok(())
}

async fn cmd_tunnel_get_config(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let state_file = get_arg_value(args, "--state-file")
        .map(PathBuf::from)
        .unwrap_or_else(default_state_path);

    let state = if state_file.exists() {
        AgentState::load(&state_file).ok()
    } else {
        None
    };

    let control_url = get_arg_value(args, "--control-url")
        .or_else(|| state.as_ref().map(|s| s.control_plane_url.clone()))
        .or_else(|| std::env::var("CONTROL_PLANE_URL").ok())
        .unwrap_or_else(|| "http://127.0.0.1:9090".to_string());

    let device_id = get_arg_value(args, "--device-id")
        .or_else(|| state.as_ref().map(|s| s.device_id.clone()))
        .or_else(|| std::env::var("DEVICE_ID").ok())
        .ok_or("Missing --device-id and no state file found")?;

    let token = get_arg_value(args, "--token")
        .or_else(|| state.as_ref().and_then(|s| s.device_token.clone()))
        .or_else(|| std::env::var("DEVICE_TOKEN").ok())
        .or_else(|| std::env::var("CONTROL_API_TOKEN").ok());

    let format = get_arg_value(args, "--format").unwrap_or_else(|| "conf".to_string());

    let agent = AgentEngine::new(
        device_id,
        "bsdm-client".to_string(),
        "desktop".to_string(),
        None,
        std::env::consts::OS.to_string(),
        control_url,
        token,
        Duration::from_secs(30),
    );

    let client = reqwest::Client::new();
    let config_content = agent.fetch_tunnel_config(&client, &format).await?;

    if let Some(out_path) = get_arg_value(args, "--output").map(PathBuf::from) {
        agent_spike::tunnel::save_atomic_0600(&out_path, &config_content)?;
        info!(path = %out_path.display(), "Downloaded tunnel config written to file");
    } else {
        print!("{config_content}");
    }

    Ok(())
}

async fn cmd_daemon(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let state_file = get_arg_value(args, "--state-file")
        .map(PathBuf::from)
        .unwrap_or_else(default_state_path);

    let state = if state_file.exists() {
        match AgentState::load(&state_file) {
            Ok(s) => Some(s),
            Err(e) => {
                warn!("Could not read state file ({}): {e}", state_file.display());
                None
            }
        }
    } else {
        None
    };

    let control_url = get_arg_value(args, "--control-url")
        .or_else(|| state.as_ref().map(|s| s.control_plane_url.clone()))
        .or_else(|| std::env::var("CONTROL_PLANE_URL").ok())
        .unwrap_or_else(|| "http://127.0.0.1:9090".to_string());

    let device_id = get_arg_value(args, "--device-id")
        .or_else(|| state.as_ref().map(|s| s.device_id.clone()))
        .or_else(|| std::env::var("DEVICE_ID").ok())
        .unwrap_or_else(|| format!("dev-{}", hex::encode(rand::random::<[u8; 4]>())));

    let device_name = get_arg_value(args, "--device-name")
        .or_else(|| state.as_ref().map(|s| s.device_name.clone()))
        .or_else(|| std::env::var("DEVICE_NAME").ok())
        .unwrap_or_else(|| format!("agent-{device_id}"));

    let token = get_arg_value(args, "--token")
        .or_else(|| state.as_ref().and_then(|s| s.device_token.clone()))
        .or_else(|| std::env::var("DEVICE_TOKEN").ok())
        .or_else(|| std::env::var("CONTROL_API_TOKEN").ok());

    let auto_tunnel = has_flag(args, "--with-tunnel")
        || has_flag(args, "--tunnel")
        || std::env::var("AGENT_TUNNEL").is_ok()
        || state
            .as_ref()
            .and_then(|s| s.tunnel_conf_path.as_ref())
            .is_some();

    info!(
        %control_url,
        %device_id,
        auto_tunnel,
        "🚀 Starting BSDM Connect Client Daemon"
    );

    let mut agent = AgentEngine::new(
        device_id.clone(),
        device_name.clone(),
        "desktop".to_string(),
        None,
        std::env::consts::OS.to_string(),
        control_url.clone(),
        token.clone(),
        Duration::from_secs(30),
    );

    let client = reqwest::Client::new();

    // Enroll if token is missing
    if agent.policy_version().await.is_empty() && token.is_none() {
        info!("No token available — performing bootstrap enrollment...");
        match agent.enroll(&client, None, false, auto_tunnel).await {
            Ok(res) => {
                agent.set_api_token(Some(res.device_token.clone()));
                let conf_file = default_conf_path();
                if let Some(t_val) = res.tunnel_config {
                    if let Ok(c_conf) = serde_json::from_value::<AwgClientConfig>(t_val) {
                        let _ = c_conf.save_conf(&conf_file);
                    }
                }
                let st = AgentState {
                    device_id: res.device_id,
                    device_name,
                    device_type: "desktop".to_string(),
                    platform: std::env::consts::OS.to_string(),
                    control_plane_url: control_url.clone(),
                    device_token: Some(res.device_token),
                    client_cert_pem: res.client_cert_pem,
                    ca_cert_pem: res.ca_cert_pem,
                    tunnel_conf_path: Some(conf_file.to_string_lossy().to_string()),
                    updated_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                };
                let _ = st.save(&state_file);
            }
            Err(e) => warn!("Bootstrap enrollment failed: {e}"),
        }
    }

    let agent = Arc::new(agent);

    // Initial policy pull & smoke evaluation
    if let Err(e) = agent.pull_policy(&client).await {
        warn!("Initial policy pull failed: {e}");
    }
    let events = demo_evaluate(&agent).await;
    let _ = agent.send_events(&client, events).await;
    let _ = agent.send_heartbeat(&client).await;

    // Launch background loops: heartbeat & policy watcher
    let agent_hb = agent.clone();
    tokio::spawn(async move {
        agent_hb.run_heartbeat_loop().await;
    });

    let agent_ws = agent.clone();
    tokio::spawn(async move {
        agent_ws.watch_policy_ws_loop().await;
    });

    // Start embedded Web/Mobile UI server in background
    let routes_path = default_routes_path();
    let routes = Arc::new(RwLock::new(RouteTable::load_or_default(&routes_path)));
    let conf_path = default_conf_path();
    let tunnel_active = Arc::new(RwLock::new(false));

    let ui_state = Arc::new(UiServerState {
        routes,
        routes_path,
        conf_path: conf_path.clone(),
        control_url: control_url.clone(),
        proxy_authority: "127.0.0.1:3128".to_string(),
        tunnel_active: tunnel_active.clone(),
        device_id: device_id.clone(),
    });

    let ui_port: u16 = get_arg_value(args, "--port")
        .or_else(|| std::env::var("AGENT_UI_PORT").ok())
        .and_then(|p| p.parse().ok())
        .unwrap_or(8765);
    let bind_addr = SocketAddr::from(([127, 0, 0, 1], ui_port));
    tokio::spawn(async move {
        let _ = run_ui_server(bind_addr, ui_state).await;
    });

    println!("🌐 BSDM Connect UI active: http://127.0.0.1:{ui_port}");
    println!("⚙️  Dynamic PAC file active: http://127.0.0.1:{ui_port}/proxy.pac");

    // Bring up AmneziaWG tunnel if requested
    if auto_tunnel && conf_path.exists() {
        info!(path = %conf_path.display(), "Activating AmneziaWG tunnel...");
        match tunnel_up(&conf_path, false) {
            Ok(msg) => {
                info!(%msg, "Tunnel is active");
                *tunnel_active.write().await = true;
            }
            Err(e) => warn!("Could not bring up tunnel: {e}"),
        }
    }

    info!("BSDM Connect daemon running. Press Ctrl+C to terminate.");
    tokio::signal::ctrl_c().await?;

    if *tunnel_active.read().await {
        info!("Shutting down AmneziaWG tunnel...");
        if let Err(e) = tunnel_down(&conf_path, false) {
            error!("Tunnel shutdown error: {e}");
        }
    }

    info!("BSDM Connect daemon terminated.");
    Ok(())
}
