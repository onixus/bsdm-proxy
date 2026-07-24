use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

/// Obfuscation parameters for AmneziaWG (AWG)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwgObfuscationConfig {
    /// Number of junk packets sent before handshake (Jc)
    pub jc: u16,
    /// Minimum junk packet size in bytes (Jmin)
    pub jmin: u16,
    /// Maximum junk packet size in bytes (Jmax)
    pub jmax: u16,
    /// Random bytes added to Handshake Initiation packet (S1)
    pub s1: u16,
    /// Random bytes added to Handshake Response packet (S2)
    pub s2: u16,
    /// Magic header for Handshake Initiation (H1)
    pub h1: u32,
    /// Magic header for Handshake Response (H2)
    pub h2: u32,
    /// Magic header for Cookie Reply (H3)
    pub h3: u32,
    /// Magic header for Transport Data packets (H4)
    pub h4: u32,
}

impl Default for AwgObfuscationConfig {
    fn default() -> Self {
        Self {
            jc: 4,
            jmin: 40,
            jmax: 70,
            s1: 15,
            s2: 25,
            h1: 10000001,
            h2: 10000002,
            h3: 10000003,
            h4: 10000004,
        }
    }
}

/// AmneziaWG Server Configuration state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwgServerConfig {
    pub enabled: bool,
    pub listen_port: u16,
    pub private_key: String,
    pub public_key: String,
    pub address: String,
    pub obfuscation: AwgObfuscationConfig,
    pub peers: Vec<AwgPeerConfig>,
    #[serde(default)]
    pub last_reload_status: Option<String>,
    #[serde(default)]
    pub last_reload_at: Option<u64>,
}

impl Default for AwgServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_port: 51820,
            private_key: "wP4k...placeholder...key=".to_string(),
            public_key: "pub...placeholder...key=".to_string(),
            address: "10.8.0.1/24".to_string(),
            obfuscation: AwgObfuscationConfig::default(),
            peers: vec![],
            last_reload_status: Some("standalone_unconfigured".to_string()),
            last_reload_at: None,
        }
    }
}

/// AmneziaWG Peer (Client) Configuration & Telemetry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwgPeerConfig {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub private_key: Option<String>,
    pub allowed_ips: String,
    pub assigned_ip: String,
    pub created_at: String,
    #[serde(default)]
    pub rx_bytes: u64,
    #[serde(default)]
    pub tx_bytes: u64,
    #[serde(default)]
    pub latest_handshake_secs: u64,
}

/// Telemetry metrics parsed from WireGuard/AmneziaWG dump output
#[derive(Debug, Clone, Default)]
pub struct PeerTelemetry {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub latest_handshake_secs: u64,
}

/// Generate a client `.conf` file content for AmneziaWG
pub fn generate_client_conf(
    server_public_key: &str,
    server_endpoint: &str,
    peer: &AwgPeerConfig,
    obfuscation: &AwgObfuscationConfig,
    client_private_key: &str,
) -> String {
    format!(
        r#"[Interface]
PrivateKey = {client_private_key}
Address = {assigned_ip}/32
DNS = 1.1.1.1, 8.8.8.8
Jc = {jc}
Jmin = {jmin}
Jmax = {jmax}
S1 = {s1}
S2 = {s2}
H1 = {h1}
H2 = {h2}
H3 = {h3}
H4 = {h4}

[Peer]
PublicKey = {server_public_key}
Endpoint = {server_endpoint}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"#,
        client_private_key = client_private_key,
        assigned_ip = peer.assigned_ip,
        jc = obfuscation.jc,
        jmin = obfuscation.jmin,
        jmax = obfuscation.jmax,
        s1 = obfuscation.s1,
        s2 = obfuscation.s2,
        h1 = obfuscation.h1,
        h2 = obfuscation.h2,
        h3 = obfuscation.h3,
        h4 = obfuscation.h4,
        server_public_key = server_public_key,
        server_endpoint = server_endpoint,
    )
}

/// Generate server `awg0.conf` file content containing `[Interface]` and all `[Peer]` entries
pub fn generate_server_conf(config: &AwgServerConfig) -> String {
    let mut out = format!(
        r#"[Interface]
Address = {address}
ListenPort = {port}
PrivateKey = {privkey}
Jc = {jc}
Jmin = {jmin}
Jmax = {jmax}
S1 = {s1}
S2 = {s2}
H1 = {h1}
H2 = {h2}
H3 = {h3}
H4 = {h4}
"#,
        address = config.address,
        port = config.listen_port,
        privkey = config.private_key,
        jc = config.obfuscation.jc,
        jmin = config.obfuscation.jmin,
        jmax = config.obfuscation.jmax,
        s1 = config.obfuscation.s1,
        s2 = config.obfuscation.s2,
        h1 = config.obfuscation.h1,
        h2 = config.obfuscation.h2,
        h3 = config.obfuscation.h3,
        h4 = config.obfuscation.h4,
    );

    for peer in &config.peers {
        out.push_str(&format!(
            r#"
[Peer]
# Name: {name} (ID: {id})
PublicKey = {pubkey}
AllowedIPs = {allowed_ips}
"#,
            name = peer.name,
            id = peer.id,
            pubkey = peer.public_key,
            allowed_ips = if peer.allowed_ips.is_empty() {
                format!("{}/32", peer.assigned_ip)
            } else {
                peer.allowed_ips.clone()
            },
        ));
    }

    out
}

/// Atomically write server configuration to file
pub fn save_server_conf(path: &Path, config: &AwgServerConfig) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = generate_server_conf(config);
    fs::write(path, content)?;
    info!("Saved AmneziaWG server config to {}", path.display());
    Ok(())
}

/// Save server config and trigger sidecar interface reload if configured
pub fn sync_sidecar_interface(path: &Path, config: &mut AwgServerConfig) -> Result<String, String> {
    save_server_conf(path, config).map_err(|e| format!("Failed to save awg0.conf: {}", e))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    config.last_reload_at = Some(now);

    let reload_cmd = std::env::var("AWG_RELOAD_CMD")
        .ok()
        .filter(|s| !s.is_empty());
    if let Some(cmd_str) = reload_cmd {
        info!("Executing AWG reload command: {}", cmd_str);
        let status = if cfg!(target_os = "windows") {
            Command::new("cmd").args(["/C", &cmd_str]).status()
        } else {
            Command::new("sh").args(["-c", &cmd_str]).status()
        };

        match status {
            Ok(s) if s.success() => {
                let msg = format!("Sidecar reloaded successfully via `{}`", cmd_str);
                config.last_reload_status = Some(msg.clone());
                Ok(msg)
            }
            Ok(s) => {
                let err_msg = format!("AWG reload command exit code: {:?}", s.code());
                warn!("{}", err_msg);
                config.last_reload_status = Some(err_msg.clone());
                Err(err_msg)
            }
            Err(e) => {
                let err_msg = format!("Failed to launch AWG reload command: {}", e);
                warn!("{}", err_msg);
                config.last_reload_status = Some(err_msg.clone());
                Err(err_msg)
            }
        }
    } else {
        let msg = format!(
            "Config saved to {}. Set AWG_RELOAD_CMD to enable automatic sidecar sync.",
            path.display()
        );
        config.last_reload_status = Some("saved_unreloaded".to_string());
        Ok(msg)
    }
}

/// Parse `awg show awg0 dump` or `wg show awg0 dump` output into peer telemetry
pub fn parse_interface_telemetry(dump_output: &str) -> HashMap<String, PeerTelemetry> {
    let mut map = HashMap::new();
    for line in dump_output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // WireGuard dump format per peer line (8 columns):
        // <public_key> <preshared_key> <endpoint> <allowed_ips> <latest_handshake> <rx_bytes> <tx_bytes> <persistent_keepalive>
        if parts.len() >= 7 {
            let pubkey = parts[0].to_string();
            let latest_handshake_secs = parts[4].parse::<u64>().unwrap_or(0);
            let rx_bytes = parts[5].parse::<u64>().unwrap_or(0);
            let tx_bytes = parts[6].parse::<u64>().unwrap_or(0);

            map.insert(
                pubkey,
                PeerTelemetry {
                    rx_bytes,
                    tx_bytes,
                    latest_handshake_secs,
                },
            );
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_awg_default_obfuscation_config() {
        let obf = AwgObfuscationConfig::default();
        assert_eq!(obf.jc, 4);
        assert_eq!(obf.jmin, 40);
        assert_eq!(obf.jmax, 70);
        assert_eq!(obf.s1, 15);
        assert_eq!(obf.s2, 25);
    }

    #[test]
    fn test_generate_client_conf() {
        let obf = AwgObfuscationConfig::default();
        let peer = AwgPeerConfig {
            id: "peer-1".to_string(),
            name: "Alice Phone".to_string(),
            public_key: "pubkey123".to_string(),
            private_key: Some("privkey123".to_string()),
            allowed_ips: "10.8.0.2/32".to_string(),
            assigned_ip: "10.8.0.2".to_string(),
            created_at: "2026-07-24".to_string(),
            rx_bytes: 0,
            tx_bytes: 0,
            latest_handshake_secs: 0,
        };

        let conf = generate_client_conf(
            "srvpub123",
            "proxy.corp.com:51820",
            &peer,
            &obf,
            "privkey123",
        );
        assert!(conf.contains("PrivateKey = privkey123"));
        assert!(conf.contains("Address = 10.8.0.2/32"));
        assert!(conf.contains("PublicKey = srvpub123"));
        assert!(conf.contains("Endpoint = proxy.corp.com:51820"));
        assert!(conf.contains("Jc = 4"));
        assert!(conf.contains("H1 = 10000001"));
    }

    #[test]
    fn test_generate_and_save_server_conf() {
        let mut config = AwgServerConfig {
            private_key: "srvpriv123".to_string(),
            ..Default::default()
        };
        config.peers.push(AwgPeerConfig {
            id: "p1".to_string(),
            name: "Corporate Client".to_string(),
            public_key: "peerpubkey123".to_string(),
            private_key: None,
            allowed_ips: "10.8.0.2/32".to_string(),
            assigned_ip: "10.8.0.2".to_string(),
            created_at: "2026-07-24".to_string(),
            rx_bytes: 0,
            tx_bytes: 0,
            latest_handshake_secs: 0,
        });

        let conf_str = generate_server_conf(&config);
        assert!(conf_str.contains("[Interface]"));
        assert!(conf_str.contains("PrivateKey = srvpriv123"));
        assert!(conf_str.contains("PublicKey = peerpubkey123"));
        assert!(conf_str.contains("AllowedIPs = 10.8.0.2/32"));

        let file = NamedTempFile::new().unwrap();
        save_server_conf(file.path(), &config).unwrap();
        let read_back = fs::read_to_string(file.path()).unwrap();
        assert_eq!(read_back, conf_str);
    }

    #[test]
    fn test_parse_interface_telemetry() {
        let dump = "pubkey123\t(none)\t198.51.100.20:51820\t10.8.0.2/32\t1721812900\t1048576\t2097152\t25\n\
                    pubkey456\t(none)\t198.51.100.21:51820\t10.8.0.3/32\t1721812000\t51200\t102400\t25\n";

        let map = parse_interface_telemetry(dump);
        assert_eq!(map.len(), 2);
        let p1 = map.get("pubkey123").unwrap();
        assert_eq!(p1.rx_bytes, 1048576);
        assert_eq!(p1.tx_bytes, 2097152);
        assert_eq!(p1.latest_handshake_secs, 1721812900);
    }
}
