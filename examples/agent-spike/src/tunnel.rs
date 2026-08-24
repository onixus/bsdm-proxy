//! AmneziaWG Tunnel Manager for BSDM Client (BSDM Connect)
//! Handles configuration generation with obfuscation, atomic file saving with 0600 permissions,
//! tunnel lifecycle (up/down/status), and telemetry extraction.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AwgObfuscationDto {
    #[serde(default = "default_jc")]
    pub jc: u16,
    #[serde(default = "default_jmin")]
    pub jmin: u16,
    #[serde(default = "default_jmax")]
    pub jmax: u16,
    #[serde(default = "default_s1")]
    pub s1: u16,
    #[serde(default = "default_s2")]
    pub s2: u16,
    #[serde(default = "default_h1")]
    pub h1: u32,
    #[serde(default = "default_h2")]
    pub h2: u32,
    #[serde(default = "default_h3")]
    pub h3: u32,
    #[serde(default = "default_h4")]
    pub h4: u32,
}

fn default_jc() -> u16 {
    4
}
fn default_jmin() -> u16 {
    40
}
fn default_jmax() -> u16 {
    70
}
fn default_s1() -> u16 {
    15
}
fn default_s2() -> u16 {
    25
}
fn default_h1() -> u32 {
    10000001
}
fn default_h2() -> u32 {
    10000002
}
fn default_h3() -> u32 {
    10000003
}
fn default_h4() -> u32 {
    10000004
}

impl Default for AwgObfuscationDto {
    fn default() -> Self {
        Self {
            jc: default_jc(),
            jmin: default_jmin(),
            jmax: default_jmax(),
            s1: default_s1(),
            s2: default_s2(),
            h1: default_h1(),
            h2: default_h2(),
            h3: default_h3(),
            h4: default_h4(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwgClientConfig {
    pub private_key: String,
    pub address: String,
    #[serde(default = "default_dns")]
    pub dns: String,
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    pub server_public_key: String,
    pub server_endpoint: String,
    #[serde(default)]
    pub preshared_key: Option<String>,
    #[serde(default = "default_allowed_ips")]
    pub allowed_ips: String,
    #[serde(default = "default_keepalive")]
    pub persistent_keepalive: u32,
    #[serde(default)]
    pub obfuscation: AwgObfuscationDto,
}

fn default_dns() -> String {
    "10.8.0.1".to_string()
}
fn default_mtu() -> u32 {
    1360
}
fn default_allowed_ips() -> String {
    "0.0.0.0/0, ::/0".to_string()
}
fn default_keepalive() -> u32 {
    25
}

impl AwgClientConfig {
    /// Format configuration as standard AmneziaWG / WireGuard `.conf` format
    pub fn generate_conf(&self) -> String {
        let mut out = String::with_capacity(1024);
        out.push_str("[Interface]\n");
        out.push_str(&format!("PrivateKey = {}\n", self.private_key.trim()));
        out.push_str(&format!("Address = {}\n", self.address.trim()));
        if !self.dns.trim().is_empty() {
            out.push_str(&format!("DNS = {}\n", self.dns.trim()));
        }
        if self.mtu > 0 {
            out.push_str(&format!("MTU = {}\n", self.mtu));
        }

        // AmneziaWG obfuscation header
        out.push_str(&format!("Jc = {}\n", self.obfuscation.jc));
        out.push_str(&format!("Jmin = {}\n", self.obfuscation.jmin));
        out.push_str(&format!("Jmax = {}\n", self.obfuscation.jmax));
        out.push_str(&format!("S1 = {}\n", self.obfuscation.s1));
        out.push_str(&format!("S2 = {}\n", self.obfuscation.s2));
        out.push_str(&format!("H1 = {}\n", self.obfuscation.h1));
        out.push_str(&format!("H2 = {}\n", self.obfuscation.h2));
        out.push_str(&format!("H3 = {}\n", self.obfuscation.h3));
        out.push_str(&format!("H4 = {}\n", self.obfuscation.h4));

        out.push_str("\n[Peer]\n");
        out.push_str(&format!("PublicKey = {}\n", self.server_public_key.trim()));
        if let Some(psk) = &self.preshared_key {
            if !psk.trim().is_empty() {
                out.push_str(&format!("PresharedKey = {}\n", psk.trim()));
            }
        }
        out.push_str(&format!("Endpoint = {}\n", self.server_endpoint.trim()));
        out.push_str(&format!("AllowedIPs = {}\n", self.allowed_ips.trim()));
        if self.persistent_keepalive > 0 {
            out.push_str(&format!(
                "PersistentKeepalive = {}\n",
                self.persistent_keepalive
            ));
        }
        out
    }

    /// Save configuration to file with atomic write and strict 0600 permissions
    pub fn save_conf(&self, path: &Path) -> Result<(), String> {
        let conf_str = self.generate_conf();
        save_atomic_0600(path, &conf_str)
    }
}

/// Atomically write text content to path with 0600 permissions on Unix
pub fn save_atomic_0600(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create directory {}: {e}", parent.display()))?;
    }

    let tmp_path = path.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&tmp_path, content)
        .map_err(|e| format!("Failed to write temp file {}: {e}", tmp_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        if let Err(e) = fs::set_permissions(&tmp_path, perms) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("Failed to set 0600 permissions on temp file: {e}"));
        }
    }

    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!(
            "Failed to atomically rename {} to {}: {e}",
            tmp_path.display(),
            path.display()
        )
    })?;

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub interface: String,
    pub active: bool,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub latest_handshake_secs: u64,
    pub endpoint: Option<String>,
    pub message: String,
}

/// Bring up AmneziaWG tunnel interface
pub fn tunnel_up(conf_path: &Path, dry_run: bool) -> Result<String, String> {
    if dry_run {
        let msg = format!(
            "[DRY-RUN] Would execute: awg-quick up {}",
            conf_path.display()
        );
        info!(%msg);
        return Ok(msg);
    }

    if let Ok(custom_cmd) = std::env::var("AWG_UP_CMD") {
        return run_command_string(&custom_cmd, conf_path);
    }

    // Try `awg-quick up <conf>` then fallback to `wg-quick up <conf>`
    match Command::new("awg-quick").arg("up").arg(conf_path).output() {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let msg = format!(
                "AmneziaWG tunnel activated via awg-quick ({}): {}",
                conf_path.display(),
                stdout.trim()
            );
            info!(%msg);
            Ok(msg)
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(format!(
                "awg-quick up failed with exit code {:?}: {}",
                out.status.code(),
                stderr.trim()
            ))
        }
        Err(e) => {
            warn!("awg-quick not found on PATH ({e}); attempting wg-quick fallback");
            match Command::new("wg-quick").arg("up").arg(conf_path).output() {
                Ok(out) if out.status.success() => {
                    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                    let msg = format!(
                        "Tunnel activated via wg-quick fallback ({}): {}",
                        conf_path.display(),
                        stdout.trim()
                    );
                    info!(%msg);
                    Ok(msg)
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    Err(format!("wg-quick fallback failed: {}", stderr.trim()))
                }
                Err(err) => Err(format!(
                    "Neither awg-quick nor wg-quick found: {err}. Install AmneziaWG tools or set AWG_UP_CMD."
                )),
            }
        }
    }
}

/// Bring down AmneziaWG tunnel interface
pub fn tunnel_down(conf_path: &Path, dry_run: bool) -> Result<String, String> {
    if dry_run {
        let msg = format!(
            "[DRY-RUN] Would execute: awg-quick down {}",
            conf_path.display()
        );
        info!(%msg);
        return Ok(msg);
    }

    if let Ok(custom_cmd) = std::env::var("AWG_DOWN_CMD") {
        return run_command_string(&custom_cmd, conf_path);
    }

    match Command::new("awg-quick")
        .arg("down")
        .arg(conf_path)
        .output()
    {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let msg = format!(
                "AmneziaWG tunnel deactivated via awg-quick: {}",
                stdout.trim()
            );
            info!(%msg);
            Ok(msg)
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // Fallback to wg-quick
            match Command::new("wg-quick").arg("down").arg(conf_path).output() {
                Ok(wg_out) if wg_out.status.success() => {
                    Ok("Tunnel deactivated via wg-quick fallback".to_string())
                }
                _ => Err(format!("awg-quick down failed: {}", stderr.trim())),
            }
        }
        Err(e) => match Command::new("wg-quick").arg("down").arg(conf_path).output() {
            Ok(out) if out.status.success() => {
                Ok("Tunnel deactivated via wg-quick fallback".to_string())
            }
            _ => Err(format!("Could not execute awg-quick/wg-quick down: {e}")),
        },
    }
}

/// Query tunnel telemetry via `awg show <iface>` or dump
pub fn tunnel_status(interface: &str) -> TunnelStatus {
    let output = Command::new("awg")
        .arg("show")
        .arg(interface)
        .arg("dump")
        .output()
        .or_else(|_| {
            Command::new("wg")
                .arg("show")
                .arg(interface)
                .arg("dump")
                .output()
        });

    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            parse_dump_telemetry(interface, &text)
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr);
            TunnelStatus {
                interface: interface.to_string(),
                active: false,
                rx_bytes: 0,
                tx_bytes: 0,
                latest_handshake_secs: 0,
                endpoint: None,
                message: format!("Interface inactive or unavailable: {}", err.trim()),
            }
        }
        Err(e) => TunnelStatus {
            interface: interface.to_string(),
            active: false,
            rx_bytes: 0,
            tx_bytes: 0,
            latest_handshake_secs: 0,
            endpoint: None,
            message: format!("Command 'awg/wg show' failed to execute: {e}"),
        },
    }
}

fn parse_dump_telemetry(interface: &str, dump: &str) -> TunnelStatus {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut rx = 0;
    let mut tx = 0;
    let mut handshake = 0;
    let mut endpoint = None;

    for line in dump.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // WireGuard peer dump: <pubkey> <psk> <endpoint> <allowed_ips> <latest_handshake> <rx_bytes> <tx_bytes> <keepalive>
        if parts.len() >= 7 && !parts[0].is_empty() {
            if parts[2] != "(none)" {
                endpoint = Some(parts[2].to_string());
            }
            handshake = parts[4].parse::<u64>().unwrap_or(0);
            rx = parts[5].parse::<u64>().unwrap_or(0);
            tx = parts[6].parse::<u64>().unwrap_or(0);
            break;
        }
    }

    let active = handshake > 0 && now.saturating_sub(handshake) <= 180;
    let message = if active {
        format!(
            "Connected (handshake {}s ago, rx: {} bytes, tx: {} bytes)",
            now.saturating_sub(handshake),
            rx,
            tx
        )
    } else if handshake > 0 {
        format!(
            "Handshake stale (last seen {}s ago)",
            now.saturating_sub(handshake)
        )
    } else {
        "Interface up, awaiting initial handshake".to_string()
    };

    TunnelStatus {
        interface: interface.to_string(),
        active,
        rx_bytes: rx,
        tx_bytes: tx,
        latest_handshake_secs: handshake,
        endpoint,
        message,
    }
}

fn run_command_string(cmd_template: &str, conf_path: &Path) -> Result<String, String> {
    let rendered = cmd_template.replace("{config}", &conf_path.to_string_lossy());
    let parts: Vec<&str> = rendered.split_whitespace().collect();
    if parts.is_empty() {
        return Err("Empty command".to_string());
    }
    let mut cmd = Command::new(parts[0]);
    if parts.len() > 1 {
        cmd.args(&parts[1..]);
    }
    match cmd.output() {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            Ok(stdout.trim().to_string())
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(format!(
                "Command failed with code {:?}: {}",
                out.status.code(),
                stderr.trim()
            ))
        }
        Err(e) => Err(format!("Failed to run command '{}': {e}", parts[0])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_generate_client_conf_formatting() {
        let config = AwgClientConfig {
            private_key: "test_client_priv_123".to_string(),
            address: "10.8.0.2/32".to_string(),
            dns: "10.8.0.1".to_string(),
            mtu: 1360,
            server_public_key: "test_server_pub_123".to_string(),
            server_endpoint: "proxy.corp.internal:51820".to_string(),
            preshared_key: Some("test_psk_123".to_string()),
            allowed_ips: "0.0.0.0/0, ::/0".to_string(),
            persistent_keepalive: 25,
            obfuscation: AwgObfuscationDto {
                jc: 5,
                jmin: 50,
                jmax: 80,
                s1: 20,
                s2: 30,
                h1: 11111111,
                h2: 22222222,
                h3: 33333333,
                h4: 44444444,
            },
        };

        let conf = config.generate_conf();
        assert!(conf.contains("[Interface]"));
        assert!(conf.contains("PrivateKey = test_client_priv_123"));
        assert!(conf.contains("Address = 10.8.0.2/32"));
        assert!(conf.contains("DNS = 10.8.0.1"));
        assert!(conf.contains("MTU = 1360"));
        assert!(conf.contains("Jc = 5"));
        assert!(conf.contains("Jmin = 50"));
        assert!(conf.contains("Jmax = 80"));
        assert!(conf.contains("S1 = 20"));
        assert!(conf.contains("S2 = 30"));
        assert!(conf.contains("H1 = 11111111"));
        assert!(conf.contains("H4 = 44444444"));

        assert!(conf.contains("[Peer]"));
        assert!(conf.contains("PublicKey = test_server_pub_123"));
        assert!(conf.contains("PresharedKey = test_psk_123"));
        assert!(conf.contains("Endpoint = proxy.corp.internal:51820"));
        assert!(conf.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        assert!(conf.contains("PersistentKeepalive = 25"));
    }

    #[test]
    fn test_atomic_save_and_permissions() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path();

        let content = "[Interface]\nPrivateKey = secret\n";
        save_atomic_0600(path, content).unwrap();

        let read_back = fs::read_to_string(path).unwrap();
        assert_eq!(read_back, content);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn test_dry_run_tunnel_commands() {
        let tmp = NamedTempFile::new().unwrap();
        let up_res = tunnel_up(tmp.path(), true).unwrap();
        assert!(up_res.contains("[DRY-RUN]"));
        assert!(up_res.contains("awg-quick up"));

        let down_res = tunnel_down(tmp.path(), true).unwrap();
        assert!(down_res.contains("[DRY-RUN]"));
        assert!(down_res.contains("awg-quick down"));
    }

    #[test]
    fn test_parse_dump_telemetry() {
        let dump = "serverpubkey\tpsk\t198.51.100.1:51820\t0.0.0.0/0\t1721812900\t1024\t2048\t25\n";
        let status = parse_dump_telemetry("awg0", dump);
        assert_eq!(status.interface, "awg0");
        assert_eq!(status.rx_bytes, 1024);
        assert_eq!(status.tx_bytes, 2048);
        assert_eq!(status.latest_handshake_secs, 1721812900);
        assert_eq!(status.endpoint, Some("198.51.100.1:51820".to_string()));
    }
}
