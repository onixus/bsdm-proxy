use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tracing::{info, warn};

/// Default timeout for external subprocess execution (preventing indefinite hangs)
pub const DEFAULT_CMD_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwgObfuscationDto {
    pub jc: u16,
    pub jmin: u16,
    pub jmax: u16,
    pub s1: u16,
    pub s2: u16,
    pub h1: u32,
    pub h2: u32,
    pub h3: u32,
    pub h4: u32,
}

impl Default for AwgObfuscationDto {
    fn default() -> Self {
        Self {
            jc: 4,
            jmin: 40,
            jmax: 70,
            s1: 15,
            s2: 25,
            h1: 1,
            h2: 2,
            h3: 3,
            h4: 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwgClientConfig {
    /// Client private key (Curve25519)
    pub private_key: String,
    /// Client tunnel IPv4/IPv6 address (e.g. 10.8.0.2/32)
    pub address: String,
    /// DNS servers pushed to client
    #[serde(default = "default_dns")]
    pub dns: String,
    /// Client MTU
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Server public key
    pub server_public_key: String,
    /// Server endpoint address (host:port)
    pub server_endpoint: String,
    /// Optional Pre-Shared Key (post-quantum / symmetric security)
    #[serde(default)]
    pub preshared_key: Option<String>,
    /// Allowed IP ranges routed through tunnel (default: 0.0.0.0/0, ::/0)
    #[serde(default = "default_allowed_ips")]
    pub allowed_ips: String,
    /// Persistent keepalive in seconds
    #[serde(default = "default_keepalive")]
    pub persistent_keepalive: u16,
    /// AmneziaWG obfuscation header parameters
    #[serde(default)]
    pub obfuscation: AwgObfuscationDto,
}

fn default_dns() -> String {
    "10.8.0.1".to_string()
}

fn default_mtu() -> u16 {
    1360
}

fn default_allowed_ips() -> String {
    "0.0.0.0/0, ::/0".to_string()
}

fn default_keepalive() -> u16 {
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
        if !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("create config dir {}: {e}", parent.display()))?;
        }
    }

    let tmp_path = format!("{}.tmp.{}", path.to_string_lossy(), std::process::id());
    let tmp = PathBuf::from(&tmp_path);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        let mut file = opts
            .open(&tmp)
            .map_err(|e| format!("open temp file {}: {e}", tmp.display()))?;
        use std::io::Write;
        file.write_all(content.as_bytes())
            .map_err(|e| format!("write temp file {}: {e}", tmp.display()))?;
    }

    #[cfg(not(unix))]
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        let mut file = opts
            .open(&tmp)
            .map_err(|e| format!("open temp file {}: {e}", tmp.display()))?;
        use std::io::Write;
        file.write_all(content.as_bytes())
            .map_err(|e| format!("write temp file {}: {e}", tmp.display()))?;
    }

    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("rename {} -> {}: {e}", tmp.display(), path.display())
    })?;

    Ok(())
}

/// Validates interface name against command injection attacks
pub fn validate_interface_name(name: &str) -> Result<(), String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("Interface name cannot be empty".to_string());
    }
    if trimmed.len() > 16 {
        return Err("Interface name cannot exceed 16 characters".to_string());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(
            "Interface name must contain only alphanumeric characters, underscores, or hyphens"
                .to_string(),
        );
    }
    Ok(())
}

/// Execute external command with strict timeout to prevent process hanging
pub fn run_command_with_timeout(
    cmd: &str,
    args: &[&OsStr],
    timeout: Duration,
) -> Result<Output, String> {
    let child = Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn {cmd}: {e}"))?;

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let res = child.wait_with_output();
        let _ = tx.send(res);
    });

    match rx.recv_timeout(timeout) {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(e)) => Err(format!("Command {cmd} execution failed: {e}")),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
            "Command {cmd} timed out after {}s",
            timeout.as_secs()
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(format!("Command {cmd} worker thread exited unexpectedly"))
        }
    }
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

/// Bring up AmneziaWG tunnel interface with timeout protection
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

    let conf_os = conf_path.as_os_str();
    match run_command_with_timeout(
        "awg-quick",
        &[OsStr::new("up"), conf_os],
        DEFAULT_CMD_TIMEOUT,
    ) {
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
            warn!("awg-quick not available ({e}); attempting wg-quick fallback");
            match run_command_with_timeout(
                "wg-quick",
                &[OsStr::new("up"), conf_os],
                DEFAULT_CMD_TIMEOUT,
            ) {
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
                    "Neither awg-quick nor wg-quick succeeded: {err}. Install AmneziaWG tools or set AWG_UP_CMD."
                )),
            }
        }
    }
}

/// Bring down AmneziaWG tunnel interface with timeout protection
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

    let conf_os = conf_path.as_os_str();
    match run_command_with_timeout(
        "awg-quick",
        &[OsStr::new("down"), conf_os],
        DEFAULT_CMD_TIMEOUT,
    ) {
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
            match run_command_with_timeout(
                "wg-quick",
                &[OsStr::new("down"), conf_os],
                DEFAULT_CMD_TIMEOUT,
            ) {
                Ok(wg_out) if wg_out.status.success() => {
                    Ok("Tunnel deactivated via wg-quick fallback".to_string())
                }
                _ => Err(format!("awg-quick down failed: {}", stderr.trim())),
            }
        }
        Err(e) => match run_command_with_timeout(
            "wg-quick",
            &[OsStr::new("down"), conf_os],
            DEFAULT_CMD_TIMEOUT,
        ) {
            Ok(out) if out.status.success() => {
                Ok("Tunnel deactivated via wg-quick fallback".to_string())
            }
            _ => Err(format!("Could not execute awg-quick/wg-quick down: {e}")),
        },
    }
}

/// Query tunnel telemetry via `awg show <iface>` or dump with validation
pub fn tunnel_status(interface: &str) -> TunnelStatus {
    if let Err(e) = validate_interface_name(interface) {
        return TunnelStatus {
            interface: interface.to_string(),
            active: false,
            rx_bytes: 0,
            tx_bytes: 0,
            latest_handshake_secs: 0,
            endpoint: None,
            message: format!("Invalid interface name: {e}"),
        };
    }

    let iface_os = OsStr::new(interface);
    let output = run_command_with_timeout(
        "awg",
        &[OsStr::new("show"), iface_os, OsStr::new("dump")],
        DEFAULT_CMD_TIMEOUT,
    )
    .or_else(|_| {
        run_command_with_timeout(
            "wg",
            &[OsStr::new("show"), iface_os, OsStr::new("dump")],
            DEFAULT_CMD_TIMEOUT,
        )
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
            message: format!("Command 'awg/wg show' failed: {e}"),
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
    let args: Vec<&OsStr> = parts[1..].iter().copied().map(OsStr::new).collect();
    match run_command_with_timeout(parts[0], &args, DEFAULT_CMD_TIMEOUT) {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            Ok(stdout.trim().to_string())
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(format!(
                "Custom command failed ({}): {}",
                out.status,
                stderr.trim()
            ))
        }
        Err(e) => Err(format!("Execute custom command error: {e}")),
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
    fn test_interface_name_validation() {
        assert!(validate_interface_name("awg0").is_ok());
        assert!(validate_interface_name("wg_corp-1").is_ok());
        assert!(validate_interface_name("").is_err());
        assert!(validate_interface_name("awg0; rm -rf /").is_err());
        assert!(validate_interface_name("awg0$(whoami)").is_err());
        assert!(validate_interface_name("toolonginterfacename12345").is_err());
    }

    #[test]
    fn test_atomic_save_and_permissions() {
        let tmp = NamedTempFile::new().unwrap();
        let content = "test_config_content_0600";
        save_atomic_0600(tmp.path(), content).unwrap();

        let read_back = fs::read_to_string(tmp.path()).unwrap();
        assert_eq!(read_back, content);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(tmp.path()).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn test_dry_run_tunnel_commands() {
        let tmp = NamedTempFile::new().unwrap();
        let up_res = tunnel_up(tmp.path(), true).unwrap();
        assert!(up_res.contains("[DRY-RUN]"));

        let down_res = tunnel_down(tmp.path(), true).unwrap();
        assert!(down_res.contains("[DRY-RUN]"));
    }

    #[test]
    fn test_parse_dump_telemetry() {
        let dump =
            "server_pub_key psk_key 192.168.1.100:51820 0.0.0.0/0 1700000000 1048576 2097152 25\n";
        let status = parse_dump_telemetry("awg0", dump);
        assert_eq!(status.interface, "awg0");
        assert_eq!(status.endpoint, Some("192.168.1.100:51820".to_string()));
        assert_eq!(status.rx_bytes, 1048576);
        assert_eq!(status.tx_bytes, 2097152);
        assert_eq!(status.latest_handshake_secs, 1700000000);
    }
}
