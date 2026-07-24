use serde::{Deserialize, Serialize};

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
        }
    }
}

/// AmneziaWG Peer (Client) Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwgPeerConfig {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub private_key: Option<String>,
    pub allowed_ips: String,
    pub assigned_ip: String,
    pub created_at: String,
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

#[cfg(test)]
mod tests {
    use super::*;

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
        };

        let conf = generate_client_conf("srvpub123", "proxy.corp.com:51820", &peer, &obf, "privkey123");
        assert!(conf.contains("PrivateKey = privkey123"));
        assert!(conf.contains("Address = 10.8.0.2/32"));
        assert!(conf.contains("PublicKey = srvpub123"));
        assert!(conf.contains("Endpoint = proxy.corp.com:51820"));
        assert!(conf.contains("Jc = 4"));
        assert!(conf.contains("H1 = 10000001"));
    }
}
