//! Local Domain-Based Routing Engine for BSDM Agent & BSDM Connect
//! Evaluates domain routing targets: Direct, Proxy, Tunnel, or Block.
//! Enforces input sanitization, bounds checking, and atomic persistence.

use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use tracing::info;

/// Maximum number of domain routing rules allowed to prevent memory exhaustion
pub const MAX_RULES: usize = 1000;

/// Maximum length of a single pattern string
pub const MAX_PATTERN_LEN: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteTarget {
    /// Connect directly bypassing all proxies and tunnels
    Direct,
    /// Steer traffic through BSDM HTTP/HTTPS Forward Proxy
    Proxy,
    /// Steer traffic through AmneziaWG VPN Tunnel
    Tunnel,
    /// Block request locally (sinkhole)
    Block,
}

impl std::fmt::Display for RouteTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteTarget::Direct => write!(f, "direct"),
            RouteTarget::Proxy => write!(f, "proxy"),
            RouteTarget::Tunnel => write!(f, "tunnel"),
            RouteTarget::Block => write!(f, "block"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRule {
    pub id: String,
    pub pattern: String,
    pub target: RouteTarget,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub comment: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteTable {
    #[serde(default = "default_target_proxy")]
    pub default_target: RouteTarget,
    #[serde(default)]
    pub rules: Vec<RouteRule>,
}

fn default_target_proxy() -> RouteTarget {
    RouteTarget::Proxy
}

impl Default for RouteTable {
    fn default() -> Self {
        Self::default_corporate()
    }
}

impl RouteTable {
    /// Create a standard corporate split-routing preset
    pub fn default_corporate() -> Self {
        Self {
            default_target: RouteTarget::Direct,
            rules: vec![
                RouteRule {
                    id: "rule-local-direct".to_string(),
                    pattern: "localhost; 127.0.0.1; *.local; 10.0.0.0/8; 192.168.0.0/16"
                        .to_string(),
                    target: RouteTarget::Direct,
                    enabled: true,
                    comment: Some("Local network bypass".to_string()),
                },
                RouteRule {
                    id: "rule-corp-vpn".to_string(),
                    pattern: "*.vpn.corp; *.secure.internal".to_string(),
                    target: RouteTarget::Tunnel,
                    enabled: true,
                    comment: Some("High-security services via AmneziaWG Tunnel".to_string()),
                },
                RouteRule {
                    id: "rule-corp-intranet".to_string(),
                    pattern: "*.corp; *.internal; *.company.com".to_string(),
                    target: RouteTarget::Proxy,
                    enabled: true,
                    comment: Some("Corporate services through BSDM Proxy".to_string()),
                },
                RouteRule {
                    id: "rule-block-telemetry".to_string(),
                    pattern: "telemetry.evil.com; *.tracking.test".to_string(),
                    target: RouteTarget::Block,
                    enabled: true,
                    comment: Some("Local sinkhole for tracker domains".to_string()),
                },
            ],
        }
    }

    /// Evaluate domain against routing rules.
    /// Returns the target of the first matching enabled rule, or `self.default_target`.
    pub fn evaluate(&self, host: &str) -> RouteTarget {
        let clean_host = host.trim().to_ascii_lowercase();
        let host_without_port = clean_host.split(':').next().unwrap_or(&clean_host);

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            for single_pat in rule.pattern.split(&[';', ','][..]) {
                let pat = single_pat.trim().to_ascii_lowercase();
                if pat.is_empty() {
                    continue;
                }
                if match_pattern(&pat, host_without_port) {
                    return rule.target;
                }
            }
        }

        self.default_target
    }

    /// Add or update a rule by ID with pattern validation and capacity bounds
    pub fn upsert_rule(&mut self, rule: RouteRule) -> Result<(), String> {
        validate_pattern(&rule.pattern)?;

        if let Some(pos) = self.rules.iter().position(|r| r.id == rule.id) {
            self.rules[pos] = rule;
        } else {
            if self.rules.len() >= MAX_RULES {
                return Err(format!(
                    "Maximum route table capacity reached ({MAX_RULES} rules)"
                ));
            }
            self.rules.push(rule);
        }
        Ok(())
    }

    /// Remove a rule by ID
    pub fn remove_rule(&mut self, id: &str) -> bool {
        let initial_len = self.rules.len();
        self.rules.retain(|r| r.id != id);
        self.rules.len() < initial_len
    }

    /// Save route table to JSON file with atomic write
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json =
            serde_json::to_string_pretty(self).map_err(|e| format!("route serialize: {e}"))?;
        crate::tunnel::save_atomic_0600(path, &json)?;
        info!(path = %path.display(), "Saved domain route table");
        Ok(())
    }

    /// Load route table from JSON file, returning defaults if not existing
    pub fn load_or_default(path: &Path) -> Self {
        if path.exists() {
            match fs::read_to_string(path) {
                Ok(text) => match serde_json::from_str::<Self>(&text) {
                    Ok(table) => return table,
                    Err(e) => {
                        info!(path = %path.display(), "Could not parse routes: {e}; using defaults")
                    }
                },
                Err(e) => {
                    info!(path = %path.display(), "Could not read routes: {e}; using defaults")
                }
            }
        }
        Self::default_corporate()
    }
}

/// Validates rule domain pattern
pub fn validate_pattern(pattern: &str) -> Result<(), String> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return Err("Pattern cannot be empty".to_string());
    }
    if trimmed.len() > MAX_PATTERN_LEN {
        return Err(format!(
            "Pattern exceeds maximum length of {MAX_PATTERN_LEN} characters"
        ));
    }

    for chunk in trimmed.split(&[';', ','][..]) {
        let pat = chunk.trim();
        if pat.is_empty() {
            continue;
        }
        if pat.contains('\0') || pat.chars().any(|c| c.is_control()) {
            return Err("Pattern contains illegal control or null characters".to_string());
        }

        if pat.contains('/') {
            // Check CIDR format
            if let Some((ip_str, mask_str)) = pat.split_once('/') {
                if ip_str.parse::<IpAddr>().is_err() {
                    return Err(format!("Invalid IP address in CIDR pattern: {ip_str}"));
                }
                match mask_str.parse::<u8>() {
                    Ok(mask) if mask <= 128 => {}
                    _ => return Err(format!("Invalid mask length in CIDR pattern: {mask_str}")),
                }
            }
        } else if pat.len() > 253 {
            return Err(format!(
                "Domain pattern chunk exceeds 253 characters: {pat}"
            ));
        }
    }

    Ok(())
}

/// Matches hostname against wildcard or suffix patterns
fn match_pattern(pattern: &str, host: &str) -> bool {
    if pattern == "*" || pattern == host {
        return true;
    }

    // Exact wildcard prefix (e.g. *.example.com)
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if host == suffix || host.ends_with(&format!(".{suffix}")) {
            return true;
        }
    }

    // Leading dot wildcard (e.g. .example.com)
    if let Some(suffix) = pattern.strip_prefix('.') {
        if host == suffix || host.ends_with(&format!(".{suffix}")) {
            return true;
        }
    }

    // Wildcard suffix (e.g. corp.*)
    if let Some(prefix) = pattern.strip_suffix(".*") {
        if host == prefix || host.starts_with(&format!("{prefix}.")) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_route_table_evaluation() {
        let table = RouteTable::default_corporate();

        // Local network
        assert_eq!(table.evaluate("localhost"), RouteTarget::Direct);
        assert_eq!(table.evaluate("127.0.0.1"), RouteTarget::Direct);
        assert_eq!(table.evaluate("printer.local"), RouteTarget::Direct);

        // High security -> Tunnel
        assert_eq!(table.evaluate("db.vpn.corp"), RouteTarget::Tunnel);
        assert_eq!(table.evaluate("vault.secure.internal"), RouteTarget::Tunnel);

        // Corporate Intranet -> Proxy
        assert_eq!(table.evaluate("wiki.corp"), RouteTarget::Proxy);
        assert_eq!(table.evaluate("portal.internal"), RouteTarget::Proxy);
        assert_eq!(table.evaluate("mail.company.com"), RouteTarget::Proxy);

        // Tracker -> Block
        assert_eq!(table.evaluate("telemetry.evil.com"), RouteTarget::Block);
        assert_eq!(table.evaluate("ads.tracking.test"), RouteTarget::Block);

        // Public internet -> default Direct
        assert_eq!(table.evaluate("github.com"), RouteTarget::Direct);
        assert_eq!(table.evaluate("rust-lang.org"), RouteTarget::Direct);
    }

    #[test]
    fn test_pattern_validation() {
        assert!(validate_pattern("*.corp.internal; 10.0.0.0/8").is_ok());
        assert!(validate_pattern("").is_err());
        assert!(validate_pattern("invalid/ip/address/33").is_err());
        assert!(validate_pattern("10.0.0.1/300").is_err());
        assert!(validate_pattern("test\0domain.com").is_err());
        assert!(validate_pattern("test\x1b[31mdomain.com").is_err());
    }

    #[test]
    fn test_route_save_and_load() {
        let tmp = NamedTempFile::new().unwrap();
        let mut table = RouteTable::default_corporate();
        table
            .upsert_rule(RouteRule {
                id: "custom-rule-1".to_string(),
                pattern: "*.mycustomsite.org".to_string(),
                target: RouteTarget::Tunnel,
                enabled: true,
                comment: Some("Custom tunnel rule".to_string()),
            })
            .unwrap();

        table.save(tmp.path()).unwrap();

        let loaded = RouteTable::load_or_default(tmp.path());
        assert_eq!(loaded.evaluate("app.mycustomsite.org"), RouteTarget::Tunnel);
    }
}
