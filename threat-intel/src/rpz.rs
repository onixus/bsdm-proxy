//! TASK-TI-020 & TASK-TI-021: DNS RPZ Generator & Proxy ACL Threat Export.
//!
//! Compiles active high-confidence threat indicators into:
//! - Standard DNS Response Policy Zone (RPZ) zone files for `dns-sinkhole` (hot-reloaded).
//! - Plain and JSON threat lists for BSDM Proxy ACL policies.

use crate::config::EnforcementMode;
use chrono::Utc;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

/// DNS RPZ zone configuration.
#[derive(Debug, Clone)]
pub struct RpzConfig {
    #[allow(dead_code)]
    pub zone_name: String,
    pub primary_ns: String,
    pub admin_email: String,
    pub ttl_secs: u32,
    pub wildcard_subdomains: bool,
    /// Marks the zone as observe-only in its header (issue #330).
    pub shadow_mode: bool,
}

impl Default for RpzConfig {
    fn default() -> Self {
        Self {
            zone_name: "threats.rpz".to_string(),
            primary_ns: "ns1.bsdm-proxy.internal.".to_string(),
            admin_email: "hostmaster.bsdm-proxy.internal.".to_string(),
            ttl_secs: 300,
            wildcard_subdomains: true,
            shadow_mode: true,
        }
    }
}

/// Generates a valid BIND / RPZ zone file content from a list of domain names.
pub fn generate_rpz_zone(domains: &[String], config: &RpzConfig) -> String {
    let now = Utc::now();
    let serial = now.format("%Y%m%d%H").to_string();

    let mut out = String::with_capacity(domains.len() * 64 + 512);

    // RPZ Zone Header
    out.push_str(&format!("$TTL {}\n", config.ttl_secs));
    out.push_str(&format!(
        "@ IN SOA {} {} (\n  {} ; serial\n  3600 ; refresh\n  1800 ; retry\n  604800 ; expire\n  300 ; minimum TTL\n)\n",
        config.primary_ns, config.admin_email, serial
    ));
    out.push_str(&format!("@ IN NS {}\n\n", config.primary_ns));
    if config.shadow_mode {
        out.push_str(
            "; SHADOW MODE (TI_ENFORCEMENT_MODE=shadow): observe-only artifact.\n\
             ; Do NOT load this zone into dns-sinkhole; it blocks nothing by design.\n",
        );
    }
    out.push_str("; Active Threat Intelligence RPZ Rules\n");

    // Rules: NXDOMAIN block via CNAME .
    for domain in domains {
        let clean = domain.trim().trim_end_matches('.');
        if clean.is_empty() {
            continue;
        }
        out.push_str(&format!("{clean} CNAME .\n"));
        if config.wildcard_subdomains {
            out.push_str(&format!("*.{clean} CNAME .\n"));
        }
    }

    out
}

/// Atomically writes RPZ file to the filesystem.
pub fn write_rpz_file(
    output_path: impl AsRef<Path>,
    domains: &[String],
    config: &RpzConfig,
) -> std::io::Result<usize> {
    let output_path = output_path.as_ref();
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let content = generate_rpz_zone(domains, config);
    let tmp_path = output_path.with_extension("rpz.tmp");

    {
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
    }

    std::fs::rename(&tmp_path, output_path)?;
    Ok(domains.len())
}

/// Generates JSON formatted ACL threat list for BSDM Proxy policies.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyThreatFeed {
    pub generated_at: chrono::DateTime<Utc>,
    /// `shadow` (observe-only) or `enforce`.
    pub mode: String,
    pub domain_count: usize,
    pub domains: Vec<String>,
    /// Domain -> reporting feed, used to label shadow matches per feed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub feeds: BTreeMap<String, String>,
}

pub fn export_proxy_acl_feed(
    output_path: impl AsRef<Path>,
    domains: Vec<String>,
    mode: EnforcementMode,
    feeds: BTreeMap<String, String>,
) -> std::io::Result<()> {
    let output_path = output_path.as_ref();
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let feed = ProxyThreatFeed {
        generated_at: Utc::now(),
        mode: mode.as_str().to_string(),
        domain_count: domains.len(),
        domains,
        feeds,
    };

    let json = serde_json::to_vec_pretty(&feed)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let tmp_path = output_path.with_extension("json.tmp");
    {
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(&json)?;
        file.sync_all()?;
    }

    std::fs::rename(&tmp_path, output_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_rpz_zone() {
        let domains = vec!["evil.com".to_string(), "phish.org".to_string()];
        let config = RpzConfig::default();
        let zone = generate_rpz_zone(&domains, &config);

        assert!(zone.contains("$TTL 300"));
        assert!(zone.contains("evil.com CNAME ."));
        assert!(zone.contains("*.evil.com CNAME ."));
        assert!(zone.contains("phish.org CNAME ."));
        assert!(zone.contains("*.phish.org CNAME ."));
    }

    #[test]
    fn shadow_zone_carries_observe_only_banner() {
        let domains = vec!["evil.com".to_string()];
        let shadow = generate_rpz_zone(&domains, &RpzConfig::default());
        assert!(shadow.contains("SHADOW MODE"));

        let enforce_cfg = RpzConfig {
            shadow_mode: false,
            ..RpzConfig::default()
        };
        let enforced = generate_rpz_zone(&domains, &enforce_cfg);
        assert!(!enforced.contains("SHADOW MODE"));
        assert!(enforced.contains("evil.com CNAME ."));
    }

    #[test]
    fn acl_feed_records_mode_and_feed_labels() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("threat_domains.json.shadow");
        let mut feeds = BTreeMap::new();
        feeds.insert("evil.com".to_string(), "urlhaus".to_string());

        export_proxy_acl_feed(
            &target,
            vec!["evil.com".to_string()],
            EnforcementMode::Shadow,
            feeds,
        )
        .unwrap();

        let raw = std::fs::read_to_string(&target).unwrap();
        let feed: ProxyThreatFeed = serde_json::from_str(&raw).unwrap();
        assert_eq!(feed.mode, "shadow");
        assert_eq!(feed.domain_count, 1);
        assert_eq!(
            feed.feeds.get("evil.com").map(String::as_str),
            Some("urlhaus")
        );
    }

    #[test]
    fn test_write_rpz_file_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("threats.rpz");
        let domains = vec!["test-malware.com".to_string()];
        let config = RpzConfig::default();

        let count = write_rpz_file(&target, &domains, &config).unwrap();
        assert_eq!(count, 1);
        assert!(target.exists());

        let content = std::fs::read_to_string(&target).unwrap();
        assert!(content.contains("test-malware.com CNAME ."));
    }
}
