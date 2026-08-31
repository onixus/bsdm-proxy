//! TASK-TI-020 & TASK-TI-021: DNS RPZ Generator & Proxy ACL Threat Export.
//!
//! Compiles active high-confidence threat indicators into:
//! - Standard DNS Response Policy Zone (RPZ) zone files for `dns-sinkhole` (hot-reloaded).
//! - Plain and JSON threat lists for BSDM Proxy ACL policies.

use crate::config::EnforcementMode;
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// DNS RPZ zone configuration.
#[derive(Debug, Clone)]
pub struct RpzConfig {
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

/// Owner name of the record that marks a zone as an observe-only artifact.
///
/// `dns-sinkhole` treats a zone carrying it as unloadable — see
/// `dns-sinkhole/src/zone.rs`.
pub const SHADOW_MARKER_NAME: &str = "_bsdm-enforcement-mode";

/// Parses the SOA serial number from RPZ zone text if present.
pub fn parse_soa_serial(zone_content: &str) -> Option<u64> {
    for line in zone_content.lines() {
        let trimmed = line.trim();
        // Look for lines like "2026083100 ; serial" or containing "; serial"
        if let Some((before_comment, _)) = trimmed.split_once(';') {
            let candidate = before_comment.trim();
            if let Ok(serial) = candidate.parse::<u64>() {
                if serial >= 1_000_000_000 {
                    return Some(serial);
                }
            }
        }
    }
    None
}

/// Generates the next 10-digit monotonic serial (`YYYYMMDDNN`) adhering to BIND zone standards.
///
/// Format: `YYYYMMDDNN` where `NN` is a 2-digit counter (00..99) that increments for same-day
/// zone generations and never decreases across subsequent compilations.
pub fn next_monotonic_serial(prev_serial: Option<u64>, now: DateTime<Utc>) -> u64 {
    let date_str = now.format("%Y%m%d").to_string();
    let date_prefix: u64 = date_str.parse().unwrap_or(0);
    let base_today = date_prefix * 100; // YYYYMMDD00

    match prev_serial {
        Some(prev) => {
            if prev >= base_today {
                // Same day or clock anomaly: strictly increment
                prev + 1
            } else {
                // New day and previous serial was from past date
                base_today
            }
        }
        None => base_today,
    }
}

/// Computes the backup file path for a given RPZ zone file (`<path>.bak`).
pub fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".bak");
    PathBuf::from(name)
}

/// Generates a valid BIND / RPZ zone file content from a list of domain names with an explicit serial.
pub fn generate_rpz_zone_with_serial(
    domains: &[String],
    config: &RpzConfig,
    serial: u64,
) -> String {
    let mut out = String::with_capacity(domains.len() * 64 + 512);

    // RPZ Zone Header
    out.push_str(&format!("$TTL {}\n", config.ttl_secs));
    out.push_str(&format!(
        "@ IN SOA {} {} (\n  {} ; serial\n  3600 ; refresh\n  1800 ; retry\n  604800 ; expire\n  300 ; minimum TTL\n)\n",
        config.primary_ns, config.admin_email, serial
    ));
    out.push_str(&format!("@ IN NS {}\n\n", config.primary_ns));
    if config.shadow_mode {
        // The comment is for humans; a zone parser drops it. The TXT record below
        // is the machine-readable half — `dns-sinkhole` refuses to load a zone
        // carrying it, so the shadow artifact cannot become enforcement by way of
        // someone repointing DNS_SINKHOLE_ZONE_PATH (ADR 0008).
        out.push_str(
            "; SHADOW MODE (TI_ENFORCEMENT_MODE=shadow): observe-only artifact.\n\
             ; Do NOT load this zone into dns-sinkhole; it blocks nothing by design.\n",
        );
        out.push_str(&format!("{SHADOW_MARKER_NAME} IN TXT \"shadow\"\n"));
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

/// Generates a valid BIND / RPZ zone file content with default monotonic serial calculation.
pub fn generate_rpz_zone(domains: &[String], config: &RpzConfig) -> String {
    let serial = next_monotonic_serial(None, Utc::now());
    generate_rpz_zone_with_serial(domains, config, serial)
}

/// Checks whether an RPZ backup file exists for the specified zone path.
pub fn has_rpz_backup(zone_path: impl AsRef<Path>) -> bool {
    backup_path(zone_path.as_ref()).exists()
}

/// Atomically rolls back the active RPZ zone to the previous retained backup file (`.bak`).
/// Returns `Ok(true)` if rollback succeeded, or `Ok(false)` if no backup exists.
pub fn rollback_rpz_zone(zone_path: impl AsRef<Path>) -> std::io::Result<bool> {
    let zone_path = zone_path.as_ref();
    let bak_file = backup_path(zone_path);

    if !bak_file.exists() {
        return Ok(false);
    }

    let tmp_path = zone_path.with_extension("rollback.tmp");
    std::fs::copy(&bak_file, &tmp_path)?;
    std::fs::rename(&tmp_path, zone_path)?;
    Ok(true)
}

/// Atomically writes RPZ file to the filesystem, retaining a `.bak` backup of the previous active zone
/// and maintaining monotonic serial numbers.
pub fn write_rpz_file(
    output_path: impl AsRef<Path>,
    domains: &[String],
    config: &RpzConfig,
) -> std::io::Result<usize> {
    let output_path = output_path.as_ref();
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Read previous serial and create backup if active zone exists
    let prev_serial = if output_path.exists() {
        if let Ok(existing_content) = std::fs::read_to_string(output_path) {
            let bak_file = backup_path(output_path);
            let bak_tmp = output_path.with_extension("bak.tmp");
            if std::fs::copy(output_path, &bak_tmp).is_ok() {
                let _ = std::fs::rename(&bak_tmp, &bak_file);
            }
            parse_soa_serial(&existing_content)
        } else {
            None
        }
    } else {
        None
    };

    let serial = next_monotonic_serial(prev_serial, Utc::now());
    let content = generate_rpz_zone_with_serial(domains, config, serial);
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

/// Metadata and status report of the active DNS RPZ zone file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RpzStatus {
    pub zone_path: String,
    pub exists: bool,
    pub file_size_bytes: u64,
    pub modified_at: Option<chrono::DateTime<Utc>>,
    pub soa_serial: Option<u64>,
    pub domain_count: usize,
    pub is_shadow: bool,
    pub has_backup: bool,
    pub backup_soa_serial: Option<u64>,
}

/// Inspects the current on-disk RPZ file and returns its runtime status.
pub fn get_rpz_status(zone_path: impl AsRef<Path>) -> RpzStatus {
    let zone_path = zone_path.as_ref();
    let path_str = zone_path.to_string_lossy().to_string();
    if !zone_path.exists() {
        return RpzStatus {
            zone_path: path_str,
            exists: false,
            file_size_bytes: 0,
            modified_at: None,
            soa_serial: None,
            domain_count: 0,
            is_shadow: false,
            has_backup: false,
            backup_soa_serial: None,
        };
    }

    let meta = std::fs::metadata(zone_path).ok();
    let file_size_bytes = meta.as_ref().map(|m| m.len()).unwrap_or(0);
    let modified_at = meta
        .and_then(|m| m.modified().ok())
        .map(chrono::DateTime::<Utc>::from);

    let content = std::fs::read_to_string(zone_path).unwrap_or_default();
    let soa_serial = parse_soa_serial(&content);
    let is_shadow = content.contains(SHADOW_MARKER_NAME) || path_str.ends_with(".shadow");

    // Count domain CNAME records
    let domain_count = content
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.starts_with(';')
                && !t.starts_with('$')
                && !t.starts_with('@')
                && t.ends_with("CNAME .")
        })
        .count();

    let bak_path = backup_path(zone_path);
    let has_backup = bak_path.exists();
    let backup_soa_serial = if has_backup {
        std::fs::read_to_string(&bak_path)
            .ok()
            .and_then(|c| parse_soa_serial(&c))
    } else {
        None
    };

    RpzStatus {
        zone_path: path_str,
        exists: true,
        file_size_bytes,
        modified_at,
        soa_serial,
        domain_count,
        is_shadow,
        has_backup,
        backup_soa_serial,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn a_shadow_zone_carries_the_machine_readable_marker() {
        let domains = vec!["phish.test".to_string()];
        let shadow = generate_rpz_zone(&domains, &RpzConfig::default());
        assert!(
            shadow.contains(&format!("{SHADOW_MARKER_NAME} IN TXT \"shadow\"")),
            "dns-sinkhole refuses a zone by this record; without it the banner is \
             just a comment that any parser drops:\n{shadow}"
        );

        let enforce = generate_rpz_zone(
            &domains,
            &RpzConfig {
                shadow_mode: false,
                ..RpzConfig::default()
            },
        );
        assert!(!enforce.contains(SHADOW_MARKER_NAME));
    }

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
    fn test_monotonic_serial_progression() {
        let day1 = Utc.with_ymd_and_hms(2026, 8, 31, 10, 0, 0).unwrap();
        let day2 = Utc.with_ymd_and_hms(2026, 9, 1, 8, 0, 0).unwrap();

        // 1. Initial serial for day1
        let s0 = next_monotonic_serial(None, day1);
        assert_eq!(s0, 2026083100);

        // 2. Incremental runs on day1
        let s1 = next_monotonic_serial(Some(s0), day1);
        assert_eq!(s1, 2026083101);

        let s2 = next_monotonic_serial(Some(s1), day1);
        assert_eq!(s2, 2026083102);

        // 3. Next day start
        let s3 = next_monotonic_serial(Some(s2), day2);
        assert_eq!(s3, 2026090100);
        assert!(s3 > s2);

        // 4. Backward clock skew safety: must never decrease
        let skewed = next_monotonic_serial(Some(s3), day1);
        assert_eq!(skewed, 2026090101);
        assert!(skewed > s3);
    }

    #[test]
    fn test_parse_soa_serial() {
        let zone = "$TTL 300\n@ IN SOA ns1.test hostmaster.test (\n  2026083142 ; serial\n  3600 ; refresh\n)\n";
        assert_eq!(parse_soa_serial(zone), Some(2026083142));
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
    fn test_write_rpz_file_backup_and_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("threats.rpz");
        let config = RpzConfig::default();

        // 1. First write: generation 1
        let count = write_rpz_file(&target, &["v1-malware.com".to_string()], &config).unwrap();
        assert_eq!(count, 1);
        assert!(target.exists());
        assert!(!has_rpz_backup(&target));

        let c1 = std::fs::read_to_string(&target).unwrap();
        assert!(c1.contains("v1-malware.com CNAME ."));
        let serial1 = parse_soa_serial(&c1).unwrap();

        // 2. Second write: generation 2 (creates backup of v1)
        let count2 = write_rpz_file(&target, &["v2-phish.org".to_string()], &config).unwrap();
        assert_eq!(count2, 1);
        assert!(has_rpz_backup(&target));

        let c2 = std::fs::read_to_string(&target).unwrap();
        assert!(c2.contains("v2-phish.org CNAME ."));
        let serial2 = parse_soa_serial(&c2).unwrap();
        assert!(serial2 > serial1);

        // Verify backup contents match v1
        let bak = std::fs::read_to_string(backup_path(&target)).unwrap();
        assert!(bak.contains("v1-malware.com CNAME ."));

        // 3. Rollback active zone to backup
        let rolled_back = rollback_rpz_zone(&target).unwrap();
        assert!(rolled_back);

        let restored = std::fs::read_to_string(&target).unwrap();
        assert!(restored.contains("v1-malware.com CNAME ."));
        assert!(!restored.contains("v2-phish.org CNAME ."));
    }
}
