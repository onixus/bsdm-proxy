//! Hot-reloadable certificate-pinning exception registry with an append-only audit trail.

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_EXCEPTIONS: &str = ".slack.com,.teams.microsoft.com,.zoom.us";
const MAX_EXCEPTIONS: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PinningException {
    pub domain: String,
    pub reason: String,
    pub owner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
}

impl PinningException {
    fn active_at(&self, now: u64) -> bool {
        self.expires_at_unix.is_none_or(|expires| expires > now)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinningFile {
    version: u32,
    exceptions: Vec<PinningException>,
}

#[derive(Debug, Serialize)]
struct PinningAuditRecord<'a> {
    timestamp_unix: u64,
    actor: &'a str,
    change_reason: &'a str,
    action: &'a str,
    domain: &'a str,
    exception: &'a PinningException,
    source_path: &'a str,
}

#[derive(Debug, Serialize)]
pub struct PinningReloadReport {
    pub status: &'static str,
    pub source: String,
    pub active: usize,
    pub total: usize,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub updated: Vec<String>,
    pub audited_at: String,
}

struct PinningRegistryInner {
    entries: ArcSwap<Vec<PinningException>>,
    source_path: Option<PathBuf>,
    audit_path: Option<PathBuf>,
}

#[derive(Clone)]
pub struct PinningRegistry {
    inner: Arc<PinningRegistryInner>,
}

impl PinningRegistry {
    pub fn from_env() -> Result<Self, String> {
        if let Some(path) = std::env::var("PINNING_EXCEPTIONS_PATH")
            .ok()
            .filter(|value| !value.trim().is_empty())
        {
            let source_path = PathBuf::from(path);
            let entries = load_file(&source_path)?;
            let audit_path = std::env::var("PINNING_AUDIT_LOG_PATH")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| default_audit_path(&source_path));
            return Ok(Self::new(entries, Some(source_path), Some(audit_path)));
        }

        let entries = parse_legacy_env(
            &std::env::var("PINNING_EXCEPTIONS").unwrap_or_else(|_| DEFAULT_EXCEPTIONS.into()),
        )?;
        Ok(Self::new(entries, None, None))
    }

    pub fn from_entries(entries: Vec<PinningException>) -> Result<Self, String> {
        let entries = validate_entries(entries)?;
        Ok(Self::new(entries, None, None))
    }

    fn new(
        entries: Vec<PinningException>,
        source_path: Option<PathBuf>,
        audit_path: Option<PathBuf>,
    ) -> Self {
        Self {
            inner: Arc::new(PinningRegistryInner {
                entries: ArcSwap::from_pointee(entries),
                source_path,
                audit_path,
            }),
        }
    }

    pub fn matches(&self, domain: &str) -> bool {
        let Ok(domain) = normalize_domain(domain) else {
            return false;
        };
        let now = unix_now();
        self.inner.entries.load().iter().any(|entry| {
            entry.active_at(now)
                && if entry.domain.starts_with('.') {
                    domain == entry.domain.trim_start_matches('.')
                        || domain.ends_with(&entry.domain)
                } else {
                    domain == entry.domain
                }
        })
    }

    pub fn snapshot(&self) -> Vec<PinningException> {
        self.inner.entries.load().as_ref().clone()
    }

    pub fn active_domains(&self) -> Vec<String> {
        let now = unix_now();
        self.inner
            .entries
            .load()
            .iter()
            .filter(|entry| entry.active_at(now))
            .map(|entry| entry.domain.clone())
            .collect()
    }

    pub fn source(&self) -> String {
        self.inner
            .source_path
            .as_deref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "environment".into())
    }

    pub fn audit_path(&self) -> Option<String> {
        self.inner
            .audit_path
            .as_deref()
            .map(|path| path.display().to_string())
    }

    pub fn reload(&self, actor: &str, change_reason: &str) -> Result<PinningReloadReport, String> {
        validate_audit_text("actor", actor, 128)?;
        validate_audit_text("reason", change_reason, 512)?;
        let source_path = self
            .inner
            .source_path
            .as_deref()
            .ok_or_else(|| "PINNING_EXCEPTIONS_PATH is not configured".to_string())?;
        let audit_path = self
            .inner
            .audit_path
            .as_deref()
            .ok_or_else(|| "PINNING_AUDIT_LOG_PATH is not configured".to_string())?;
        let next = load_file(source_path)?;
        let previous = self.snapshot();

        let old_by_domain: BTreeMap<_, _> = previous
            .iter()
            .map(|entry| (entry.domain.as_str(), entry))
            .collect();
        let new_by_domain: BTreeMap<_, _> = next
            .iter()
            .map(|entry| (entry.domain.as_str(), entry))
            .collect();
        let old_domains: BTreeSet<_> = old_by_domain.keys().copied().collect();
        let new_domains: BTreeSet<_> = new_by_domain.keys().copied().collect();
        let added: Vec<String> = new_domains
            .difference(&old_domains)
            .map(|domain| (*domain).to_string())
            .collect();
        let removed: Vec<String> = old_domains
            .difference(&new_domains)
            .map(|domain| (*domain).to_string())
            .collect();
        let updated: Vec<String> = old_domains
            .intersection(&new_domains)
            .filter(|domain| old_by_domain.get(**domain) != new_by_domain.get(**domain))
            .map(|domain| (*domain).to_string())
            .collect();

        append_audit(
            audit_path,
            source_path,
            actor,
            change_reason,
            &added,
            &removed,
            &updated,
            &old_by_domain,
            &new_by_domain,
        )?;
        self.inner.entries.store(Arc::new(next.clone()));

        let now = unix_now();
        Ok(PinningReloadReport {
            status: "reloaded",
            source: source_path.display().to_string(),
            active: next.iter().filter(|entry| entry.active_at(now)).count(),
            total: next.len(),
            added,
            removed,
            updated,
            audited_at: audit_path.display().to_string(),
        })
    }
}

fn load_file(path: &Path) -> Result<Vec<PinningException>, String> {
    let file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let parsed: PinningFile = serde_json::from_reader(BufReader::new(file))
        .map_err(|e| format!("parse {}: {e}", path.display()))?;
    if parsed.version != 1 {
        return Err(format!(
            "unsupported pinning exception file version {}",
            parsed.version
        ));
    }
    validate_entries(parsed.exceptions)
}

fn parse_legacy_env(value: &str) -> Result<Vec<PinningException>, String> {
    validate_entries(
        value
            .split(',')
            .map(str::trim)
            .filter(|domain| !domain.is_empty())
            .map(|domain| PinningException {
                domain: domain.to_string(),
                reason: "legacy PINNING_EXCEPTIONS configuration".into(),
                owner: "operator".into(),
                ticket: None,
                expires_at_unix: None,
            })
            .collect(),
    )
}

fn validate_entries(mut entries: Vec<PinningException>) -> Result<Vec<PinningException>, String> {
    if entries.len() > MAX_EXCEPTIONS {
        return Err(format!(
            "too many pinning exceptions (max {MAX_EXCEPTIONS})"
        ));
    }
    let mut seen = BTreeSet::new();
    for entry in &mut entries {
        entry.domain = normalize_domain(&entry.domain)?;
        validate_audit_text("exception reason", &entry.reason, 512)?;
        validate_audit_text("exception owner", &entry.owner, 128)?;
        if let Some(ticket) = &entry.ticket {
            validate_audit_text("exception ticket", ticket, 128)?;
        }
        if !seen.insert(entry.domain.clone()) {
            return Err(format!("duplicate pinning exception: {}", entry.domain));
        }
    }
    entries.sort_by(|left, right| left.domain.cmp(&right.domain));
    Ok(entries)
}

fn normalize_domain(value: &str) -> Result<String, String> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let body = value.strip_prefix('.').unwrap_or(&value);
    if body.is_empty() || body.len() > 253 || !body.contains('.') {
        return Err(format!("invalid pinning exception domain: {value}"));
    }
    if value.contains('/') || value.contains(':') || value.contains('*') || !value.is_ascii() {
        return Err(format!("invalid pinning exception domain: {value}"));
    }
    if body.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    }) {
        return Err(format!("invalid pinning exception domain: {value}"));
    }
    Ok(value)
}

fn validate_audit_text(field: &str, value: &str, max: usize) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(format!("{field} must be 1..={max} printable characters"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn append_audit(
    audit_path: &Path,
    source_path: &Path,
    actor: &str,
    change_reason: &str,
    added: &[String],
    removed: &[String],
    updated: &[String],
    old_by_domain: &BTreeMap<&str, &PinningException>,
    new_by_domain: &BTreeMap<&str, &PinningException>,
) -> Result<(), String> {
    if added.is_empty() && removed.is_empty() && updated.is_empty() {
        return Ok(());
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(audit_path)
        .map_err(|e| format!("open audit log {}: {e}", audit_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("secure audit log {}: {e}", audit_path.display()))?;
    }
    let source = source_path.display().to_string();
    for (action, domains, entries) in [
        ("added", added, new_by_domain),
        ("removed", removed, old_by_domain),
        ("updated", updated, new_by_domain),
    ] {
        for domain in domains {
            let entry = entries
                .get(domain.as_str())
                .ok_or_else(|| format!("missing audit entry for {domain}"))?;
            serde_json::to_writer(
                &mut file,
                &PinningAuditRecord {
                    timestamp_unix: unix_now(),
                    actor,
                    change_reason,
                    action,
                    domain,
                    exception: entry,
                    source_path: &source,
                },
            )
            .map_err(|e| format!("serialize audit record: {e}"))?;
            file.write_all(b"\n")
                .map_err(|e| format!("write audit log {}: {e}", audit_path.display()))?;
        }
    }
    file.sync_data()
        .map_err(|e| format!("sync audit log {}: {e}", audit_path.display()))
}

fn default_audit_path(source_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.audit.jsonl", source_path.display()))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(domain: &str) -> PinningException {
        PinningException {
            domain: domain.into(),
            reason: "vendor pins its certificate".into(),
            owner: "network-security".into(),
            ticket: Some("SEC-42".into()),
            expires_at_unix: None,
        }
    }

    #[test]
    fn exact_and_suffix_matching_are_explicit() {
        let registry = PinningRegistry::from_entries(vec![
            entry("login.example.com"),
            entry(".video.example.org"),
        ])
        .unwrap();
        assert!(registry.matches("login.example.com"));
        assert!(!registry.matches("x.login.example.com"));
        assert!(registry.matches("video.example.org"));
        assert!(registry.matches("cdn.video.example.org"));
        assert!(!registry.matches("evilvideo.example.org"));
    }

    #[test]
    fn rejects_unsafe_and_duplicate_domains() {
        assert!(PinningRegistry::from_entries(vec![entry("https://example.com")]).is_err());
        assert!(PinningRegistry::from_entries(vec![entry("*.example.com")]).is_err());
        assert!(PinningRegistry::from_entries(vec![
            entry("a.example.com"),
            entry("A.EXAMPLE.COM")
        ])
        .is_err());
    }

    #[test]
    fn expired_entries_do_not_bypass_mitm() {
        let mut expired = entry("expired.example.com");
        expired.expires_at_unix = Some(1);
        let registry = PinningRegistry::from_entries(vec![expired]).unwrap();
        assert!(!registry.matches("expired.example.com"));
        assert!(registry.active_domains().is_empty());
        assert_eq!(registry.snapshot().len(), 1);
    }

    #[test]
    fn reloads_file_and_writes_audit_records() {
        let unique = format!("bsdm-pinning-{}-{}", std::process::id(), unix_now());
        let source = std::env::temp_dir().join(format!("{unique}.json"));
        let audit = std::env::temp_dir().join(format!("{unique}.audit.jsonl"));
        std::fs::write(
            &source,
            r#"{"version":1,"exceptions":[{"domain":"one.example.com","reason":"temporary","owner":"qa"},{"domain":"remove.example.com","reason":"obsolete","owner":"qa"}]}"#,
        )
        .unwrap();
        let registry = PinningRegistry::new(
            load_file(&source).unwrap(),
            Some(source.clone()),
            Some(audit.clone()),
        );
        let live_clone = registry.clone();
        std::fs::write(
            &source,
            r#"{"version":1,"exceptions":[{"domain":"one.example.com","reason":"approved","owner":"security"},{"domain":".two.example.com","reason":"approved","owner":"security"}]}"#,
        )
        .unwrap();

        let report = registry.reload("alice", "SEC-99 approved").unwrap();
        assert_eq!(report.added, vec![".two.example.com"]);
        assert_eq!(report.removed, vec!["remove.example.com"]);
        assert_eq!(report.updated, vec!["one.example.com"]);
        assert!(live_clone.matches("cdn.two.example.com"));
        let audit_body = std::fs::read_to_string(&audit).unwrap();
        assert!(audit_body.contains(r#""actor":"alice""#));
        assert!(audit_body.contains(r#""action":"added""#));
        assert!(audit_body.contains(r#""action":"removed""#));
        assert!(audit_body.contains(r#""action":"updated""#));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(audit);
    }
}
