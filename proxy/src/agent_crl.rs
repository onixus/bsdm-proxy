//! Agent certificate revocation list (lab Phase C).
//!
//! Tracks revoked client-cert fingerprints (and serials when issued). Serves
//! JSON for ops and optional CA-signed X.509 CRL PEM for external consumers.

use crate::security_util::constant_time_eq;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

const FILE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrlEntry {
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    pub device_id: String,
    pub revoked_at: u64,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CrlFile {
    version: u32,
    crl_number: u64,
    entries: Vec<CrlEntry>,
}

/// In-memory + optional durable CRL.
#[derive(Clone)]
pub struct AgentCrl {
    entries: Arc<RwLock<Vec<CrlEntry>>>,
    path: Option<PathBuf>,
    crl_number: Arc<AtomicU64>,
}

impl Default for AgentCrl {
    fn default() -> Self {
        Self::memory_only()
    }
}

impl AgentCrl {
    pub fn memory_only() -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
            path: None,
            crl_number: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn from_env() -> Self {
        let path = std::env::var("AGENT_CRL_PATH")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        match path {
            Some(p) => match load(&p) {
                Ok((entries, number)) => {
                    info!(
                        path = %p.display(),
                        count = entries.len(),
                        crl_number = number,
                        "Loaded agent CRL"
                    );
                    Self {
                        entries: Arc::new(RwLock::new(entries)),
                        path: Some(p),
                        crl_number: Arc::new(AtomicU64::new(number.max(1))),
                    }
                }
                Err(e) => {
                    warn!(
                        path = %p.display(),
                        error = %e,
                        "Failed to load AGENT_CRL_PATH — starting empty"
                    );
                    Self {
                        entries: Arc::new(RwLock::new(Vec::new())),
                        path: Some(p),
                        crl_number: Arc::new(AtomicU64::new(1)),
                    }
                }
            },
            None => Self::memory_only(),
        }
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
            path: Some(path),
            crl_number: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn is_fingerprint_revoked(&self, fingerprint: &str) -> bool {
        if fingerprint.is_empty() {
            return false;
        }
        let fp = fingerprint.to_ascii_lowercase();
        let entries = self.entries.read().expect("crl lock");
        entries
            .iter()
            .any(|e| constant_time_eq(e.fingerprint.to_ascii_lowercase().as_bytes(), fp.as_bytes()))
    }

    pub fn is_serial_revoked(&self, serial_hex: &str) -> bool {
        if serial_hex.is_empty() {
            return false;
        }
        let s = serial_hex.to_ascii_lowercase();
        let entries = self.entries.read().expect("crl lock");
        entries.iter().any(|e| {
            e.serial_hex
                .as_ref()
                .is_some_and(|h| constant_time_eq(h.to_ascii_lowercase().as_bytes(), s.as_bytes()))
        })
    }

    pub fn entry_by_fingerprint(&self, fingerprint: &str) -> Option<CrlEntry> {
        if fingerprint.is_empty() {
            return None;
        }
        let fp = fingerprint.to_ascii_lowercase();
        let entries = self.entries.read().expect("crl lock");
        entries
            .iter()
            .find(|e| {
                constant_time_eq(e.fingerprint.to_ascii_lowercase().as_bytes(), fp.as_bytes())
            })
            .cloned()
    }

    pub fn entry_by_serial(&self, serial_hex: &str) -> Option<CrlEntry> {
        if serial_hex.is_empty() {
            return None;
        }
        let s = serial_hex.to_ascii_lowercase();
        let entries = self.entries.read().expect("crl lock");
        entries
            .iter()
            .find(|e| {
                e.serial_hex.as_ref().is_some_and(|h| {
                    constant_time_eq(h.to_ascii_lowercase().as_bytes(), s.as_bytes())
                })
            })
            .cloned()
    }

    /// Add a revocation entry (idempotent by fingerprint). Returns true if newly added.
    pub fn revoke(
        &self,
        device_id: &str,
        fingerprint: Option<&str>,
        serial_hex: Option<&str>,
        reason: &str,
    ) -> bool {
        let Some(fp) = fingerprint.map(str::trim).filter(|s| !s.is_empty()) else {
            return false;
        };
        let fp = fp.to_ascii_lowercase();
        let mut entries = self.entries.write().expect("crl lock");
        if entries
            .iter()
            .any(|e| constant_time_eq(e.fingerprint.as_bytes(), fp.as_bytes()))
        {
            return false;
        }
        entries.push(CrlEntry {
            fingerprint: fp,
            serial_hex: serial_hex
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_ascii_lowercase()),
            device_id: device_id.to_string(),
            revoked_at: unix_now(),
            reason: if reason.is_empty() {
                "unspecified".into()
            } else {
                reason.to_string()
            },
        });
        self.crl_number.fetch_add(1, Ordering::Relaxed);
        let number = self.crl_number.load(Ordering::Relaxed);
        info!(
            device_id,
            count = entries.len(),
            crl_number = number,
            "Agent cert added to CRL"
        );
        let _ = self.persist_locked(&entries, number);
        true
    }

    pub fn list(&self) -> Vec<CrlEntry> {
        self.entries.read().expect("crl lock").clone()
    }

    pub fn crl_number(&self) -> u64 {
        self.crl_number.load(Ordering::Relaxed)
    }

    pub fn to_json_document(&self) -> serde_json::Value {
        let entries = self.list();
        serde_json::json!({
            "version": FILE_VERSION,
            "crl_number": self.crl_number(),
            "count": entries.len(),
            "entries": entries,
            "updated_at": unix_now(),
        })
    }

    fn persist_locked(&self, entries: &[CrlEntry], crl_number: u64) -> bool {
        let Some(path) = self.path.as_ref() else {
            return false;
        };
        match save(path, entries, crl_number) {
            Ok(()) => true,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to persist agent CRL");
                false
            }
        }
    }
}

fn load(path: &Path) -> Result<(Vec<CrlEntry>, u64), String> {
    if !path.exists() {
        return Ok((Vec::new(), 1));
    }
    let raw = fs::read_to_string(path).map_err(|e| format!("read CRL: {e}"))?;
    if raw.trim().is_empty() {
        return Ok((Vec::new(), 1));
    }
    let file: CrlFile = serde_json::from_str(&raw).map_err(|e| format!("parse CRL: {e}"))?;
    if file.version != FILE_VERSION {
        return Err(format!(
            "unsupported CRL file version {} (expected {FILE_VERSION})",
            file.version
        ));
    }
    Ok((file.entries, file.crl_number.max(1)))
}

fn save(path: &Path, entries: &[CrlEntry], crl_number: u64) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("create CRL parent: {e}"))?;
        }
    }
    let file = CrlFile {
        version: FILE_VERSION,
        crl_number,
        entries: entries.to_vec(),
    };
    let payload = serde_json::to_vec_pretty(&file).map_err(|e| format!("serialize CRL: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp).map_err(|e| format!("create CRL tmp: {e}"))?;
        f.write_all(&payload)
            .map_err(|e| format!("write CRL tmp: {e}"))?;
        f.sync_all().map_err(|e| format!("sync CRL tmp: {e}"))?;
    }
    fs::rename(&tmp, path).map_err(|e| format!("rename CRL: {e}"))?;
    Ok(())
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

    #[test]
    fn revoke_and_lookup() {
        let crl = AgentCrl::memory_only();
        assert!(!crl.is_fingerprint_revoked("aabb"));
        assert!(crl.revoke("dev-1", Some("AaBb"), Some("0f"), "keyCompromise"));
        assert!(!crl.revoke("dev-1", Some("aabb"), None, "again")); // idempotent
        assert!(crl.is_fingerprint_revoked("AABB"));
        assert_eq!(crl.list().len(), 1);
        assert_eq!(crl.list()[0].serial_hex.as_deref(), Some("0f"));
    }

    #[test]
    fn round_trip_file() {
        let dir =
            std::env::temp_dir().join(format!("bsdm-crl-{}-{}", std::process::id(), unix_now()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("crl.json");
        let crl = AgentCrl::with_path(path.clone());
        crl.revoke("d1", Some("deadbeef"), Some("01"), "cessation");
        let (entries, number) = load(&path).unwrap();
        let loaded = AgentCrl {
            entries: Arc::new(RwLock::new(entries)),
            path: Some(path),
            crl_number: Arc::new(AtomicU64::new(number)),
        };
        assert!(loaded.is_fingerprint_revoked("deadbeef"));
        let _ = fs::remove_dir_all(&dir);
    }
}
