//! Agent device inventory (Phase C).
//!
//! Cohesive in-memory map with optional durable JSON path
//! (`AGENT_DEVICES_PATH`). Heartbeats merge into the map; revoke marks
//! devices; both rewrite the file when persistence is configured.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

const FILE_VERSION: u32 = 1;
const MAX_DEVICES: usize = 10_000;
const POLICY_VERSION: &str = "v0.1.0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisteredDevice {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub ip: String,
    pub device_type: String,
    pub agent_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_score: Option<u8>,
    pub last_seen: u64,
    #[serde(default)]
    pub revoked: bool,
}

impl RegisteredDevice {
    /// Trust-UI / Admin Console row shape for `GET /api/v1/devices`.
    pub fn to_api_row(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "name": self.name,
            "ip": self.ip,
            "type": self.device_type,
            "status": if self.revoked {
                "Revoked"
            } else if self.agent_status.eq_ignore_ascii_case("healthy") {
                "Secured"
            } else {
                "Flagged"
            },
            "connection": self.last_seen.to_string(),
            "lastSeen": self.last_seen,
            "agentStatus": self.agent_status,
            "agentVersion": self.agent_version,
            "policyVersion": self.policy_version,
            "certSubject": self.cert_subject,
            "certFingerprint": self.cert_fingerprint,
            "trustScore": self.trust_score,
        })
    }
}

/// Fields accepted by `POST /api/v1/agent/heartbeat` (validated by caller).
#[derive(Debug, Clone)]
pub struct HeartbeatUpdate {
    pub device_id: String,
    pub status: Option<String>,
    pub agent_version: Option<String>,
    pub policy_version: Option<String>,
    pub name: Option<String>,
    pub ip: Option<String>,
    pub device_type: Option<String>,
    pub cert_subject: Option<String>,
    pub cert_fingerprint: Option<String>,
    pub trust_score: Option<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HeartbeatError {
    EmptyDeviceId,
    InvalidTrustScore,
}

impl HeartbeatError {
    pub fn message(&self) -> &'static str {
        match self {
            HeartbeatError::EmptyDeviceId => "device_id must not be empty",
            HeartbeatError::InvalidTrustScore => "trust_score must be between 0 and 100",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RevokeError {
    InvalidId,
    NotFound,
}

impl RevokeError {
    pub fn message(&self) -> &'static str {
        match self {
            RevokeError::InvalidId => "invalid device id",
            RevokeError::NotFound => "device not found",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DevicesFile {
    version: u32,
    devices: Vec<RegisteredDevice>,
}

/// Runtime registry: map + optional durable path.
#[derive(Clone)]
pub struct DeviceRegistry {
    devices: Arc<RwLock<HashMap<String, RegisteredDevice>>>,
    path: Option<PathBuf>,
}

impl Default for DeviceRegistry {
    fn default() -> Self {
        Self::memory_only()
    }
}

impl DeviceRegistry {
    pub fn memory_only() -> Self {
        Self {
            devices: Arc::new(RwLock::new(HashMap::new())),
            path: None,
        }
    }

    /// Load from `AGENT_DEVICES_PATH` when set; otherwise memory-only.
    pub fn from_env() -> Self {
        let Some(path) = path_from_env() else {
            return Self::memory_only();
        };
        match load(&path) {
            Ok(loaded) => {
                info!(
                    path = %path.display(),
                    count = loaded.len(),
                    "Agent device registry ready"
                );
                Self {
                    devices: Arc::new(RwLock::new(loaded)),
                    path: Some(path),
                }
            }
            Err(error) => {
                warn!(
                    path = %path.display(),
                    error = %error,
                    "Failed to load AGENT_DEVICES_PATH — continuing empty (path kept for writes)"
                );
                Self {
                    devices: Arc::new(RwLock::new(HashMap::new())),
                    path: Some(path),
                }
            }
        }
    }

    /// Test helper: empty registry that persists to `path`.
    pub fn with_path(path: PathBuf) -> Self {
        Self {
            devices: Arc::new(RwLock::new(HashMap::new())),
            path: Some(path),
        }
    }

    /// Test helper: seed devices and optional path.
    pub fn from_map(map: HashMap<String, RegisteredDevice>, path: Option<PathBuf>) -> Self {
        Self {
            devices: Arc::new(RwLock::new(map)),
            path,
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn is_persistent(&self) -> bool {
        self.path.is_some()
    }

    /// Merge heartbeat into the registry. Returns whether a durable write succeeded.
    pub fn apply_heartbeat(&self, hb: HeartbeatUpdate) -> Result<bool, HeartbeatError> {
        if hb.device_id.trim().is_empty() {
            return Err(HeartbeatError::EmptyDeviceId);
        }
        if hb.trust_score.is_some_and(|score| score > 100) {
            return Err(HeartbeatError::InvalidTrustScore);
        }

        let mut devices = self.devices.write().expect("device registry lock");
        let previous = devices.get(&hb.device_id);
        let device = RegisteredDevice {
            id: hb.device_id.clone(),
            name: hb
                .name
                .filter(|name| !name.trim().is_empty())
                .or_else(|| previous.map(|d| d.name.clone()))
                .unwrap_or_else(|| hb.device_id.clone()),
            ip: hb
                .ip
                .or_else(|| previous.map(|d| d.ip.clone()))
                .unwrap_or_default(),
            device_type: hb
                .device_type
                .filter(|kind| matches!(kind.as_str(), "desktop" | "phone"))
                .or_else(|| previous.map(|d| d.device_type.clone()))
                .unwrap_or_else(|| "desktop".to_string()),
            agent_status: hb.status.unwrap_or_else(|| "healthy".to_string()),
            agent_version: hb
                .agent_version
                .or_else(|| previous.and_then(|d| d.agent_version.clone())),
            policy_version: hb
                .policy_version
                .or_else(|| previous.and_then(|d| d.policy_version.clone())),
            cert_subject: hb
                .cert_subject
                .or_else(|| previous.and_then(|d| d.cert_subject.clone())),
            cert_fingerprint: hb
                .cert_fingerprint
                .or_else(|| previous.and_then(|d| d.cert_fingerprint.clone())),
            trust_score: hb
                .trust_score
                .or_else(|| previous.and_then(|d| d.trust_score)),
            last_seen: unix_now(),
            revoked: previous.is_some_and(|d| d.revoked),
        };
        info!(
            device_id = %device.id,
            status = %device.agent_status,
            agent_version = ?device.agent_version,
            "Agent heartbeat received"
        );
        devices.insert(device.id.clone(), device);
        Ok(self.persist_locked(&devices))
    }

    pub fn revoke(&self, device_id: &str) -> Result<bool, RevokeError> {
        if device_id.is_empty() || device_id.contains('/') {
            return Err(RevokeError::InvalidId);
        }
        let mut devices = self.devices.write().expect("device registry lock");
        let Some(device) = devices.get_mut(device_id) else {
            return Err(RevokeError::NotFound);
        };
        device.revoked = true;
        warn!(device_id, "Device trust revoked");
        Ok(self.persist_locked(&devices))
    }

    /// Devices sorted by `last_seen` descending (API list order).
    pub fn list_api_rows(&self) -> Vec<serde_json::Value> {
        let devices = self.devices.read().expect("device registry lock");
        let mut rows: Vec<_> = devices.values().map(RegisteredDevice::to_api_row).collect();
        rows.sort_by_key(|row| std::cmp::Reverse(row["lastSeen"].as_u64().unwrap_or(0)));
        rows
    }

    fn persist_locked(&self, devices: &HashMap<String, RegisteredDevice>) -> bool {
        let Some(path) = self.path.as_ref() else {
            return false;
        };
        match save(path, devices) {
            Ok(()) => true,
            Err(error) => {
                warn!(
                    path = %path.display(),
                    error = %error,
                    "Failed to persist agent device registry"
                );
                false
            }
        }
    }
}

// --- Agent Contract policy helpers (shared with control plane) ---

/// Comma-separated SNI deny patterns for Agent Contract policy pull.
/// Env: `AGENT_SNI_DENY_PATTERNS`. Unset → pilot lab defaults.
pub fn sni_deny_patterns_from_env() -> Vec<String> {
    match std::env::var("AGENT_SNI_DENY_PATTERNS") {
        Ok(raw) if !raw.trim().is_empty() => raw
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_string)
            .collect(),
        _ => vec!["*.evil.com".to_string(), "badsite.test".to_string()],
    }
}

/// Build `GET /api/v1/agent/policy` JSON body (Agent Contract v0.1 subset).
pub fn agent_policy_document(
    policy_mode: &str,
    mitm_categories: &[String],
    pinning_exceptions: &[String],
) -> serde_json::Value {
    let sni_deny = sni_deny_patterns_from_env();
    let sni_rules: Vec<serde_json::Value> = sni_deny
        .iter()
        .map(|pattern| {
            serde_json::json!({
                "pattern": pattern,
                "action": "deny",
            })
        })
        .collect();
    serde_json::json!({
        "policy_version": POLICY_VERSION,
        "policy_mode": policy_mode,
        "mitm_categories": mitm_categories,
        "pinning_exceptions": pinning_exceptions,
        "sni_deny_patterns": sni_deny,
        "sni_rules": sni_rules,
    })
}

// --- file IO ---

/// Optional path from `AGENT_DEVICES_PATH` (empty / unset → memory-only).
pub fn path_from_env() -> Option<PathBuf> {
    std::env::var("AGENT_DEVICES_PATH")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

/// Load registry from disk. Missing file → empty map (created on first save).
pub fn load(path: &Path) -> Result<HashMap<String, RegisteredDevice>, String> {
    if !path.exists() {
        info!(
            path = %path.display(),
            "Agent device registry file missing — starting empty"
        );
        return Ok(HashMap::new());
    }
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("read AGENT_DEVICES_PATH {}: {e}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(HashMap::new());
    }
    let file: DevicesFile = serde_json::from_str(&raw)
        .map_err(|e| format!("parse AGENT_DEVICES_PATH {}: {e}", path.display()))?;
    if file.version != FILE_VERSION {
        return Err(format!(
            "unsupported agent devices file version {} (expected {FILE_VERSION})",
            file.version
        ));
    }
    if file.devices.len() > MAX_DEVICES {
        return Err(format!(
            "agent devices file has {} entries (max {MAX_DEVICES})",
            file.devices.len()
        ));
    }
    let mut map = HashMap::with_capacity(file.devices.len());
    for device in file.devices {
        if device.id.trim().is_empty() {
            warn!("skipping device entry with empty id in registry file");
            continue;
        }
        map.insert(device.id.clone(), device);
    }
    info!(
        path = %path.display(),
        count = map.len(),
        "Loaded agent device registry"
    );
    Ok(map)
}

/// Atomic write: temp file in same directory + rename.
pub fn save(path: &Path, devices: &HashMap<String, RegisteredDevice>) -> Result<(), String> {
    if devices.len() > MAX_DEVICES {
        return Err(format!(
            "refusing to persist {} devices (max {MAX_DEVICES})",
            devices.len()
        ));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("create agent devices parent {}: {e}", parent.display()))?;
        }
    }
    let mut devices_vec: Vec<_> = devices.values().cloned().collect();
    devices_vec.sort_by(|a, b| a.id.cmp(&b.id));
    let file = DevicesFile {
        version: FILE_VERSION,
        devices: devices_vec,
    };
    let payload =
        serde_json::to_vec_pretty(&file).map_err(|e| format!("serialize agent devices: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| format!("create temp agent devices file {}: {e}", tmp.display()))?;
        f.write_all(&payload)
            .map_err(|e| format!("write temp agent devices file: {e}"))?;
        f.sync_all()
            .map_err(|e| format!("sync temp agent devices file: {e}"))?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        format!(
            "rename agent devices {} → {}: {e}",
            tmp.display(),
            path.display()
        )
    })?;
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

    fn sample(id: &str) -> RegisteredDevice {
        RegisteredDevice {
            id: id.into(),
            name: format!("name-{id}"),
            ip: "10.0.0.1".into(),
            device_type: "desktop".into(),
            agent_status: "healthy".into(),
            agent_version: Some("0.1.0".into()),
            policy_version: Some("v0.1.0".into()),
            cert_subject: None,
            cert_fingerprint: None,
            trust_score: Some(90),
            last_seen: unix_now(),
            revoked: false,
        }
    }

    #[test]
    fn round_trip_persist() {
        let dir = std::env::temp_dir().join(format!(
            "bsdm-devices-{}-{}",
            std::process::id(),
            unix_now()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("devices.json");
        let mut map = HashMap::new();
        map.insert("a".into(), sample("a"));
        map.insert("b".into(), {
            let mut d = sample("b");
            d.revoked = true;
            d
        });
        save(&path, &map).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded["b"].revoked);
        assert_eq!(loaded["a"].name, "name-a");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_is_empty() {
        let path = std::env::temp_dir().join(format!(
            "bsdm-devices-missing-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_file(&path);
        let loaded = load(&path).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn registry_heartbeat_merge_and_revoke() {
        let dir = std::env::temp_dir().join(format!(
            "bsdm-devices-reg-{}-{}",
            std::process::id(),
            unix_now()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("devices.json");
        let reg = DeviceRegistry::with_path(path.clone());

        let persisted = reg
            .apply_heartbeat(HeartbeatUpdate {
                device_id: "d1".into(),
                status: Some("healthy".into()),
                agent_version: Some("0.1.0".into()),
                policy_version: Some("v0.1.0".into()),
                name: Some("Laptop".into()),
                ip: Some("10.0.0.2".into()),
                device_type: Some("desktop".into()),
                cert_subject: None,
                cert_fingerprint: None,
                trust_score: Some(91),
            })
            .unwrap();
        assert!(persisted);

        // Second heartbeat preserves revoke=false and merges fields.
        reg.apply_heartbeat(HeartbeatUpdate {
            device_id: "d1".into(),
            status: Some("degraded".into()),
            agent_version: None,
            policy_version: None,
            name: None,
            ip: None,
            device_type: None,
            cert_subject: None,
            cert_fingerprint: None,
            trust_score: None,
        })
        .unwrap();

        let rows = reg.list_api_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["name"], "Laptop");
        assert_eq!(rows[0]["agentVersion"], "0.1.0");
        assert_eq!(rows[0]["status"], "Flagged");

        assert!(reg.revoke("d1").unwrap());
        let rows = reg.list_api_rows();
        assert_eq!(rows[0]["status"], "Revoked");

        let reloaded = DeviceRegistry::from_map(load(&path).unwrap(), Some(path));
        assert_eq!(reloaded.list_api_rows()[0]["status"], "Revoked");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn heartbeat_validation() {
        let reg = DeviceRegistry::memory_only();
        assert_eq!(
            reg.apply_heartbeat(HeartbeatUpdate {
                device_id: "  ".into(),
                status: None,
                agent_version: None,
                policy_version: None,
                name: None,
                ip: None,
                device_type: None,
                cert_subject: None,
                cert_fingerprint: None,
                trust_score: None,
            }),
            Err(HeartbeatError::EmptyDeviceId)
        );
        assert_eq!(
            reg.apply_heartbeat(HeartbeatUpdate {
                device_id: "x".into(),
                status: None,
                agent_version: None,
                policy_version: None,
                name: None,
                ip: None,
                device_type: None,
                cert_subject: None,
                cert_fingerprint: None,
                trust_score: Some(101),
            }),
            Err(HeartbeatError::InvalidTrustScore)
        );
    }

    #[test]
    fn policy_document_shape() {
        let doc = agent_policy_document(
            "selective-mitm",
            &["malware".into()],
            &[".slack.com".into()],
        );
        assert_eq!(doc["policy_version"], POLICY_VERSION);
        assert_eq!(doc["policy_mode"], "selective-mitm");
        assert!(doc["sni_rules"].is_array());
        assert_eq!(doc["sni_rules"][0]["action"], "deny");
        assert_eq!(doc["pinning_exceptions"][0], ".slack.com");
    }
}
