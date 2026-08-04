//! On-disk agent device registry (Phase C).
//!
//! Heartbeats update an in-memory map; when `AGENT_DEVICES_PATH` is set the map
//! is loaded at control-plane start and rewritten after each successful
//! heartbeat / revoke so inventory survives proxy restarts.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

const FILE_VERSION: u32 = 1;
const MAX_DEVICES: usize = 10_000;

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

#[derive(Debug, Serialize, Deserialize)]
struct DevicesFile {
    version: u32,
    devices: Vec<RegisteredDevice>,
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

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
            last_seen: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            revoked: false,
        }
    }

    #[test]
    fn round_trip_persist() {
        let dir = std::env::temp_dir().join(format!(
            "bsdm-devices-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
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
}
