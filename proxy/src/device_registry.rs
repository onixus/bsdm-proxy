//! Agent device inventory (Phase C).
//!
//! In-memory map with optional durable JSON path (`AGENT_DEVICES_PATH`) and
//! optional **multi-node Redis** write-through (`AGENT_DEVICES_REDIS_URL` or
//! `REDIS_URL` + `AGENT_DEVICES_REDIS=true`). Heartbeats/enroll/revoke update
//! local + Redis (and file when configured).

use crate::security_util::constant_time_eq;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

const FILE_VERSION: u32 = 1;
const MAX_DEVICES: usize = 10_000;
const POLICY_VERSION: &str = "v0.1.0";
const TOKEN_PREFIX: &str = "bsdmagent_";

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
    /// Client cert serial (hex) for X.509 CRL when issued via CSR enroll.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_serial: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_score: Option<u8>,
    pub last_seen: u64,
    #[serde(default)]
    pub revoked: bool,
    /// OS platform from enroll: `linux` | `macos` | `windows`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// User identity (UPN / email) from enroll — not verified without IdP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<u64>,
    /// SHA-256 hex of device Bearer token (plaintext returned only at enroll).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_token_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
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
            "certSerial": self.cert_serial,
            "trustScore": self.trust_score,
            "platform": self.platform,
            "userIdentity": self.user_identity,
            "enrolledAt": self.enrolled_at,
            "enrolled": self.device_token_hash.is_some() || self.enrolled_at.is_some(),
            "capabilities": self.capabilities,
        })
    }
}

/// Enroll request (device_token always; optional mTLS fields after CSR sign).
#[derive(Debug, Clone)]
pub struct EnrollRequest {
    pub device_id: Option<String>,
    pub platform: String,
    pub name: Option<String>,
    pub user_identity: Option<String>,
    pub capabilities: Vec<String>,
    pub device_type: Option<String>,
    pub cert_subject: Option<String>,
    pub cert_fingerprint: Option<String>,
    pub cert_serial: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EnrollResult {
    pub device_id: String,
    /// Plaintext device Bearer — shown once; only the hash is stored.
    pub device_token: String,
    pub platform: String,
    pub enrolled_at: u64,
    pub persisted: bool,
    pub reenrolled: bool,
    pub cert_subject: Option<String>,
    pub cert_fingerprint: Option<String>,
    pub cert_serial: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnrollError {
    InvalidPlatform,
    EmptyDeviceId,
    Revoked,
}

impl EnrollError {
    pub fn message(&self) -> &'static str {
        match self {
            EnrollError::InvalidPlatform => "platform must be linux|macos|windows",
            EnrollError::EmptyDeviceId => "device_id must not be empty when provided",
            EnrollError::Revoked => "device is revoked; clear revoke before re-enroll",
        }
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

/// Redis multi-node backend for the agent device registry.
#[derive(Clone)]
struct DeviceRedis {
    conn: ConnectionManager,
    /// HASH device_id → JSON RegisteredDevice
    devices_hash: String,
    token_prefix: String,
    fp_prefix: String,
    serial_prefix: String,
}

/// Runtime registry: map + optional file + optional Redis multi-node store.
#[derive(Clone)]
pub struct DeviceRegistry {
    devices: Arc<RwLock<HashMap<String, RegisteredDevice>>>,
    path: Option<PathBuf>,
    redis: Option<DeviceRedis>,
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
            redis: None,
        }
    }

    /// Load from `AGENT_DEVICES_PATH` when set; otherwise memory-only.
    /// Redis is attached later via [`Self::attach_redis`] (async connect).
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
                    redis: None,
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
                    redis: None,
                }
            }
        }
    }

    /// Test helper: empty registry that persists to `path`.
    pub fn with_path(path: PathBuf) -> Self {
        Self {
            devices: Arc::new(RwLock::new(HashMap::new())),
            path: Some(path),
            redis: None,
        }
    }

    /// Test helper: seed devices and optional path.
    pub fn from_map(map: HashMap<String, RegisteredDevice>, path: Option<PathBuf>) -> Self {
        Self {
            devices: Arc::new(RwLock::new(map)),
            path,
            redis: None,
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn is_persistent(&self) -> bool {
        self.path.is_some() || self.redis.is_some()
    }

    pub fn is_multi_node(&self) -> bool {
        self.redis.is_some()
    }

    /// Attach Redis multi-node backend and pull remote devices into local cache.
    pub async fn attach_redis(&mut self, conn: ConnectionManager) -> Result<usize, String> {
        let prefix = redis_key_prefix_from_env();
        let backend = DeviceRedis {
            conn,
            devices_hash: format!("{prefix}devices"),
            token_prefix: format!("{prefix}tok:"),
            fp_prefix: format!("{prefix}fp:"),
            serial_prefix: format!("{prefix}ser:"),
        };
        self.redis = Some(backend);
        let n = self.pull_from_redis().await;
        info!(
            hash = %self.redis.as_ref().map(|r| r.devices_hash.as_str()).unwrap_or(""),
            pulled = n,
            "Agent device registry multi-node Redis attached"
        );
        Ok(n)
    }

    /// Pull all devices from Redis HASH and merge by `last_seen` (remote wins if newer).
    pub async fn pull_from_redis(&self) -> usize {
        let Some(r) = self.redis.clone() else {
            return 0;
        };
        let mut conn = r.conn;
        let remote: HashMap<String, String> = match conn.hgetall(&r.devices_hash).await {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "Redis HGETALL agent devices failed");
                return 0;
            }
        };
        let mut merged = 0usize;
        let mut devices = self.devices.write().expect("device registry lock");
        for (_id, json) in remote {
            let Ok(dev) = serde_json::from_str::<RegisteredDevice>(&json) else {
                continue;
            };
            if dev.id.trim().is_empty() {
                continue;
            }
            match devices.get(&dev.id) {
                Some(local) if local.last_seen >= dev.last_seen => {}
                _ => {
                    devices.insert(dev.id.clone(), dev);
                    merged += 1;
                }
            }
        }
        if merged > 0 {
            debug!(
                merged,
                total = devices.len(),
                "Merged agent devices from Redis"
            );
        }
        merged
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
            cert_serial: previous.and_then(|d| d.cert_serial.clone()),
            trust_score: hb
                .trust_score
                .or_else(|| previous.and_then(|d| d.trust_score)),
            last_seen: unix_now(),
            revoked: previous.is_some_and(|d| d.revoked),
            // Preserve enroll metadata across heartbeats.
            platform: previous.and_then(|d| d.platform.clone()),
            user_identity: previous.and_then(|d| d.user_identity.clone()),
            enrolled_at: previous.and_then(|d| d.enrolled_at),
            device_token_hash: previous.and_then(|d| d.device_token_hash.clone()),
            capabilities: previous.map(|d| d.capabilities.clone()).unwrap_or_default(),
        };
        info!(
            device_id = %device.id,
            status = %device.agent_status,
            agent_version = ?device.agent_version,
            "Agent heartbeat received"
        );
        let stored = device.clone();
        devices.insert(device.id.clone(), device);
        let file_ok = self.persist_locked(&devices);
        let redis_ok = self.redis_put_device(&stored, None);
        Ok(file_ok || redis_ok)
    }

    /// Lab enroll: issue a device Bearer token (mTLS reserved).
    pub fn enroll(&self, req: EnrollRequest) -> Result<EnrollResult, EnrollError> {
        let platform = req.platform.to_ascii_lowercase();
        if !matches!(platform.as_str(), "linux" | "macos" | "windows") {
            return Err(EnrollError::InvalidPlatform);
        }
        let device_id = match req.device_id {
            Some(id) => {
                let id = id.trim().to_string();
                if id.is_empty() || id.contains('/') {
                    return Err(EnrollError::EmptyDeviceId);
                }
                id
            }
            None => format!("dev-{}", hex::encode(rand::random::<u128>().to_be_bytes())),
        };

        let mut devices = self.devices.write().expect("device registry lock");
        if let Some(existing) = devices.get(&device_id) {
            if existing.revoked {
                return Err(EnrollError::Revoked);
            }
        }
        let reenrolled = devices.contains_key(&device_id);
        let previous = devices.get(&device_id).cloned();
        let old_token_hash = previous.as_ref().and_then(|d| d.device_token_hash.clone());
        let now = unix_now();
        let plaintext = generate_device_token();
        let token_hash = hash_device_token(&plaintext);
        let name = req
            .name
            .filter(|n| !n.trim().is_empty())
            .or_else(|| previous.as_ref().map(|d| d.name.clone()))
            .unwrap_or_else(|| device_id.clone());
        let device_type = req
            .device_type
            .filter(|k| matches!(k.as_str(), "desktop" | "phone"))
            .or_else(|| previous.as_ref().map(|d| d.device_type.clone()))
            .unwrap_or_else(|| "desktop".to_string());
        let capabilities = if req.capabilities.is_empty() {
            previous
                .as_ref()
                .map(|d| d.capabilities.clone())
                .unwrap_or_else(|| vec!["local-proxy".into()])
        } else {
            req.capabilities
        };

        let device = RegisteredDevice {
            id: device_id.clone(),
            name,
            ip: previous.as_ref().map(|d| d.ip.clone()).unwrap_or_default(),
            device_type,
            agent_status: previous
                .as_ref()
                .map(|d| d.agent_status.clone())
                .unwrap_or_else(|| "healthy".into()),
            agent_version: previous.as_ref().and_then(|d| d.agent_version.clone()),
            policy_version: previous.as_ref().and_then(|d| d.policy_version.clone()),
            cert_subject: req
                .cert_subject
                .filter(|s| !s.trim().is_empty())
                .or_else(|| previous.as_ref().and_then(|d| d.cert_subject.clone())),
            cert_fingerprint: req
                .cert_fingerprint
                .filter(|s| !s.trim().is_empty())
                .or_else(|| previous.as_ref().and_then(|d| d.cert_fingerprint.clone())),
            cert_serial: req
                .cert_serial
                .filter(|s| !s.trim().is_empty())
                .or_else(|| previous.as_ref().and_then(|d| d.cert_serial.clone())),
            trust_score: previous.as_ref().and_then(|d| d.trust_score),
            last_seen: now,
            revoked: false,
            platform: Some(platform.clone()),
            user_identity: req
                .user_identity
                .filter(|u| !u.trim().is_empty())
                .or_else(|| previous.as_ref().and_then(|d| d.user_identity.clone())),
            enrolled_at: Some(now),
            device_token_hash: Some(token_hash),
            capabilities,
        };
        let cert_subject = device.cert_subject.clone();
        let cert_fingerprint = device.cert_fingerprint.clone();
        let cert_serial = device.cert_serial.clone();
        info!(
            device_id = %device.id,
            platform = %platform,
            reenrolled,
            has_client_cert = cert_fingerprint.is_some(),
            "Agent device enrolled"
        );
        let stored = device.clone();
        devices.insert(device.id.clone(), device);
        let file_ok = self.persist_locked(&devices);
        let redis_ok = self.redis_put_device(&stored, old_token_hash.as_deref());
        Ok(EnrollResult {
            device_id,
            device_token: plaintext,
            platform,
            enrolled_at: now,
            persisted: file_ok || redis_ok,
            reenrolled,
            cert_subject,
            cert_fingerprint,
            cert_serial,
        })
    }

    /// Constant-time check that `token` matches a non-revoked enrolled device.
    pub fn device_token_valid(&self, token: &str) -> bool {
        if token.is_empty() {
            return false;
        }
        let hash = hash_device_token(token);
        {
            let devices = self.devices.read().expect("device registry lock");
            if devices.values().any(|d| {
                !d.revoked
                    && d.device_token_hash
                        .as_ref()
                        .is_some_and(|h| constant_time_eq(h.as_bytes(), hash.as_bytes()))
            }) {
                return true;
            }
        }
        // Multi-node: resolve token hash via Redis index.
        if let Some(dev) = self.redis_get_by_token_hash(&hash) {
            if !dev.revoked {
                self.cache_device(dev);
                return true;
            }
        }
        false
    }

    /// True if `fingerprint` (SHA-256 hex of client cert DER) matches a non-revoked enroll.
    pub fn cert_fingerprint_valid(&self, fingerprint: &str) -> bool {
        if fingerprint.is_empty() {
            return false;
        }
        let fp = fingerprint.to_ascii_lowercase();
        {
            let devices = self.devices.read().expect("device registry lock");
            if devices.values().any(|d| {
                !d.revoked
                    && d.cert_fingerprint.as_ref().is_some_and(|h| {
                        constant_time_eq(h.to_ascii_lowercase().as_bytes(), fp.as_bytes())
                    })
            }) {
                return true;
            }
        }
        if let Some(dev) = self.redis_get_by_fp(&fp) {
            if !dev.revoked {
                self.cache_device(dev);
                return true;
            }
        }
        false
    }

    /// True if we have ever seen this fingerprint (even if later revoked).
    pub fn cert_fingerprint_known(&self, fingerprint: &str) -> bool {
        if fingerprint.is_empty() {
            return false;
        }
        let fp = fingerprint.to_ascii_lowercase();
        {
            let devices = self.devices.read().expect("device registry lock");
            if devices.values().any(|d| {
                d.cert_fingerprint.as_ref().is_some_and(|h| {
                    constant_time_eq(h.to_ascii_lowercase().as_bytes(), fp.as_bytes())
                })
            }) {
                return true;
            }
        }
        self.redis_get_by_fp(&fp).is_some()
    }

    /// True if serial was issued to any enrolled (or revoked) device.
    pub fn cert_serial_known(&self, serial_hex: &str) -> bool {
        if serial_hex.is_empty() {
            return false;
        }
        let s = serial_hex.to_ascii_lowercase();
        {
            let devices = self.devices.read().expect("device registry lock");
            if devices.values().any(|d| {
                d.cert_serial.as_ref().is_some_and(|h| {
                    constant_time_eq(h.to_ascii_lowercase().as_bytes(), s.as_bytes())
                })
            }) {
                return true;
            }
        }
        self.redis_get_by_serial(&s).is_some()
    }

    /// Active (non-revoked) device with matching serial, if any.
    pub fn cert_serial_valid(&self, serial_hex: &str) -> bool {
        if serial_hex.is_empty() {
            return false;
        }
        let s = serial_hex.to_ascii_lowercase();
        {
            let devices = self.devices.read().expect("device registry lock");
            if devices.values().any(|d| {
                !d.revoked
                    && d.cert_serial.as_ref().is_some_and(|h| {
                        constant_time_eq(h.to_ascii_lowercase().as_bytes(), s.as_bytes())
                    })
            }) {
                return true;
            }
        }
        if let Some(dev) = self.redis_get_by_serial(&s) {
            if !dev.revoked {
                self.cache_device(dev);
                return true;
            }
        }
        false
    }

    /// Revoke device trust. Returns `(persisted, cert_fingerprint, cert_serial)` for CRL.
    pub fn revoke(
        &self,
        device_id: &str,
    ) -> Result<(bool, Option<String>, Option<String>), RevokeError> {
        if device_id.is_empty() || device_id.contains('/') {
            return Err(RevokeError::InvalidId);
        }
        // Multi-node: ensure we have the device if only remote has it.
        if self
            .devices
            .read()
            .expect("device registry lock")
            .get(device_id)
            .is_none()
        {
            if let Some(remote) = self.redis_get_device(device_id) {
                self.cache_device(remote);
            }
        }
        let mut devices = self.devices.write().expect("device registry lock");
        let Some(device) = devices.get_mut(device_id) else {
            return Err(RevokeError::NotFound);
        };
        let old_token = device.device_token_hash.clone();
        device.revoked = true;
        device.device_token_hash = None;
        let fp = device.cert_fingerprint.clone();
        let serial = device.cert_serial.clone();
        let stored = device.clone();
        warn!(device_id, "Device trust revoked");
        let file_ok = self.persist_locked(&devices);
        drop(devices);
        let redis_ok = self.redis_put_device(&stored, old_token.as_deref());
        Ok((file_ok || redis_ok, fp, serial))
    }

    /// Devices sorted by `last_seen` descending (API list order).
    pub fn list_api_rows(&self) -> Vec<serde_json::Value> {
        // Best-effort multi-node refresh before listing.
        self.block_on_redis_pull();
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

    fn cache_device(&self, device: RegisteredDevice) {
        let mut devices = self.devices.write().expect("device registry lock");
        devices.insert(device.id.clone(), device);
    }

    fn redis_put_device(&self, device: &RegisteredDevice, old_token_hash: Option<&str>) -> bool {
        let Some(r) = self.redis.clone() else {
            return false;
        };
        let device = device.clone();
        let old_token_hash = old_token_hash.map(str::to_string);
        block_on_current(async move {
            let mut conn = r.conn;
            let Ok(json) = serde_json::to_string(&device) else {
                return false;
            };
            if let Err(e) = conn
                .hset::<_, _, _, ()>(&r.devices_hash, &device.id, &json)
                .await
            {
                warn!(error = %e, device_id = %device.id, "Redis HSET agent device failed");
                return false;
            }
            if let Some(ref old) = old_token_hash {
                if device
                    .device_token_hash
                    .as_ref()
                    .map(|h| h != old)
                    .unwrap_or(true)
                {
                    let _: Result<(), _> = conn.del(format!("{}{old}", r.token_prefix)).await;
                }
            }
            if let Some(ref h) = device.device_token_hash {
                let _: Result<(), _> = conn.set(format!("{}{h}", r.token_prefix), &device.id).await;
            } else if let Some(ref old) = old_token_hash {
                let _: Result<(), _> = conn.del(format!("{}{old}", r.token_prefix)).await;
            }
            if let Some(ref fp) = device.cert_fingerprint {
                let _: Result<(), _> = conn
                    .set(
                        format!("{}{}", r.fp_prefix, fp.to_ascii_lowercase()),
                        &device.id,
                    )
                    .await;
            }
            if let Some(ref ser) = device.cert_serial {
                let _: Result<(), _> = conn
                    .set(
                        format!("{}{}", r.serial_prefix, ser.to_ascii_lowercase()),
                        &device.id,
                    )
                    .await;
            }
            true
        })
        .unwrap_or(false)
    }

    fn redis_get_device(&self, device_id: &str) -> Option<RegisteredDevice> {
        let r = self.redis.clone()?;
        let device_id = device_id.to_string();
        block_on_current(async move {
            let mut conn = r.conn;
            let json: Option<String> = conn.hget(&r.devices_hash, &device_id).await.ok()?;
            json.and_then(|j| serde_json::from_str(&j).ok())
        })
        .flatten()
    }

    fn redis_get_by_token_hash(&self, hash: &str) -> Option<RegisteredDevice> {
        let r = self.redis.clone()?;
        let key = format!("{}{hash}", r.token_prefix);
        block_on_current(async move {
            let mut conn = r.conn;
            let id: Option<String> = conn.get(&key).await.ok()?;
            let id = id?;
            let json: Option<String> = conn.hget(&r.devices_hash, &id).await.ok()?;
            json.and_then(|j| serde_json::from_str(&j).ok())
        })
        .flatten()
    }

    fn redis_get_by_fp(&self, fp: &str) -> Option<RegisteredDevice> {
        let r = self.redis.clone()?;
        let key = format!("{}{fp}", r.fp_prefix);
        block_on_current(async move {
            let mut conn = r.conn;
            let id: Option<String> = conn.get(&key).await.ok()?;
            let id = id?;
            let json: Option<String> = conn.hget(&r.devices_hash, &id).await.ok()?;
            json.and_then(|j| serde_json::from_str(&j).ok())
        })
        .flatten()
    }

    fn redis_get_by_serial(&self, serial: &str) -> Option<RegisteredDevice> {
        let r = self.redis.clone()?;
        let key = format!("{}{serial}", r.serial_prefix);
        block_on_current(async move {
            let mut conn = r.conn;
            let id: Option<String> = conn.get(&key).await.ok()?;
            let id = id?;
            let json: Option<String> = conn.hget(&r.devices_hash, &id).await.ok()?;
            json.and_then(|j| serde_json::from_str(&j).ok())
        })
        .flatten()
    }

    fn block_on_redis_pull(&self) {
        if self.redis.is_none() {
            return;
        }
        let this = self.clone();
        let _ = block_on_current(async move { this.pull_from_redis().await });
    }
}

/// Run an async block on the current Tokio runtime (hyper handlers), or None if none.
pub(crate) fn block_on_current<F, T>(fut: F) -> Option<T>
where
    F: std::future::Future<Output = T>,
{
    let handle = tokio::runtime::Handle::try_current().ok()?;
    Some(tokio::task::block_in_place(|| handle.block_on(fut)))
}

/// Redis URL for multi-node agent devices.
/// Prefer `AGENT_DEVICES_REDIS_URL`; else `REDIS_URL` when `AGENT_DEVICES_REDIS=true`.
pub fn redis_url_from_env() -> Option<String> {
    if let Ok(url) = std::env::var("AGENT_DEVICES_REDIS_URL") {
        let url = url.trim().to_string();
        if !url.is_empty() {
            return Some(url);
        }
    }
    let enabled = std::env::var("AGENT_DEVICES_REDIS")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    if !enabled {
        return None;
    }
    std::env::var("REDIS_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub(crate) fn redis_key_prefix_from_env() -> String {
    std::env::var("AGENT_REDIS_PREFIX")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "bsdm:agent:".into())
}

/// Connect a Redis client for agent multi-node stores.
pub async fn connect_agent_redis(url: &str) -> Result<ConnectionManager, String> {
    let client = redis::Client::open(url).map_err(|e| format!("agent redis client: {e}"))?;
    ConnectionManager::new(client)
        .await
        .map_err(|e| format!("agent redis connect: {e}"))
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

fn generate_device_token() -> String {
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&rand::random::<[u8; 32]>());
    format!("{TOKEN_PREFIX}{}", hex::encode(raw))
}

pub fn hash_device_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
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
            cert_serial: None,
            trust_score: Some(90),
            last_seen: unix_now(),
            revoked: false,
            platform: None,
            user_identity: None,
            enrolled_at: None,
            device_token_hash: None,
            capabilities: vec![],
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

        assert!(reg.revoke("d1").unwrap().0);
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

    #[test]
    fn enroll_issues_token_and_validates() {
        let reg = DeviceRegistry::memory_only();
        let result = reg
            .enroll(EnrollRequest {
                device_id: Some("enroll-1".into()),
                platform: "macos".into(),
                name: Some("Mac".into()),
                user_identity: Some("alice@corp".into()),
                capabilities: vec!["local-proxy".into()],
                device_type: Some("desktop".into()),
                cert_subject: None,
                cert_fingerprint: None,
                cert_serial: None,
            })
            .unwrap();
        assert!(result.device_token.starts_with(TOKEN_PREFIX));
        assert!(reg.device_token_valid(&result.device_token));
        assert!(!reg.device_token_valid("bsdmagent_wrong"));
        let rows = reg.list_api_rows();
        assert_eq!(rows[0]["platform"], "macos");
        assert_eq!(rows[0]["enrolled"], true);

        reg.revoke("enroll-1").unwrap();
        assert!(!reg.device_token_valid(&result.device_token));
        assert!(matches!(
            reg.enroll(EnrollRequest {
                device_id: Some("enroll-1".into()),
                platform: "macos".into(),
                name: None,
                user_identity: None,
                capabilities: vec![],
                device_type: None,
                cert_subject: None,
                cert_fingerprint: None,
                cert_serial: None,
            }),
            Err(EnrollError::Revoked)
        ));
    }
}
