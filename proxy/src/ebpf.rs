//! eBPF / XDP (eXpress Data Path) kernel packet filter & bypass manager.
//!
//! Enables zero-CPU overhead packet drops at the NIC driver level (`XDP_DROP`)
//! for blocked IPv4/IPv6 addresses and malicious traffic.
//!
//! Locking discipline: kernel side-effects (`ip`, `bpftool`, clang) are NEVER
//! performed while a `config` or `blocked_ips` lock is held. Every public method
//! snapshots what it needs, releases the guard, and only then shells out. This
//! keeps the two locks independent and avoids both self-deadlocks (the same
//! thread re-entering `config`) and lock-order inversions between callers.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

/// Maximum number of entries compiled into the BPF hash maps (`bpf/xdp_drop.c`).
/// Changing it requires editing and recompiling the BPF object.
pub const COMPILED_MAX_ENTRIES: u32 = 65536;

/// Name of the IPv4 blocklist map declared by `bpf/xdp_drop.c`.
pub const MAP_NAME_V4: &str = "bsdm_blocked_ips";
/// Name of the IPv6 blocklist map declared by `bpf/xdp_drop.c`.
pub const MAP_NAME_V6: &str = "bsdm_blocked_ips_v6";
/// Name of the global drop-counter array map declared by `bpf/xdp_drop.c`.
pub const MAP_NAME_STATS: &str = "bsdm_drop_stats";

/// Minimum interval between two `bpftool map dump` sweeps, so that a burst of
/// control-plane requests cannot turn into a burst of subprocesses.
const STATS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// Runtime mode for eBPF XDP program attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XdpMode {
    /// Generic / SKB mode (works on any netdev, driver independent)
    #[default]
    #[serde(alias = "skb")]
    Skb,
    /// Native driver mode (zero-copy hardware driver level)
    #[serde(alias = "driver", alias = "native")]
    Driver,
    /// Hardware offload to SmartNIC
    #[serde(alias = "offload", alias = "hw")]
    Offload,
}

impl XdpMode {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "driver" | "native" => Self::Driver,
            "offload" | "hw" => Self::Offload,
            _ => Self::Skb,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Skb => "skb",
            Self::Driver => "driver",
            Self::Offload => "offload",
        }
    }

    /// Argument accepted by `ip link set dev <if> <arg> ...`.
    fn ip_link_arg(&self) -> &'static str {
        match self {
            Self::Driver => "xdp",
            Self::Offload => "xdpoffload",
            Self::Skb => "xdpgeneric",
        }
    }
}

/// Runtime configuration for eBPF XDP filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EbpfXdpConfig {
    pub enabled: bool,
    pub interface: String,
    pub mode: XdpMode,
    #[serde(alias = "map_name")]
    pub map_name: String,
    #[serde(alias = "max_entries")]
    pub max_entries: u32,
}

impl Default for EbpfXdpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: "eth0".to_string(),
            mode: XdpMode::Skb,
            map_name: MAP_NAME_V4.to_string(),
            max_entries: COMPILED_MAX_ENTRIES,
        }
    }
}

impl EbpfXdpConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("EBPF_XDP_ENABLED")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        let interface = std::env::var("EBPF_XDP_IFACE").unwrap_or_else(|_| "eth0".to_string());
        let mode_str = std::env::var("EBPF_XDP_MODE").unwrap_or_else(|_| "skb".to_string());
        let max_entries = std::env::var("EBPF_XDP_MAX_ENTRIES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(COMPILED_MAX_ENTRIES);

        Self {
            enabled,
            interface,
            mode: XdpMode::parse(&mode_str),
            map_name: MAP_NAME_V4.to_string(),
            max_entries,
        }
    }

    /// Rejects values the kernel side cannot actually honour, so the API never
    /// acknowledges a setting that has no effect.
    pub fn validate(&self) -> Result<(), String> {
        if self.interface.is_empty() || self.interface.len() > 15 {
            return Err("interface must be 1..=15 characters".to_string());
        }
        if !self
            .interface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '@'))
        {
            return Err(format!("invalid interface name: {}", self.interface));
        }
        if self.map_name != MAP_NAME_V4 {
            return Err(format!(
                "mapName must be \"{}\" (the map declared by bpf/xdp_drop.c)",
                MAP_NAME_V4
            ));
        }
        if self.max_entries == 0 || self.max_entries > COMPILED_MAX_ENTRIES {
            return Err(format!(
                "maxEntries must be 1..={} (compiled into bpf/xdp_drop.c)",
                COMPILED_MAX_ENTRIES
            ));
        }
        Ok(())
    }
}

/// A blocked IP entry with audit metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EbpfBlockedIp {
    pub id: String,
    pub ip: String,
    pub added_at: String,
    pub reason: String,
    pub packets_dropped: u64,
    pub bytes_dropped: u64,
}

/// Request body for blocking an IP address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockIpRequest {
    pub ip: String,
    pub reason: Option<String>,
}

/// Kernel XDP statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EbpfStats {
    pub enabled: bool,
    /// Whether the XDP program is actually loaded on the interface right now.
    /// `enabled` only reflects the requested configuration.
    pub attached: bool,
    pub interface: String,
    pub mode: XdpMode,
    pub active_blocked_ips: u32,
    pub packets_dropped_total: u64,
    pub bytes_dropped_total: u64,
    /// `None` when no measurement is available (never a synthetic value).
    pub kernel_latency_us: Option<f64>,
    pub cpu_usage_user_percent: f64,
}

struct ManagerInner {
    config: RwLock<EbpfXdpConfig>,
    blocked_ips: RwLock<HashMap<IpAddr, EbpfBlockedIp>>,
    dropped_packets: AtomicU64,
    dropped_bytes: AtomicU64,
    attached: AtomicBool,
    last_stats_refresh: Mutex<Option<Instant>>,
}

impl Drop for ManagerInner {
    fn drop(&mut self) {
        // Only the last owner of the shared state reaches this point, so a
        // cloned handle going out of scope can never detach a live program.
        if !self.attached.load(Ordering::SeqCst) {
            return;
        }
        let cfg = match self.config.read() {
            Ok(c) => c.clone(),
            Err(_) => return,
        };
        detach_kernel_program(&cfg);
    }
}

fn detach_kernel_program(config: &EbpfXdpConfig) {
    if std::env::consts::OS != "linux" {
        return;
    }
    let _ = Command::new("ip")
        .args([
            "link",
            "set",
            "dev",
            &config.interface,
            config.mode.ip_link_arg(),
            "off",
        ])
        .output();
}

/// Manager for kernel eBPF map sync, packet drops, and runtime statistics.
///
/// Cloning yields another handle to the same shared state; the kernel program is
/// detached only when the last handle is dropped.
#[derive(Clone)]
pub struct EbpfXdpManager {
    inner: Arc<ManagerInner>,
}

impl EbpfXdpManager {
    pub fn new(config: EbpfXdpConfig) -> Self {
        let manager = Self {
            inner: Arc::new(ManagerInner {
                config: RwLock::new(config.clone()),
                blocked_ips: RwLock::new(HashMap::new()),
                dropped_packets: AtomicU64::new(0),
                dropped_bytes: AtomicU64::new(0),
                attached: AtomicBool::new(false),
                last_stats_refresh: Mutex::new(None),
            }),
        };

        if config.enabled {
            info!(
                "Initializing eBPF XDP manager on interface {} (mode: {:?})",
                config.interface, config.mode
            );
            manager.attach_kernel_program(&config);
        } else {
            debug!("eBPF XDP manager initialized in disabled state");
        }

        manager
    }

    /// Attaches the XDP object and records whether it actually succeeded, so
    /// `stats()` never claims an active filter that is not loaded.
    fn attach_kernel_program(&self, config: &EbpfXdpConfig) -> bool {
        if std::env::consts::OS != "linux" {
            warn!("eBPF XDP is only supported on Linux. Operating in simulated mode.");
            self.inner.attached.store(false, Ordering::SeqCst);
            return false;
        }

        if !std::path::Path::new("bpf/xdp_drop.o").exists() {
            info!("Compiling bpf/xdp_drop.c to BPF bytecode...");
            let out = Command::new("clang")
                .args([
                    "-O2",
                    "-target",
                    "bpf",
                    "-c",
                    "bpf/xdp_drop.c",
                    "-o",
                    "bpf/xdp_drop.o",
                ])
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    info!("Compiled bpf/xdp_drop.o successfully")
                }
                Ok(o) => {
                    error!(
                        "Failed to compile XDP program: {}",
                        String::from_utf8_lossy(&o.stderr)
                    );
                    self.inner.attached.store(false, Ordering::SeqCst);
                    return false;
                }
                Err(e) => {
                    error!("Failed to invoke clang: {}", e);
                    self.inner.attached.store(false, Ordering::SeqCst);
                    return false;
                }
            }
        }

        let mode_str = config.mode.ip_link_arg();

        // Detach previous attachment first (ignore errors if none existed)
        let _ = Command::new("ip")
            .args(["link", "set", "dev", &config.interface, mode_str, "off"])
            .output();
        self.inner.attached.store(false, Ordering::SeqCst);

        info!(
            "Attaching XDP program bpf/xdp_drop.o to netdev {}",
            config.interface
        );
        let attach = Command::new("ip")
            .args([
                "link",
                "set",
                "dev",
                &config.interface,
                mode_str,
                "obj",
                "bpf/xdp_drop.o",
                "sec",
                "xdp",
            ])
            .output();
        match attach {
            Ok(o) if o.status.success() => {
                info!("Attached XDP program to {} successfully", config.interface);
                self.inner.attached.store(true, Ordering::SeqCst);
                true
            }
            Ok(o) => {
                error!(
                    "Failed to attach XDP to {}: {}",
                    config.interface,
                    String::from_utf8_lossy(&o.stderr)
                );
                false
            }
            Err(e) => {
                error!("Failed to invoke ip command: {}", e);
                false
            }
        }
    }

    fn detach(&self, config: &EbpfXdpConfig) {
        detach_kernel_program(config);
        self.inner.attached.store(false, Ordering::SeqCst);
    }

    /// Formats an IP address as a hex string suitable for bpftool.
    fn ip_to_hex(ip: &IpAddr) -> String {
        let bytes: Vec<u8> = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn is_enabled(&self) -> bool {
        self.inner.config.read().map(|c| c.enabled).unwrap_or(false)
    }

    /// Whether the XDP program is currently loaded on the interface.
    pub fn is_attached(&self) -> bool {
        self.inner.attached.load(Ordering::SeqCst)
    }

    pub fn config(&self) -> EbpfXdpConfig {
        self.inner
            .config
            .read()
            .map(|c| c.clone())
            .unwrap_or_default()
    }

    /// Updates the runtime eBPF configuration.
    ///
    /// The kernel program is only re-attached when the attachment actually
    /// changes (enable transition, interface or mode change) — unrelated field
    /// edits no longer tear down a working filter.
    pub fn update_config(&self, new_cfg: EbpfXdpConfig) -> Result<(), String> {
        new_cfg.validate()?;

        // Snapshot the transition under the lock, then release it before any
        // kernel interaction.
        let (was_enabled, old_cfg) = {
            let mut cfg = self
                .inner
                .config
                .write()
                .map_err(|_| "Failed to acquire config write lock".to_string())?;
            let previous = cfg.clone();
            *cfg = new_cfg.clone();
            (previous.enabled, previous)
        };

        let attachment_changed =
            old_cfg.interface != new_cfg.interface || old_cfg.mode != new_cfg.mode;

        if was_enabled && (!new_cfg.enabled || attachment_changed) {
            self.detach(&old_cfg);
        }

        if new_cfg.enabled && (!was_enabled || attachment_changed || !self.is_attached()) {
            if !self.attach_kernel_program(&new_cfg) {
                return Err(format!(
                    "eBPF XDP program could not be attached to {}",
                    new_cfg.interface
                ));
            }
            // Re-sync existing blocked IPs into the freshly loaded kernel maps.
            let ips: Vec<IpAddr> = self
                .inner
                .blocked_ips
                .read()
                .map(|m| m.keys().copied().collect())
                .unwrap_or_default();
            for ip in ips {
                if let Err(e) = self.sync_ip_to_kernel(&ip, true) {
                    error!(
                        "Failed to re-sync blocked IP {} after config change: {}",
                        ip, e
                    );
                }
            }
        }

        Ok(())
    }

    fn map_name_for(&self, ip: &IpAddr) -> String {
        match ip {
            IpAddr::V4(_) => MAP_NAME_V4.to_string(),
            IpAddr::V6(_) => MAP_NAME_V6.to_string(),
        }
    }

    /// Programs (or removes) a single address in the kernel map.
    ///
    /// Returns `Err` on any kernel-side failure so callers never report success
    /// for an address that is not actually filtered.
    fn sync_ip_to_kernel(&self, ip: &IpAddr, block: bool) -> Result<(), String> {
        if std::env::consts::OS != "linux" {
            debug!("eBPF XDP simulated mode: skipping kernel sync for {}", ip);
            return Ok(());
        }

        let map_name = self.map_name_for(ip);
        let hex = Self::ip_to_hex(ip);
        // Value layout must match `struct ip_drop_stats` in bpf/xdp_drop.c
        // (two u64 counters, zero-initialised on insert).
        let zero_value = vec!["00"; 16].join(" ");

        let args: Vec<&str> = if block {
            vec![
                "map",
                "update",
                "name",
                &map_name,
                "key",
                "hex",
                &hex,
                "value",
                "hex",
                &zero_value,
            ]
        } else {
            vec!["map", "delete", "name", &map_name, "key", "hex", &hex]
        };

        let out = Command::new("bpftool")
            .args(&args)
            .output()
            .map_err(|e| format!("failed to invoke bpftool: {}", e))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let action = if block { "update" } else { "delete" };
            error!(
                "Failed to {} BPF map {} for {}: {}",
                action, map_name, ip, stderr
            );
            return Err(format!("bpftool map {} failed: {}", action, stderr));
        }

        if block {
            info!(
                "eBPF XDP: Blocked IP {} synced to kernel BPF map {}",
                ip, map_name
            );
        } else {
            info!(
                "eBPF XDP: Removed IP {} from kernel BPF map {}",
                ip, map_name
            );
        }
        Ok(())
    }

    /// Block an IP address with optional reason. Returns the created entry.
    ///
    /// If the kernel map cannot be programmed the entry is rolled back and an
    /// error is returned — the API must not advertise a block that is not live.
    pub fn block_ip(&self, ip: IpAddr, reason: Option<String>) -> Result<EbpfBlockedIp, String> {
        let id = format!("ebpf-{}", ip.to_string().replace(['.', ':'], "-"));
        let entry = EbpfBlockedIp {
            id,
            ip: ip.to_string(),
            added_at: chrono::Utc::now().to_rfc3339(),
            reason: reason.unwrap_or_else(|| "Manual administrative block".to_string()),
            packets_dropped: 0,
            bytes_dropped: 0,
        };

        {
            let mut map = self
                .inner
                .blocked_ips
                .write()
                .map_err(|_| "Failed to acquire write lock".to_string())?;
            if map.contains_key(&ip) {
                return Err(format!("IP {} is already blocked", ip));
            }
            map.insert(ip, entry.clone());
        }

        if self.is_enabled() {
            if let Err(e) = self.sync_ip_to_kernel(&ip, true) {
                if let Ok(mut map) = self.inner.blocked_ips.write() {
                    map.remove(&ip);
                }
                return Err(e);
            }
        }

        Ok(entry)
    }

    /// Unblock an IP address by its IP string or ID.
    ///
    /// `Ok(false)` means the entry was unknown; `Err` means the entry was
    /// removed from the registry but the kernel map still holds it.
    pub fn unblock_ip(&self, id_or_ip: &str) -> Result<bool, String> {
        let removed = {
            let mut map = self
                .inner
                .blocked_ips
                .write()
                .map_err(|_| "Failed to acquire write lock".to_string())?;

            let target = id_or_ip
                .parse::<IpAddr>()
                .ok()
                .filter(|ip| map.contains_key(ip))
                .or_else(|| {
                    map.iter().find_map(|(ip, entry)| {
                        if entry.id == id_or_ip || entry.ip == id_or_ip {
                            Some(*ip)
                        } else {
                            None
                        }
                    })
                });

            match target {
                Some(ip) => {
                    map.remove(&ip);
                    Some(ip)
                }
                None => None,
            }
        };

        let Some(ip) = removed else {
            return Ok(false);
        };

        if self.is_enabled() {
            self.sync_ip_to_kernel(&ip, false)?;
        }
        Ok(true)
    }

    /// Number of addresses currently in the blocklist registry.
    pub fn blocked_ip_count(&self) -> usize {
        self.inner.blocked_ips.read().map(|m| m.len()).unwrap_or(0)
    }

    /// Check if an IP address is blocked.
    pub fn is_ip_blocked(&self, ip: &IpAddr) -> bool {
        self.inner
            .blocked_ips
            .read()
            .map(|set| set.contains_key(ip))
            .unwrap_or(false)
    }

    /// Pulls the authoritative counters out of the kernel maps into the
    /// in-memory registry. No-op (returns `false`) outside Linux or when the
    /// program is not attached.
    pub fn refresh_kernel_stats(&self) -> bool {
        if std::env::consts::OS != "linux" || !self.is_attached() {
            return false;
        }

        // Rate-limit the dump so control-plane traffic cannot spawn one bpftool
        // process per request.
        match self.inner.last_stats_refresh.lock() {
            Ok(mut last) => {
                let now = Instant::now();
                if let Some(prev) = *last {
                    if now.duration_since(prev) < STATS_REFRESH_INTERVAL {
                        return false;
                    }
                }
                *last = Some(now);
            }
            Err(_) => return false,
        }

        let mut refreshed = false;

        if let Some(entries) = dump_map(MAP_NAME_STATS) {
            let mut packets = None;
            let mut bytes = None;
            for (key, value) in &entries {
                let idx = le_u32(key);
                let counter = le_u64(value);
                match (idx, counter) {
                    (Some(0), Some(v)) => packets = Some(v),
                    (Some(1), Some(v)) => bytes = Some(v),
                    _ => {}
                }
            }
            if let Some(p) = packets {
                self.inner.dropped_packets.store(p, Ordering::Relaxed);
                refreshed = true;
            }
            if let Some(b) = bytes {
                self.inner.dropped_bytes.store(b, Ordering::Relaxed);
                refreshed = true;
            }
        }

        // Per-address counters live in the value of each blocklist entry.
        let mut per_ip: HashMap<IpAddr, (u64, u64)> = HashMap::new();
        for (map_name, is_v6) in [(MAP_NAME_V4, false), (MAP_NAME_V6, true)] {
            let Some(entries) = dump_map(map_name) else {
                continue;
            };
            for (key, value) in entries {
                let Some(ip) = bytes_to_ip(&key, is_v6) else {
                    continue;
                };
                if value.len() < 16 {
                    continue;
                }
                let packets = le_u64(&value[..8]).unwrap_or(0);
                let bytes = le_u64(&value[8..16]).unwrap_or(0);
                per_ip.insert(ip, (packets, bytes));
            }
        }

        if !per_ip.is_empty() {
            if let Ok(mut map) = self.inner.blocked_ips.write() {
                for (ip, entry) in map.iter_mut() {
                    if let Some((packets, bytes)) = per_ip.get(ip) {
                        entry.packets_dropped = *packets;
                        entry.bytes_dropped = *bytes;
                    }
                }
                refreshed = true;
            }
        }

        refreshed
    }

    /// Retrieve kernel packet drop stats.
    pub fn stats(&self) -> EbpfStats {
        self.refresh_kernel_stats();

        let config = self.config();
        let active_count = self
            .inner
            .blocked_ips
            .read()
            .map(|m| m.len() as u32)
            .unwrap_or(0);

        EbpfStats {
            enabled: config.enabled,
            attached: self.is_attached(),
            interface: config.interface,
            mode: config.mode,
            active_blocked_ips: active_count,
            packets_dropped_total: self.inner.dropped_packets.load(Ordering::Relaxed),
            bytes_dropped_total: self.inner.dropped_bytes.load(Ordering::Relaxed),
            // No latency probe exists yet; report absence instead of a constant.
            kernel_latency_us: None,
            cpu_usage_user_percent: 0.0,
        }
    }

    /// List all currently blocked IPs with audit metadata.
    pub fn list_blocked_ips(&self) -> Vec<EbpfBlockedIp> {
        self.refresh_kernel_stats();
        self.inner
            .blocked_ips
            .read()
            .map(|m| {
                let mut list: Vec<EbpfBlockedIp> = m.values().cloned().collect();
                list.sort_by(|a, b| b.added_at.cmp(&a.added_at));
                list
            })
            .unwrap_or_default()
    }

    /// Record a drop observed outside the kernel maps (simulation mode, tests).
    pub fn record_drop(&self, ip: &IpAddr, bytes: u64) {
        if let Ok(mut m) = self.inner.blocked_ips.write() {
            if let Some(entry) = m.get_mut(ip) {
                entry.packets_dropped = entry.packets_dropped.saturating_add(1);
                entry.bytes_dropped = entry.bytes_dropped.saturating_add(bytes);
            }
        }
        self.inner.dropped_packets.fetch_add(1, Ordering::Relaxed);
        self.inner.dropped_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Clear all blocked IPs. Returns the number of entries whose kernel-side
    /// removal failed (they are logged individually).
    pub fn clear(&self) -> usize {
        let ips: Vec<IpAddr> = match self.inner.blocked_ips.write() {
            Ok(mut m) => {
                let keys: Vec<IpAddr> = m.keys().copied().collect();
                m.clear();
                keys
            }
            Err(_) => return 0,
        };

        if !self.is_enabled() {
            return 0;
        }

        let mut failures = 0;
        for ip in ips {
            if let Err(e) = self.sync_ip_to_kernel(&ip, false) {
                error!("Failed to remove {} from kernel map: {}", ip, e);
                failures += 1;
            }
        }
        failures
    }
}

/// Runs `bpftool -j map dump name <map>` and returns raw (key, value) byte pairs.
fn dump_map(map_name: &str) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    let out = Command::new("bpftool")
        .args(["-j", "map", "dump", "name", map_name])
        .output()
        .map_err(|e| debug!("bpftool unavailable for map {}: {}", map_name, e))
        .ok()?;

    if !out.status.success() {
        debug!(
            "bpftool map dump {} failed: {}",
            map_name,
            String::from_utf8_lossy(&out.stderr).trim()
        );
        return None;
    }

    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| warn!("Unparseable bpftool output for {}: {}", map_name, e))
        .ok()?;

    let entries = parsed.as_array()?;
    let mut result = Vec::with_capacity(entries.len());
    for entry in entries {
        let (Some(key), Some(value)) = (
            entry.get("key").and_then(hex_array),
            entry.get("value").and_then(hex_array),
        ) else {
            continue;
        };
        result.push((key, value));
    }
    Some(result)
}

/// Parses bpftool's `["0x0a","0x00",...]` byte arrays.
fn hex_array(value: &serde_json::Value) -> Option<Vec<u8>> {
    let arr = value.as_array()?;
    let mut bytes = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item.as_str()?;
        let s = s.trim_start_matches("0x");
        bytes.push(u8::from_str_radix(s, 16).ok()?);
    }
    Some(bytes)
}

fn le_u32(bytes: &[u8]) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn le_u64(bytes: &[u8]) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(raw))
}

/// Map keys hold the address in network byte order, exactly as written by
/// [`EbpfXdpManager::ip_to_hex`].
fn bytes_to_ip(bytes: &[u8], is_v6: bool) -> Option<IpAddr> {
    if is_v6 {
        let raw: [u8; 16] = bytes.get(..16)?.try_into().ok()?;
        Some(IpAddr::V6(Ipv6Addr::from(raw)))
    } else {
        let raw: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
        Some(IpAddr::V4(Ipv4Addr::from(raw)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_config_defaults() {
        let cfg = EbpfXdpConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.interface, "eth0");
        assert_eq!(cfg.mode, XdpMode::Skb);
        assert_eq!(cfg.map_name, "bsdm_blocked_ips");
        assert_eq!(cfg.max_entries, 65536);
        cfg.validate().expect("default config is valid");
    }

    #[test]
    fn test_ebpf_mode_parsing() {
        assert_eq!(XdpMode::parse("driver"), XdpMode::Driver);
        assert_eq!(XdpMode::parse("native"), XdpMode::Driver);
        assert_eq!(XdpMode::parse("offload"), XdpMode::Offload);
        assert_eq!(XdpMode::parse("hw"), XdpMode::Offload);
        assert_eq!(XdpMode::parse("skb"), XdpMode::Skb);
        assert_eq!(XdpMode::parse("generic"), XdpMode::Skb);
    }

    #[test]
    fn test_config_validation_rejects_unsupported_values() {
        let too_many = EbpfXdpConfig {
            max_entries: COMPILED_MAX_ENTRIES + 1,
            ..Default::default()
        };
        assert!(too_many.validate().is_err());

        let foreign_map = EbpfXdpConfig {
            map_name: "some_other_map".to_string(),
            ..Default::default()
        };
        assert!(foreign_map.validate().is_err());

        let odd_iface = EbpfXdpConfig {
            interface: "eth0; rm -rf /".to_string(),
            ..Default::default()
        };
        assert!(odd_iface.validate().is_err());

        let empty_iface = EbpfXdpConfig {
            interface: String::new(),
            ..Default::default()
        };
        assert!(empty_iface.validate().is_err());
    }

    #[test]
    fn test_ebpf_ipv4_and_ipv6_blocking() {
        let manager = EbpfXdpManager::new(EbpfXdpConfig::default());
        let ip_v4: IpAddr = "192.0.2.42".parse().expect("valid ipv4");
        let ip_v6: IpAddr = "2001:db8::1".parse().expect("valid ipv6");

        assert!(!manager.is_ip_blocked(&ip_v4));
        assert!(!manager.is_ip_blocked(&ip_v6));

        let entry_v4 = manager
            .block_ip(ip_v4, Some("Test v4 drop".to_string()))
            .expect("block v4");
        assert_eq!(entry_v4.ip, "192.0.2.42");
        assert_eq!(entry_v4.reason, "Test v4 drop");
        assert!(manager.is_ip_blocked(&ip_v4));

        // Duplicate blocks are rejected instead of silently resetting counters.
        assert!(manager.block_ip(ip_v4, None).is_err());

        let entry_v6 = manager
            .block_ip(ip_v6, Some("Test v6 drop".to_string()))
            .expect("block v6");
        assert_eq!(entry_v6.ip, "2001:db8::1");
        assert!(manager.is_ip_blocked(&ip_v6));

        // Stats should reflect active blocked count and initially 0 drops (no fake stubs)
        let stats = manager.stats();
        assert_eq!(stats.active_blocked_ips, 2);
        assert_eq!(stats.packets_dropped_total, 0);
        assert_eq!(stats.bytes_dropped_total, 0);
        assert!(!stats.attached);
        assert_eq!(stats.kernel_latency_us, None);

        // Record a drop and verify metrics update
        manager.record_drop(&ip_v4, 64);
        let updated_stats = manager.stats();
        assert_eq!(updated_stats.packets_dropped_total, 1);
        assert_eq!(updated_stats.bytes_dropped_total, 64);

        // Unblock by IP string
        assert!(manager.unblock_ip("192.0.2.42").expect("unblock v4"));
        assert!(!manager.is_ip_blocked(&ip_v4));

        // Unblock by ID
        assert!(manager.unblock_ip(&entry_v6.id).expect("unblock v6"));
        assert!(!manager.is_ip_blocked(&ip_v6));
        assert_eq!(manager.stats().active_blocked_ips, 0);

        // Unknown identifiers are reported as "not found", not as an error.
        assert!(!manager.unblock_ip("203.0.113.9").expect("unknown ip"));
    }

    #[test]
    fn test_clone_does_not_detach_shared_state() {
        let manager = EbpfXdpManager::new(EbpfXdpConfig::default());
        let ip: IpAddr = "198.51.100.7".parse().expect("valid ipv4");
        manager.block_ip(ip, None).expect("block");

        let handle = manager.clone();
        drop(handle);

        // The surviving handle still sees the shared registry.
        assert!(manager.is_ip_blocked(&ip));
        assert_eq!(manager.stats().active_blocked_ips, 1);
    }

    #[test]
    fn test_update_config_does_not_deadlock_with_blocked_entries() {
        let manager = EbpfXdpManager::new(EbpfXdpConfig::default());
        manager
            .block_ip("198.51.100.10".parse().expect("valid ipv4"), None)
            .expect("block v4");
        manager
            .block_ip("2001:db8::10".parse().expect("valid ipv6"), None)
            .expect("block v6");

        let mut cfg = manager.config();
        cfg.interface = "eth1".to_string();
        cfg.mode = XdpMode::Driver;
        manager.update_config(cfg).expect("update config");

        assert_eq!(manager.config().interface, "eth1");
        assert_eq!(manager.config().mode, XdpMode::Driver);
        assert_eq!(manager.stats().active_blocked_ips, 2);
    }

    #[test]
    fn test_update_config_rejects_invalid_settings() {
        let manager = EbpfXdpManager::new(EbpfXdpConfig::default());
        let mut cfg = manager.config();
        cfg.max_entries = COMPILED_MAX_ENTRIES * 4;
        assert!(manager.update_config(cfg).is_err());
        // Rejected updates must not be applied.
        assert_eq!(manager.config().max_entries, COMPILED_MAX_ENTRIES);
    }

    #[test]
    fn test_concurrent_block_and_config_update_do_not_deadlock() {
        use std::thread;

        let manager = EbpfXdpManager::new(EbpfXdpConfig::default());
        let writer = manager.clone();
        let updater = manager.clone();

        let t1 = thread::spawn(move || {
            for i in 0..200u8 {
                let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, i));
                let _ = writer.block_ip(ip, None);
                let _ = writer.unblock_ip(&ip.to_string());
            }
        });
        let t2 = thread::spawn(move || {
            for i in 0..200u32 {
                let mut cfg = updater.config();
                cfg.max_entries = 1024 + i;
                let _ = updater.update_config(cfg);
            }
        });

        t1.join().expect("blocker thread");
        t2.join().expect("updater thread");
    }

    #[test]
    fn test_hex_array_and_key_decoding() {
        let json: serde_json::Value =
            serde_json::from_str(r#"["0xc0","0x00","0x02","0x2a"]"#).expect("json");
        let bytes = hex_array(&json).expect("bytes");
        assert_eq!(bytes, vec![0xc0, 0x00, 0x02, 0x2a]);
        assert_eq!(
            bytes_to_ip(&bytes, false),
            Some("192.0.2.42".parse().expect("ipv4"))
        );
        assert_eq!(le_u64(&[1, 0, 0, 0, 0, 0, 0, 0]), Some(1));
        assert_eq!(le_u32(&[2, 0, 0, 0]), Some(2));
    }

    #[test]
    fn test_ip_to_hex_uses_network_byte_order() {
        let v4: IpAddr = "192.0.2.42".parse().expect("ipv4");
        assert_eq!(EbpfXdpManager::ip_to_hex(&v4), "c0 00 02 2a");
        let v6: IpAddr = "2001:db8::1".parse().expect("ipv6");
        assert_eq!(
            EbpfXdpManager::ip_to_hex(&v6),
            "20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01"
        );
    }
}
