//! Persist and apply operator configuration from the admin console.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use tokio::sync::watch;
use tracing::{info, warn};

/// Canonical Roskomnadzor dump mirror (GitHub raw URLs currently return 404).
pub const DEFAULT_RKN_SYNC_URL: &str = "https://svn.code.sf.net/p/zapret-info/code/dump.csv";

const ENV_HEADER: &str = "# Managed by BSDM Admin Console — do not edit while proxy is running\n";

/// Keys whose values are masked in GET /api/config responses.
const SECRET_MARKERS: &[&str] = &[
    "_TOKEN",
    "_PASSWORD",
    "_SECRET",
    "_KEY",
    "API_KEY",
    "BIND_PASSWORD",
    "CLIENT_SECRET",
];

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigApplyRequest {
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub acl_rules: Option<serde_json::Value>,
    #[serde(default)]
    pub restart: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfigApplyResponse {
    pub status: &'static str,
    pub env_path: String,
    pub hot_reload: Vec<String>,
    pub restart: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfigSnapshotResponse {
    pub env_path: String,
    pub env: BTreeMap<String, String>,
}

pub fn config_env_path() -> PathBuf {
    if let Ok(path) = std::env::var("CONFIG_ENV_PATH") {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }
    let etc = Path::new("/etc/bsdm-proxy/bsdm-proxy.env");
    if etc.is_file() {
        return etc.to_path_buf();
    }
    PathBuf::from("./bsdm-proxy.env")
}

pub fn parse_env_text(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        map.insert(key.to_string(), value.to_string());
    }
    map
}

pub fn format_env_file(vars: &HashMap<String, String>) -> String {
    let mut keys: Vec<_> = vars.keys().collect();
    keys.sort();
    let mut out = String::from(ENV_HEADER);
    for key in keys {
        let value = &vars[key];
        if value.is_empty() {
            continue;
        }
        out.push_str(key);
        out.push('=');
        out.push_str(value);
        out.push('\n');
    }
    out
}

pub fn apply_env_map(vars: &HashMap<String, String>) {
    for (key, value) in vars {
        if value.is_empty() {
            std::env::remove_var(key);
        } else {
            std::env::set_var(key, value);
        }
    }
}

pub fn mask_secret_value(key: &str, value: &str) -> String {
    if is_secret_key(key) && !value.is_empty() {
        "***".to_string()
    } else {
        value.to_string()
    }
}

pub fn mask_env_map(vars: &HashMap<String, String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (key, value) in vars {
        out.insert(key.clone(), mask_secret_value(key, value));
    }
    out
}

fn is_secret_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    SECRET_MARKERS.iter().any(|marker| upper.contains(marker))
}

pub fn read_env_file() -> Result<HashMap<String, String>, String> {
    let path = config_env_path();
    if !path.is_file() {
        return Ok(HashMap::new());
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    Ok(parse_env_text(&content))
}

pub fn write_env_file(vars: &HashMap<String, String>) -> Result<PathBuf, String> {
    let path = config_env_path();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
        }
    }
    let content = format_env_file(vars);
    let tmp = path.with_extension("env.tmp");
    std::fs::write(&tmp, &content)
        .map_err(|e| format!("failed to write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("failed to replace {}: {e}", path.display())
    })?;
    Ok(path)
}

pub fn write_acl_rules_file(path: &str, rules: &serde_json::Value) -> Result<(), String> {
    serde_json::from_value::<crate::acl_config::AclRulesDocument>(rules.clone())
        .map_err(|e| format!("invalid acl_rules payload: {e}"))?;
    let content = serde_json::to_string_pretty(rules)
        .map_err(|e| format!("failed to serialize acl_rules: {e}"))?;
    let path_buf = PathBuf::from(path);
    if let Some(parent) = path_buf.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
        }
    }
    let tmp = path_buf.with_extension("json.tmp");
    std::fs::write(&tmp, format!("{content}\n"))
        .map_err(|e| format!("failed to write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path_buf).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("failed to replace {}: {e}", path_buf.display())
    })?;
    Ok(())
}

pub fn config_snapshot() -> Result<ConfigSnapshotResponse, String> {
    let path = config_env_path();
    let mut env = read_env_file()?;
    if env.is_empty() {
        env = snapshot_process_env();
    }
    Ok(ConfigSnapshotResponse {
        env_path: path.display().to_string(),
        env: mask_env_map(&env),
    })
}

fn snapshot_process_env() -> HashMap<String, String> {
    std::env::vars().collect()
}

pub fn schedule_service_restart(shutdown_tx: watch::Sender<bool>) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(750)).await;

        if let Ok(cmd) = std::env::var("CONFIG_RESTART_CMD") {
            if !cmd.trim().is_empty() {
                info!("Executing CONFIG_RESTART_CMD after config apply");
                match tokio::process::Command::new("sh")
                    .arg("-c")
                    .arg(&cmd)
                    .spawn()
                {
                    Ok(_) => {
                        let _ = shutdown_tx.send(true);
                        return;
                    }
                    Err(error) => warn!("CONFIG_RESTART_CMD failed: {error}"),
                }
            }
        }

        if let Ok(exe) = std::env::current_exe() {
            let args: Vec<String> = std::env::args().skip(1).collect();
            match tokio::process::Command::new(exe).args(&args).spawn() {
                Ok(_) => {
                    info!("Spawned replacement proxy process after config apply");
                    let _ = shutdown_tx.send(true);
                    return;
                }
                Err(error) => warn!("Self-restart spawn failed: {error}"),
            }
        }

        warn!("Config applied; shutting down without replacement process");
        let _ = shutdown_tx.send(true);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_format_env_roundtrip() {
        let text = "# comment\nHTTP_PORT=3128\n\nMETRICS_PORT=9090\n";
        let map = parse_env_text(text);
        assert_eq!(map.get("HTTP_PORT"), Some(&"3128".to_string()));
        let formatted = format_env_file(&map);
        assert!(formatted.contains("HTTP_PORT=3128"));
        assert!(formatted.contains("METRICS_PORT=9090"));
    }

    #[test]
    fn masks_secret_keys() {
        assert_eq!(
            mask_secret_value("CONTROL_API_TOKEN", "secret"),
            "***".to_string()
        );
        assert_eq!(mask_secret_value("HTTP_PORT", "3128"), "3128".to_string());
    }

    #[test]
    fn default_rkn_url_is_sf_mirror() {
        assert!(DEFAULT_RKN_SYNC_URL.contains("sf.net"));
    }
}
