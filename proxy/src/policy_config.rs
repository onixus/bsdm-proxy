//! Load ACL and categorization configuration from environment variables.

use crate::acl::{AclAction, AclEngine, AclEngineHandle};
use crate::acl_config::{load_acl_engine_from_file, parse_acl_action};
use crate::categorization::{CategorizationConfig, CategorizationEngine};
use crate::pinning::PinningRegistry;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    Sni,
    SelectiveMitm,
    FullMitm,
}

impl PolicyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyMode::Sni => "sni",
            PolicyMode::SelectiveMitm => "selective-mitm",
            PolicyMode::FullMitm => "full-mitm",
        }
    }
}

impl std::str::FromStr for PolicyMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "sni" => Ok(PolicyMode::Sni),
            "selective-mitm" | "selective" => Ok(PolicyMode::SelectiveMitm),
            "full-mitm" | "full" => Ok(PolicyMode::FullMitm),
            other => Err(format!("Unknown policy mode: {}", other)),
        }
    }
}

impl std::fmt::Display for PolicyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Clone)]
pub struct PolicyConfig {
    pub policy_mode: PolicyMode,
    pub mitm_categories: Vec<String>,
    pub pinning_registry: Arc<PinningRegistry>,
    pub acl_enabled: bool,
    pub acl_engine: Option<Arc<AclEngineHandle>>,
    pub acl_rules_path: Option<String>,
    pub acl_auto_reload: bool,
    pub acl_reload_interval: Duration,
    pub categorization: Option<Arc<CategorizationEngine>>,
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn load_ut1_config() -> (bool, Option<String>) {
    let enabled = env_flag("UT1_ENABLED")
        || env_flag("LOCAL_CATEGORY_DB_ENABLED")
        || env_flag("SHALLALIST_ENABLED");

    let path = std::env::var("UT1_PATH")
        .ok()
        .or_else(|| std::env::var("LOCAL_CATEGORY_DB_PATH").ok())
        .or_else(|| std::env::var("SHALLALIST_PATH").ok());

    if env_flag("SHALLALIST_ENABLED") || std::env::var("SHALLALIST_PATH").is_ok() {
        warn!(
            "SHALLALIST_* env vars are deprecated; use UT1_ENABLED and UT1_PATH \
             (https://dsi.ut-capitole.fr/blacklists/index_en.php)"
        );
    }

    (enabled, path)
}

fn load_categorization_config() -> CategorizationConfig {
    let cache_ttl_secs = std::env::var("CATEGORIZATION_CACHE_TTL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600);

    let (ut1_enabled, ut1_path) = load_ut1_config();

    CategorizationConfig {
        enabled: true,
        cache_ttl: Duration::from_secs(cache_ttl_secs),
        ut1_enabled,
        ut1_path,
        urlhaus_enabled: env_flag("URLHAUS_ENABLED"),
        urlhaus_api: std::env::var("URLHAUS_API")
            .unwrap_or_else(|_| "https://urlhaus-api.abuse.ch/v1/url/".to_string()),
        phishtank_enabled: env_flag("PHISHTANK_ENABLED"),
        phishtank_api: std::env::var("PHISHTANK_API")
            .unwrap_or_else(|_| "https://checkurl.phishtank.com/checkurl/".to_string()),
        phishtank_api_key: std::env::var("PHISHTANK_API_KEY")
            .ok()
            .filter(|s| !s.is_empty()),
        custom_db_enabled: env_flag("CUSTOM_DB_ENABLED"),
        custom_db_path: std::env::var("CUSTOM_DB_PATH").ok(),
        rkn_sync_enabled: env_flag("RKN_SYNC_ENABLED"),
        rkn_sync_url: std::env::var("RKN_SYNC_URL").unwrap_or_else(|_| {
            "https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv".to_string()
        }),
        rkn_sync_interval_secs: std::env::var("RKN_SYNC_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(86400),
    }
}

pub fn configured_policy_mode() -> PolicyMode {
    std::env::var("POLICY_MODE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(PolicyMode::SelectiveMitm)
}

pub fn configured_mitm_categories() -> Vec<String> {
    std::env::var("MITM_CATEGORIES")
        .unwrap_or_else(|_| "malware,phishing,illegal-content".to_string())
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn load_policy_config() -> PolicyConfig {
    let policy_mode = configured_policy_mode();
    let mitm_categories = configured_mitm_categories();

    let pinning_registry = Arc::new(PinningRegistry::from_env().unwrap_or_else(|error| {
        panic!("Failed to load certificate pinning exception registry: {error}")
    }));

    info!(
        "Policy mode initialized: mode={}, mitm_categories={:?}, pinning_exceptions={}, pinning_source={}",
        policy_mode,
        mitm_categories,
        pinning_registry.snapshot().len(),
        pinning_registry.source()
    );

    let acl_enabled = env_flag("ACL_ENABLED");
    let default_action = std::env::var("ACL_DEFAULT_ACTION")
        .map(|v| parse_acl_action(&v))
        .unwrap_or(AclAction::Allow);
    let rules_path = std::env::var("ACL_RULES_PATH").ok();
    let acl_auto_reload = env_flag("ACL_AUTO_RELOAD");
    let acl_reload_interval = std::env::var("ACL_RELOAD_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(60));

    let acl_engine = if acl_enabled {
        let engine = if let Some(ref path) = rules_path {
            match load_acl_engine_from_file(path, default_action) {
                Ok(engine) => engine,
                Err(e) => {
                    warn!("Failed to load ACL rules from {}: {}", path, e);
                    AclEngine::new(default_action)
                }
            }
        } else {
            info!("ACL enabled without ACL_RULES_PATH, using default action only");
            AclEngine::new(default_action)
        };
        Some(Arc::new(AclEngineHandle::new(engine)))
    } else {
        None
    };

    let categorization = if env_flag("CATEGORIZATION_ENABLED") {
        Some(Arc::new(CategorizationEngine::new(
            load_categorization_config(),
        )))
    } else {
        None
    };

    PolicyConfig {
        policy_mode,
        mitm_categories,
        pinning_registry,
        acl_enabled,
        acl_engine,
        acl_rules_path: rules_path,
        acl_auto_reload,
        acl_reload_interval,
        categorization,
    }
}

pub fn reload_acl_engine(path: &str, fallback_default: AclAction) -> Result<AclEngine, String> {
    load_acl_engine_from_file(path, fallback_default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_acl_action_values() {
        assert_eq!(parse_acl_action("deny"), AclAction::Deny);
        assert_eq!(parse_acl_action("ALLOW"), AclAction::Allow);
        assert_eq!(parse_acl_action("redirect"), AclAction::Redirect);
    }

    #[test]
    fn parse_policy_mode_values() {
        assert_eq!("sni".parse::<PolicyMode>().unwrap(), PolicyMode::Sni);
        assert_eq!(
            "selective-mitm".parse::<PolicyMode>().unwrap(),
            PolicyMode::SelectiveMitm
        );
        assert_eq!(
            "selective".parse::<PolicyMode>().unwrap(),
            PolicyMode::SelectiveMitm
        );
        assert_eq!(
            "full-mitm".parse::<PolicyMode>().unwrap(),
            PolicyMode::FullMitm
        );
        assert_eq!("full".parse::<PolicyMode>().unwrap(), PolicyMode::FullMitm);
        assert!("invalid".parse::<PolicyMode>().is_err());
    }
}
