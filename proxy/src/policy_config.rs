//! Load ACL and categorization configuration from environment variables.

use bsdm_proxy::acl::{AclAction, AclEngine};
use bsdm_proxy::acl_config::{load_acl_engine_from_file, parse_acl_action};
use bsdm_proxy::categorization::{CategorizationConfig, CategorizationEngine};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Clone)]
pub struct PolicyConfig {
    pub acl_enabled: bool,
    pub acl_engine: Option<Arc<RwLock<AclEngine>>>,
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

fn load_categorization_config() -> CategorizationConfig {
    let cache_ttl_secs = std::env::var("CATEGORIZATION_CACHE_TTL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600);

    CategorizationConfig {
        enabled: true,
        cache_ttl: Duration::from_secs(cache_ttl_secs),
        shallalist_enabled: env_flag("SHALLALIST_ENABLED"),
        shallalist_path: std::env::var("SHALLALIST_PATH").ok(),
        urlhaus_enabled: env_flag("URLHAUS_ENABLED"),
        urlhaus_api: std::env::var("URLHAUS_API")
            .unwrap_or_else(|_| "https://urlhaus-api.abuse.ch/v1/url/".to_string()),
        phishtank_enabled: env_flag("PHISHTANK_ENABLED"),
        phishtank_api: std::env::var("PHISHTANK_API")
            .unwrap_or_else(|_| "https://checkurl.phishtank.com/checkurl/".to_string()),
        custom_db_enabled: env_flag("CUSTOM_DB_ENABLED"),
        custom_db_path: std::env::var("CUSTOM_DB_PATH").ok(),
    }
}

pub fn load_policy_config() -> PolicyConfig {
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
        Some(Arc::new(RwLock::new(engine)))
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
}
