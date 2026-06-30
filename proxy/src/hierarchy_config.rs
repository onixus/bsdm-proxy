//! Load hierarchical caching configuration from environment variables.

use crate::cache_digest::DigestRegistry;
use crate::hierarchy::{HierarchyConfig, HierarchyManager};
use crate::metrics::Metrics;
use crate::peers::{PeerConfig, PeerRegistry, PeerType};
use crate::selection::parse_strategy;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn env_flag_default_true(name: &str) -> bool {
    std::env::var(name)
        .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no"))
        .unwrap_or(true)
}

fn parse_peer_list(
    value: &str,
    peer_type: PeerType,
    default_icp_port: Option<u16>,
) -> Vec<PeerConfig> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(
            |entry| match PeerConfig::parse_from_string(entry, peer_type) {
                Ok(mut config) => {
                    if config.icp_port.is_none() {
                        config.icp_port = default_icp_port;
                    }
                    Some(config)
                }
                Err(e) => {
                    warn!("Skipping invalid peer '{}': {}", entry, e);
                    None
                }
            },
        )
        .collect()
}

pub fn load_hierarchy_config() -> HierarchyConfig {
    let icp_timeout_ms = std::env::var("ICP_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let parent_timeout_secs = std::env::var("PARENT_TIMEOUT_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let max_sibling_queries = std::env::var("ICP_MAX_SIBLING_QUERIES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    HierarchyConfig {
        enabled: env_flag("HIERARCHY_ENABLED"),
        icp_timeout: Duration::from_millis(icp_timeout_ms),
        parent_timeout: Duration::from_secs(parent_timeout_secs),
        max_sibling_queries,
        retry_parents: true,
        use_htcp: env_flag("HIERARCHY_USE_HTCP"),
        digest_enabled: env_flag_default_true("HIERARCHY_DIGEST_ENABLED"),
    }
}

/// Built hierarchy runtime: manager + shared digest registry for discovery and cache updates.
pub struct HierarchySetup {
    pub manager: Arc<HierarchyManager>,
    pub digest_registry: Arc<DigestRegistry>,
}

/// Build hierarchy manager from environment. Returns `None` when disabled.
pub async fn build_hierarchy_manager(
    config: &HierarchyConfig,
    metrics: Arc<Metrics>,
) -> Result<Option<HierarchySetup>, Box<dyn std::error::Error + Send + Sync>> {
    if !config.enabled {
        return Ok(None);
    }

    let digest_bit_count = std::env::var("HIERARCHY_DIGEST_BITS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(65_536);
    let digest_hash_count = std::env::var("HIERARCHY_DIGEST_HASHES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let digest_remote_ttl_secs = std::env::var("HIERARCHY_DIGEST_REMOTE_TTL_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let digest_registry = Arc::new(DigestRegistry::new(
        digest_bit_count,
        digest_hash_count,
        Duration::from_secs(digest_remote_ttl_secs),
    ));

    let registry = PeerRegistry::new();
    let sibling_query_port = if config.use_htcp {
        htcp_peer_port()
    } else {
        std::env::var("ICP_PEER_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3130)
    };

    if let Ok(parents) = std::env::var("CACHE_PARENTS") {
        for peer_config in parse_peer_list(&parents, PeerType::Parent, None) {
            registry.add_peer(peer_config).await;
        }
    }

    if let Ok(siblings) = std::env::var("CACHE_SIBLINGS") {
        for peer_config in parse_peer_list(&siblings, PeerType::Sibling, Some(sibling_query_port)) {
            registry.add_peer(peer_config).await;
        }
    }

    let strategy_name =
        std::env::var("CACHE_SELECTION_STRATEGY").unwrap_or_else(|_| "round-robin".to_string());
    let strategy = parse_strategy(&strategy_name);

    let mut manager = HierarchyManager::new(config.clone(), registry, strategy)
        .with_metrics(metrics)
        .with_digest_registry(digest_registry.clone())
        .with_htcp_peer_port(htcp_peer_port());

    if config.use_htcp {
        let client_bind =
            std::env::var("HTCP_CLIENT_BIND").unwrap_or_else(|_| "0.0.0.0:0".to_string());
        manager.init_htcp(&client_bind).await?;
        info!(
            "Hierarchy enabled (strategy={}, HTCP client bind={}, peer port={})",
            strategy_name, client_bind, htcp_peer_port()
        );
    } else {
        let client_bind =
            std::env::var("ICP_CLIENT_BIND").unwrap_or_else(|_| "0.0.0.0:0".to_string());
        manager.init_icp(&client_bind).await?;
        info!(
            "Hierarchy enabled (strategy={}, ICP client bind={})",
            strategy_name, client_bind
        );
    }

    if config.digest_enabled {
        info!(
            "Cache digest enabled (bits={}, hashes={}, remote_ttl={}s)",
            digest_bit_count, digest_hash_count, digest_remote_ttl_secs
        );
    }

    Ok(Some(HierarchySetup {
        manager: Arc::new(manager),
        digest_registry,
    }))
}

pub fn icp_server_bind_addr() -> String {
    std::env::var("ICP_BIND").unwrap_or_else(|_| "0.0.0.0:3130".to_string())
}

pub fn htcp_server_bind_addr() -> String {
    std::env::var("HTCP_BIND").unwrap_or_else(|_| "0.0.0.0:4827".to_string())
}

pub fn htcp_peer_port() -> u16 {
    std::env::var("HTCP_PEER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4827)
}

pub fn should_start_icp_server(config: &HierarchyConfig) -> bool {
    config.enabled
        && !config.use_htcp
        && std::env::var("ICP_SERVER_ENABLED")
            .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no"))
            .unwrap_or(true)
}

pub fn should_start_htcp_server(config: &HierarchyConfig) -> bool {
    config.enabled
        && config.use_htcp
        && std::env::var("HTCP_SERVER_ENABLED")
            .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no"))
            .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_parents_list() {
        let peers = parse_peer_list("127.0.0.1:1488:1.5", PeerType::Parent, None);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].host, "127.0.0.1");
        assert_eq!(peers[0].port, 1488);
        assert!((peers[0].weight - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_siblings_get_default_icp_port() {
        let peers = parse_peer_list("10.0.0.2:1488", PeerType::Sibling, Some(3130));
        assert_eq!(peers[0].icp_port, Some(3130));
    }

    #[test]
    fn parse_siblings_with_explicit_icp_port() {
        let peers = parse_peer_list("10.0.0.2:1488:1.0:3140", PeerType::Sibling, Some(3130));
        assert_eq!(peers[0].icp_port, Some(3140));
    }

    #[test]
    fn icp_server_skipped_when_htcp_enabled() {
        let config = HierarchyConfig {
            enabled: true,
            use_htcp: true,
            ..Default::default()
        };
        assert!(!should_start_icp_server(&config));
        assert!(should_start_htcp_server(&config));
    }
}
