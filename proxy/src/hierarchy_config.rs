//! Load hierarchical caching configuration from environment variables.

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
    }
}

/// Build hierarchy manager from environment. Returns `None` when disabled.
pub async fn build_hierarchy_manager(
    config: &HierarchyConfig,
    metrics: Arc<Metrics>,
) -> Result<Option<Arc<HierarchyManager>>, Box<dyn std::error::Error + Send + Sync>> {
    if !config.enabled {
        return Ok(None);
    }

    let registry = PeerRegistry::new();
    let sibling_icp_port = std::env::var("ICP_PEER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .or(Some(3130));

    if let Ok(parents) = std::env::var("CACHE_PARENTS") {
        for peer_config in parse_peer_list(&parents, PeerType::Parent, None) {
            registry.add_peer(peer_config).await;
        }
    }

    if let Ok(siblings) = std::env::var("CACHE_SIBLINGS") {
        for peer_config in parse_peer_list(&siblings, PeerType::Sibling, sibling_icp_port) {
            registry.add_peer(peer_config).await;
        }
    }

    let strategy_name =
        std::env::var("CACHE_SELECTION_STRATEGY").unwrap_or_else(|_| "round-robin".to_string());
    let strategy = parse_strategy(&strategy_name);

    let mut manager =
        HierarchyManager::new(config.clone(), registry, strategy).with_metrics(metrics);

    let client_bind = std::env::var("ICP_CLIENT_BIND").unwrap_or_else(|_| "0.0.0.0:0".to_string());
    manager.init_icp(&client_bind).await?;

    info!(
        "Hierarchy enabled (strategy={}, ICP client bind={})",
        strategy_name, client_bind
    );

    Ok(Some(Arc::new(manager)))
}

pub fn icp_server_bind_addr() -> String {
    std::env::var("ICP_BIND").unwrap_or_else(|_| "0.0.0.0:3130".to_string())
}

pub fn should_start_icp_server(config: &HierarchyConfig) -> bool {
    config.enabled
        && std::env::var("ICP_SERVER_ENABLED")
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
}
