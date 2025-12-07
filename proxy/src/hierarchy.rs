//! Hierarchy Manager
//!
//! Coordinates request flow through cache hierarchy:
//! Local cache → Siblings (ICP) → Parents → Origin

use crate::icp::{IcpClient, IcpOpcode};
use crate::peers::{CachePeer, PeerRegistry, PeerType};
use crate::selection::SelectionStrategy;
use bytes::Bytes;
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

type Body = http_body_util::Full<Bytes>;

/// Result of hierarchy query
#[derive(Debug, Clone)]
pub enum HierarchyResult {
    /// Found in local cache
    LocalHit,
    /// Found in sibling cache
    SiblingHit(Arc<CachePeer>),
    /// Found in parent cache
    ParentHit(Arc<CachePeer>),
    /// Must fetch from origin
    OriginRequired,
}

/// Configuration for hierarchy manager
#[derive(Clone)]
pub struct HierarchyConfig {
    /// Enable hierarchical caching
    pub enabled: bool,
    /// ICP query timeout
    pub icp_timeout: Duration,
    /// Parent request timeout
    pub parent_timeout: Duration,
    /// Maximum sibling queries in parallel
    pub max_sibling_queries: usize,
    /// Retry parent on failure
    pub retry_parents: bool,
}

impl Default for HierarchyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            icp_timeout: Duration::from_millis(100),
            parent_timeout: Duration::from_secs(5),
            max_sibling_queries: 10,
            retry_parents: true,
        }
    }
}

/// Manages cache hierarchy traversal
pub struct HierarchyManager {
    config: HierarchyConfig,
    peer_registry: PeerRegistry,
    selection_strategy: Box<dyn SelectionStrategy>,
    icp_client: Option<Arc<IcpClient>>,
}

impl HierarchyManager {
    pub fn new(
        config: HierarchyConfig,
        peer_registry: PeerRegistry,
        selection_strategy: Box<dyn SelectionStrategy>,
    ) -> Self {
        Self {
            config,
            peer_registry,
            selection_strategy,
            icp_client: None,
        }
    }

    /// Initialize ICP client
    pub async fn init_icp(&mut self, bind_addr: &str) -> Result<(), std::io::Error> {
        let client = IcpClient::new(bind_addr).await?;
        self.icp_client = Some(Arc::new(client));
        info!("ICP client initialized on {}", bind_addr);
        Ok(())
    }

    /// Check if hierarchy is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Determine where to fetch the resource from
    pub async fn resolve_source(&self, url: &str) -> HierarchyResult {
        if !self.config.enabled {
            return HierarchyResult::OriginRequired;
        }

        let start = Instant::now();

        // Step 1: Check siblings via ICP (parallel queries)
        if let Some(sibling) = self.query_siblings(url).await {
            debug!(
                "Sibling HIT for {} from {} ({}ms)",
                url,
                sibling.id,
                start.elapsed().as_millis()
            );
            return HierarchyResult::SiblingHit(sibling);
        }

        // Step 2: Try parents (sequential with failover)
        if let Some(parent) = self.select_parent(url).await {
            debug!(
                "Parent selected for {}: {} ({}ms)",
                url,
                parent.id,
                start.elapsed().as_millis()
            );
            return HierarchyResult::ParentHit(parent);
        }

        // Step 3: Fall back to origin
        debug!(
            "No cache peer available for {}, fetching from origin ({}ms)",
            url,
            start.elapsed().as_millis()
        );
        HierarchyResult::OriginRequired
    }

    /// Query sibling caches via ICP
    async fn query_siblings(&self, url: &str) -> Option<Arc<CachePeer>> {
        let icp_client = self.icp_client.as_ref()?;
        let siblings = self.peer_registry.sibling_caches().await;
        
        if siblings.is_empty() {
            return None;
        }

        // Collect sibling addresses with ICP ports
        let sibling_addrs: Vec<_> = siblings
            .iter()
            .filter_map(|s| {
                s.config.icp_port.map(|port| {
                    format!("{}:{}", s.config.host, port)
                        .parse()
                        .ok()
                })
            })
            .flatten()
            .take(self.config.max_sibling_queries)
            .collect();

        if sibling_addrs.is_empty() {
            return None;
        }

        debug!("Querying {} siblings via ICP for {}", sibling_addrs.len(), url);

        // Query siblings in parallel
        let results = icp_client
            .query_peers(&sibling_addrs, url, self.config.icp_timeout)
            .await;

        // Find first HIT
        for result in results {
            if result.response == IcpOpcode::Hit {
                // Find corresponding peer
                for sibling in &siblings {
                    if let Some(icp_port) = sibling.config.icp_port {
                        let addr = format!("{}:{}", sibling.config.host, icp_port);
                        if addr == result.peer.to_string() {
                            sibling.update_rtt(result.latency);
                            return Some(sibling.clone());
                        }
                    }
                }
            }
        }

        None
    }

    /// Select a parent cache using configured strategy
    async fn select_parent(&self, url: &str) -> Option<Arc<CachePeer>> {
        let parents = self.peer_registry.parent_caches().await;
        
        if parents.is_empty() {
            return None;
        }

        // Use selection strategy
        self.selection_strategy
            .select(&parents, url)
            .cloned()
    }

    /// Record successful fetch from peer
    pub async fn record_peer_hit(&self, peer: &CachePeer, bytes: u64) {
        peer.stats.record_request().await;
        peer.stats.record_hit(bytes).await;
    }

    /// Record miss from peer
    pub async fn record_peer_miss(&self, peer: &CachePeer) {
        peer.stats.record_request().await;
        peer.stats.record_miss().await;
    }

    /// Record error from peer
    pub async fn record_peer_error(&self, peer: &CachePeer) {
        peer.stats.record_request().await;
        peer.stats.record_error().await;
        
        // Check if peer should be marked unhealthy
        let error_rate = peer.stats.error_rate();
        if error_rate > 0.5 {
            peer.set_healthy(false);
            warn!(
                "Peer {} marked unhealthy (error rate: {:.1}%)",
                peer.id,
                error_rate * 100.0
            );
        }
    }

    /// Get hierarchy statistics
    pub async fn stats_summary(&self) -> String {
        let mut summary = String::new();
        summary.push_str(&format!("Hierarchy enabled: {}\n", self.config.enabled));
        summary.push_str(&format!("Selection strategy: {}\n", self.selection_strategy.name()));
        summary.push_str(&format!("ICP timeout: {:?}\n", self.config.icp_timeout));
        
        let siblings = self.peer_registry.sibling_caches().await;
        let parents = self.peer_registry.parent_caches().await;
        
        summary.push_str(&format!("Siblings: {}\n", siblings.len()));
        summary.push_str(&format!("Parents: {}\n", parents.len()));
        
        summary.push_str(&self.peer_registry.stats_summary().await);
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peers::PeerConfig;
    use crate::selection::RoundRobinStrategy;

    #[tokio::test]
    async fn test_hierarchy_disabled() {
        let config = HierarchyConfig {
            enabled: false,
            ..Default::default()
        };
        let registry = PeerRegistry::new();
        let strategy = Box::new(RoundRobinStrategy::new());
        
        let manager = HierarchyManager::new(config, registry, strategy);
        
        let result = manager.resolve_source("http://example.com/test").await;
        assert!(matches!(result, HierarchyResult::OriginRequired));
    }

    #[tokio::test]
    async fn test_parent_selection() {
        let config = HierarchyConfig {
            enabled: true,
            ..Default::default()
        };
        let registry = PeerRegistry::new();
        
        // Add parent
        let parent_config = PeerConfig {
            host: "parent.example.com".to_string(),
            port: 1488,
            peer_type: PeerType::Parent,
            weight: 1.0,
            icp_port: None,
            max_connections: 100,
        };
        registry.add_peer(parent_config).await;
        
        let strategy = Box::new(RoundRobinStrategy::new());
        let manager = HierarchyManager::new(config, registry, strategy);
        
        let result = manager.resolve_source("http://example.com/test").await;
        assert!(matches!(result, HierarchyResult::ParentHit(_)));
    }

    #[tokio::test]
    async fn test_peer_statistics() {
        let registry = PeerRegistry::new();
        
        let peer_config = PeerConfig {
            host: "test.example.com".to_string(),
            port: 1488,
            peer_type: PeerType::Parent,
            weight: 1.0,
            icp_port: None,
            max_connections: 100,
        };
        let peer = registry.add_peer(peer_config).await;
        
        let config = HierarchyConfig::default();
        let strategy = Box::new(RoundRobinStrategy::new());
        let manager = HierarchyManager::new(config, registry, strategy);
        
        // Record some hits
        manager.record_peer_hit(&peer, 1024).await;
        manager.record_peer_hit(&peer, 2048).await;
        manager.record_peer_miss(&peer).await;
        
        assert_eq!(peer.stats.requests.load(std::sync::atomic::Ordering::Relaxed), 3);
        assert_eq!(peer.stats.hits.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert_eq!(peer.stats.misses.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(peer.stats.hit_rate(), 2.0 / 3.0);
    }
}
