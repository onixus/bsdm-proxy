//! Hierarchy Manager
//!
//! Coordinates request flow through cache hierarchy:
//! Local cache → Siblings (ICP) → Parents → Origin

use crate::cache_digest::DigestRegistry;
use crate::htcp::{HtcpClient, HtcpOpcode};
use crate::icp::{IcpClient, IcpOpcode};
use crate::cache_key::http_cache_key;
use crate::metrics::Metrics;
use crate::peers::{CachePeer, PeerRegistry};
use crate::selection::SelectionStrategy;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

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
    /// Use HTCP instead of ICP for sibling queries
    pub use_htcp: bool,
    /// Use cache digests to skip sibling ICP/HTCP queries
    pub digest_enabled: bool,
}

impl Default for HierarchyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            icp_timeout: Duration::from_millis(100),
            parent_timeout: Duration::from_secs(5),
            max_sibling_queries: 10,
            retry_parents: true,
            use_htcp: false,
            digest_enabled: true,
        }
    }
}

/// Manages cache hierarchy traversal
pub struct HierarchyManager {
    config: HierarchyConfig,
    peer_registry: PeerRegistry,
    selection_strategy: Box<dyn SelectionStrategy>,
    icp_client: Option<Arc<IcpClient>>,
    htcp_client: Option<Arc<HtcpClient>>,
    digest_registry: Option<Arc<DigestRegistry>>,
    htcp_peer_port: u16,
    metrics: Option<Arc<Metrics>>,
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
            htcp_client: None,
            digest_registry: None,
            htcp_peer_port: 4827,
            metrics: None,
        }
    }

    pub fn with_digest_registry(mut self, registry: Arc<DigestRegistry>) -> Self {
        self.digest_registry = Some(registry);
        self
    }

    pub fn with_htcp_peer_port(mut self, port: u16) -> Self {
        self.htcp_peer_port = port;
        self
    }

    pub fn peer_registry(&self) -> PeerRegistry {
        self.peer_registry.clone()
    }

    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Initialize ICP client (skipped when HTCP is selected for sibling queries).
    pub async fn init_icp(&mut self, bind_addr: &str) -> Result<(), std::io::Error> {
        if self.config.use_htcp {
            return Ok(());
        }
        let client = IcpClient::new(bind_addr).await?;
        self.icp_client = Some(Arc::new(client));
        info!("ICP client initialized on {}", bind_addr);
        Ok(())
    }

    /// Initialize HTCP client for sibling queries.
    pub async fn init_htcp(&mut self, bind_addr: &str) -> Result<(), std::io::Error> {
        let client = HtcpClient::new(bind_addr).await?;
        self.htcp_client = Some(Arc::new(client));
        info!("HTCP client initialized on {}", bind_addr);
        Ok(())
    }

    /// Check if hierarchy is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Timeout for HTTP requests to parent/sibling peers.
    pub fn parent_timeout(&self) -> Duration {
        self.config.parent_timeout
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
            self.record_resolution("sibling_hit", start);
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
            self.record_resolution("parent_hit", start);
            return HierarchyResult::ParentHit(parent);
        }

        // Step 3: Fall back to origin
        debug!(
            "No cache peer available for {}, fetching from origin ({}ms)",
            url,
            start.elapsed().as_millis()
        );
        self.record_resolution("origin_required", start);
        HierarchyResult::OriginRequired
    }

    fn record_resolution(&self, result: &str, start: Instant) {
        if let Some(metrics) = &self.metrics {
            metrics.record_hierarchy_resolution(result);
            metrics.observe_hierarchy_lookup(start.elapsed().as_secs_f64());
        }
    }

    /// Query sibling caches via ICP or HTCP (with optional cache-digest filtering).
    async fn query_siblings(&self, url: &str) -> Option<Arc<CachePeer>> {
        let siblings = self.peer_registry.sibling_caches().await;
        if siblings.is_empty() {
            return None;
        }

        let cache_key = http_cache_key("GET", url);
        let mut candidates: Vec<Arc<CachePeer>> = Vec::new();
        let mut digest_skipped = 0usize;

        for sibling in siblings {
            if self.config.digest_enabled {
                if let Some(registry) = &self.digest_registry {
                    if let Some(false) =
                        registry.peer_might_have_url(&sibling.id, cache_key.as_ref()).await
                    {
                        digest_skipped += 1;
                        continue;
                    }
                }
            }
            candidates.push(sibling);
        }

        if let Some(metrics) = &self.metrics {
            for _ in 0..digest_skipped {
                metrics.record_hierarchy_digest_skip();
            }
        }

        if candidates.is_empty() {
            return None;
        }

        if self.config.use_htcp {
            return self.query_siblings_htcp(url, &candidates).await;
        }
        self.query_siblings_icp(url, &candidates).await
    }

    async fn query_siblings_icp(
        &self,
        url: &str,
        siblings: &[Arc<CachePeer>],
    ) -> Option<Arc<CachePeer>> {
        let icp_client = self.icp_client.as_ref()?;

        let sibling_addrs: Vec<_> = siblings
            .iter()
            .filter_map(|s| {
                s.config
                    .icp_port
                    .map(|port| format!("{}:{}", s.config.host, port).parse().ok())
            })
            .flatten()
            .take(self.config.max_sibling_queries)
            .collect();

        if sibling_addrs.is_empty() {
            return None;
        }

        debug!(
            "Querying {} siblings via ICP for {}",
            sibling_addrs.len(),
            url
        );

        let results = icp_client
            .query_peers(&sibling_addrs, url, self.config.icp_timeout)
            .await;

        self.process_sibling_results(siblings, &results, IcpOpcode::Hit)
    }

    async fn query_siblings_htcp(
        &self,
        url: &str,
        siblings: &[Arc<CachePeer>],
    ) -> Option<Arc<CachePeer>> {
        let htcp_client = self.htcp_client.as_ref()?;
        let sibling_addrs: Vec<_> = siblings
            .iter()
            .filter_map(|s| format!("{}:{}", s.config.host, self.htcp_peer_port).parse().ok())
            .take(self.config.max_sibling_queries)
            .collect();

        if sibling_addrs.is_empty() {
            return None;
        }

        debug!(
            "Querying {} siblings via HTCP for {}",
            sibling_addrs.len(),
            url
        );

        let results = htcp_client
            .query_peers(&sibling_addrs, url, self.config.icp_timeout)
            .await;

        self.map_htcp_results(siblings, &results)
    }

    fn process_sibling_results(
        &self,
        siblings: &[Arc<CachePeer>],
        results: &[crate::icp::IcpResult],
        hit_opcode: IcpOpcode,
    ) -> Option<Arc<CachePeer>> {
        let responded = results.len();
        for result in results {
            if let Some(metrics) = &self.metrics {
                let outcome = match result.response {
                    IcpOpcode::Hit => "hit",
                    IcpOpcode::Miss => "miss",
                    IcpOpcode::Error | IcpOpcode::Denied => "error",
                    _ => "error",
                };
                metrics.record_hierarchy_icp_query(outcome);
            }
        }
        if let Some(metrics) = &self.metrics {
            let total = siblings.len().min(self.config.max_sibling_queries);
            for _ in 0..total.saturating_sub(responded) {
                metrics.record_hierarchy_icp_query("timeout");
            }
        }

        for result in results {
            if result.response == hit_opcode {
                for sibling in siblings {
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

    fn map_htcp_results(
        &self,
        siblings: &[Arc<CachePeer>],
        results: &[crate::htcp::HtcpResult],
    ) -> Option<Arc<CachePeer>> {
        for result in results {
            if let Some(metrics) = &self.metrics {
                let outcome = match result.response {
                    HtcpOpcode::Hit => "hit",
                    HtcpOpcode::Miss => "miss",
                    HtcpOpcode::Error => "error",
                    _ => "error",
                };
                metrics.record_hierarchy_icp_query(outcome);
            }
        }

        for result in results {
            if result.response == HtcpOpcode::Hit {
                for sibling in siblings {
                    let addr = format!("{}:{}", sibling.config.host, self.htcp_peer_port);
                    if addr == result.peer.to_string() {
                        sibling.update_rtt(result.latency);
                        return Some(sibling.clone());
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
        self.selection_strategy.select(&parents, url).cloned()
    }

    /// Record successful fetch from peer
    pub async fn record_peer_hit(&self, peer: &CachePeer, bytes: u64) {
        if let Some(metrics) = &self.metrics {
            metrics.record_hierarchy_peer_request(&peer.config.peer_type.to_string(), "hit");
        }
        peer.stats.record_request().await;
        peer.stats.record_hit(bytes).await;
    }

    /// Record miss from peer
    pub async fn record_peer_miss(&self, peer: &CachePeer) {
        if let Some(metrics) = &self.metrics {
            metrics.record_hierarchy_peer_request(&peer.config.peer_type.to_string(), "miss");
        }
        peer.stats.record_request().await;
        peer.stats.record_miss().await;
    }

    /// Record error from peer
    pub async fn record_peer_error(&self, peer: &CachePeer) {
        if let Some(metrics) = &self.metrics {
            metrics.record_hierarchy_peer_request(&peer.config.peer_type.to_string(), "error");
        }
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
        summary.push_str(&format!(
            "Selection strategy: {}\n",
            self.selection_strategy.name()
        ));
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
    use crate::PeerType;

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

        assert_eq!(
            peer.stats
                .requests
                .load(std::sync::atomic::Ordering::Relaxed),
            3
        );
        assert_eq!(
            peer.stats.hits.load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(
            peer.stats.misses.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(peer.stats.hit_rate(), 2.0 / 3.0);
    }
}
