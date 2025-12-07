//! Cache Peer Management
//!
//! Manages parent and sibling cache peers for hierarchical caching.
//! Tracks peer health, RTT, statistics, and connection pools.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Type of cache peer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerType {
    /// Parent cache - queried on miss before going to origin
    Parent,
    /// Sibling cache - queried via ICP, only if HIT
    Sibling,
}

impl std::fmt::Display for PeerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerType::Parent => write!(f, "parent"),
            PeerType::Sibling => write!(f, "sibling"),
        }
    }
}

/// Statistics for a cache peer
#[derive(Debug, Default)]
pub struct PeerStats {
    pub requests: AtomicU64,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub errors: AtomicU64,
    pub bytes_received: AtomicU64,
    pub last_success: RwLock<Option<Instant>>,
    pub last_failure: RwLock<Option<Instant>>,
}

impl PeerStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn record_request(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn record_hit(&self, bytes: u64) {
        self.hits.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        *self.last_success.write().await = Some(Instant::now());
    }

    pub async fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
        *self.last_success.write().await = Some(Instant::now());
    }

    pub async fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        *self.last_failure.write().await = Some(Instant::now());
    }

    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed) as f64;
        let total = (self.hits.load(Ordering::Relaxed) + self.misses.load(Ordering::Relaxed)) as f64;
        if total == 0.0 {
            0.0
        } else {
            hits / total
        }
    }

    pub fn error_rate(&self) -> f64 {
        let errors = self.errors.load(Ordering::Relaxed) as f64;
        let total = self.requests.load(Ordering::Relaxed) as f64;
        if total == 0.0 {
            0.0
        } else {
            errors / total
        }
    }
}

/// Configuration for a cache peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub host: String,
    pub port: u16,
    pub peer_type: PeerType,
    pub weight: f64,
    pub icp_port: Option<u16>,
    pub max_connections: usize,
}

impl PeerConfig {
    pub fn parse_from_string(s: &str, peer_type: PeerType) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 2 {
            return Err("Invalid peer format. Expected host:port[:weight]".to_string());
        }

        let host = parts[0].to_string();
        let port = parts[1].parse::<u16>()
            .map_err(|e| format!("Invalid port: {}", e))?;
        let weight = if parts.len() > 2 {
            parts[2].parse::<f64>()
                .map_err(|e| format!("Invalid weight: {}", e))?
        } else {
            1.0
        };

        Ok(Self {
            host,
            port,
            peer_type,
            weight,
            icp_port: None,
            max_connections: 100,
        })
    }
}

/// A cache peer (parent or sibling)
#[derive(Debug)]
pub struct CachePeer {
    pub id: String,
    pub config: PeerConfig,
    pub healthy: AtomicBool,
    pub rtt_ms: AtomicU64,
    pub stats: PeerStats,
    pub created_at: Instant,
}

impl CachePeer {
    pub fn new(config: PeerConfig) -> Self {
        let id = format!("{}:{}:{}", config.peer_type, config.host, config.port);
        info!("Creating cache peer: {} (type: {}, weight: {})", 
              id, config.peer_type, config.weight);
        
        Self {
            id,
            config,
            healthy: AtomicBool::new(true),
            rtt_ms: AtomicU64::new(0),
            stats: PeerStats::new(),
            created_at: Instant::now(),
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    pub fn set_healthy(&self, healthy: bool) {
        let was_healthy = self.healthy.swap(healthy, Ordering::Relaxed);
        if was_healthy != healthy {
            if healthy {
                info!("Peer {} is now healthy", self.id);
            } else {
                warn!("Peer {} is now unhealthy", self.id);
            }
        }
    }

    pub fn rtt(&self) -> Duration {
        Duration::from_millis(self.rtt_ms.load(Ordering::Relaxed))
    }

    pub fn update_rtt(&self, rtt: Duration) {
        let rtt_ms = rtt.as_millis() as u64;
        self.rtt_ms.store(rtt_ms, Ordering::Relaxed);
        debug!("Peer {} RTT updated to {}ms", self.id, rtt_ms);
    }

    pub fn score(&self) -> f64 {
        if !self.is_healthy() {
            return 0.0;
        }

        let base_score = self.config.weight;
        let error_rate = self.stats.error_rate();
        let rtt_factor = 1.0 / (1.0 + (self.rtt().as_millis() as f64 / 100.0));
        
        base_score * (1.0 - error_rate) * rtt_factor
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.config.host, self.config.port)
    }
}

/// Manages all cache peers
#[derive(Clone)]
pub struct PeerRegistry {
    peers: Arc<RwLock<HashMap<String, Arc<CachePeer>>>>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a peer to the registry
    pub async fn add_peer(&self, config: PeerConfig) -> Arc<CachePeer> {
        let peer = Arc::new(CachePeer::new(config));
        let id = peer.id.clone();
        self.peers.write().await.insert(id, peer.clone());
        peer
    }

    /// Remove a peer from the registry
    pub async fn remove_peer(&self, id: &str) -> bool {
        self.peers.write().await.remove(id).is_some()
    }

    /// Get a peer by ID
    pub async fn get_peer(&self, id: &str) -> Option<Arc<CachePeer>> {
        self.peers.read().await.get(id).cloned()
    }

    /// Get all peers
    pub async fn all_peers(&self) -> Vec<Arc<CachePeer>> {
        self.peers.read().await.values().cloned().collect()
    }

    /// Get all healthy peers
    pub async fn healthy_peers(&self) -> Vec<Arc<CachePeer>> {
        self.all_peers().await
            .into_iter()
            .filter(|p| p.is_healthy())
            .collect()
    }

    /// Get peers by type
    pub async fn peers_by_type(&self, peer_type: PeerType) -> Vec<Arc<CachePeer>> {
        self.all_peers().await
            .into_iter()
            .filter(|p| p.config.peer_type == peer_type)
            .collect()
    }

    /// Get healthy peers by type
    pub async fn healthy_peers_by_type(&self, peer_type: PeerType) -> Vec<Arc<CachePeer>> {
        self.healthy_peers().await
            .into_iter()
            .filter(|p| p.config.peer_type == peer_type)
            .collect()
    }

    /// Get parent caches
    pub async fn parent_caches(&self) -> Vec<Arc<CachePeer>> {
        self.healthy_peers_by_type(PeerType::Parent).await
    }

    /// Get sibling caches
    pub async fn sibling_caches(&self) -> Vec<Arc<CachePeer>> {
        self.healthy_peers_by_type(PeerType::Sibling).await
    }

    /// Check health of all peers and update status
    pub async fn health_check(&self) {
        let peers = self.all_peers().await;
        debug!("Running health check on {} peers", peers.len());

        for peer in peers {
            // Passive health check based on error rate
            let error_rate = peer.stats.error_rate();
            
            if error_rate > 0.5 {
                peer.set_healthy(false);
            } else if error_rate < 0.1 && !peer.is_healthy() {
                // Recover if error rate drops
                peer.set_healthy(true);
            }
        }
    }

    /// Get statistics summary
    pub async fn stats_summary(&self) -> String {
        let peers = self.all_peers().await;
        let mut summary = String::new();
        summary.push_str(&format!("Total peers: {}\n", peers.len()));

        for peer in peers {
            let requests = peer.stats.requests.load(Ordering::Relaxed);
            let hits = peer.stats.hits.load(Ordering::Relaxed);
            let misses = peer.stats.misses.load(Ordering::Relaxed);
            let errors = peer.stats.errors.load(Ordering::Relaxed);
            let hit_rate = peer.stats.hit_rate() * 100.0;
            let error_rate = peer.stats.error_rate() * 100.0;

            summary.push_str(&format!(
                "  {} [{}] healthy={} rtt={}ms score={:.2}\n    requests={} hits={} misses={} errors={} hit_rate={:.1}% error_rate={:.1}%\n",
                peer.id,
                peer.config.peer_type,
                peer.is_healthy(),
                peer.rtt().as_millis(),
                peer.score(),
                requests,
                hits,
                misses,
                errors,
                hit_rate,
                error_rate
            ));
        }

        summary
    }
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_peer_creation() {
        let config = PeerConfig {
            host: "parent.example.com".to_string(),
            port: 1488,
            peer_type: PeerType::Parent,
            weight: 1.0,
            icp_port: Some(3130),
            max_connections: 100,
        };

        let peer = CachePeer::new(config);
        assert_eq!(peer.config.host, "parent.example.com");
        assert_eq!(peer.config.port, 1488);
        assert!(peer.is_healthy());
    }

    #[tokio::test]
    async fn test_peer_stats() {
        let config = PeerConfig {
            host: "test.example.com".to_string(),
            port: 1488,
            peer_type: PeerType::Parent,
            weight: 1.0,
            icp_port: None,
            max_connections: 100,
        };

        let peer = CachePeer::new(config);
        
        peer.stats.record_request().await;
        peer.stats.record_hit(1024).await;
        peer.stats.record_request().await;
        peer.stats.record_miss().await;

        assert_eq!(peer.stats.requests.load(Ordering::Relaxed), 2);
        assert_eq!(peer.stats.hits.load(Ordering::Relaxed), 1);
        assert_eq!(peer.stats.misses.load(Ordering::Relaxed), 1);
        assert_eq!(peer.stats.hit_rate(), 0.5);
    }

    #[tokio::test]
    async fn test_registry() {
        let registry = PeerRegistry::new();

        let config1 = PeerConfig {
            host: "parent1.example.com".to_string(),
            port: 1488,
            peer_type: PeerType::Parent,
            weight: 1.0,
            icp_port: None,
            max_connections: 100,
        };

        let config2 = PeerConfig {
            host: "sibling1.example.com".to_string(),
            port: 1488,
            peer_type: PeerType::Sibling,
            weight: 0.5,
            icp_port: Some(3130),
            max_connections: 50,
        };

        registry.add_peer(config1).await;
        registry.add_peer(config2).await;

        let all_peers = registry.all_peers().await;
        assert_eq!(all_peers.len(), 2);

        let parents = registry.parent_caches().await;
        assert_eq!(parents.len(), 1);

        let siblings = registry.sibling_caches().await;
        assert_eq!(siblings.len(), 1);
    }

    #[test]
    fn test_peer_config_parse() {
        let result = PeerConfig::parse_from_string(
            "parent.example.com:1488:1.5",
            PeerType::Parent
        );
        assert!(result.is_ok());
        
        let config = result.unwrap();
        assert_eq!(config.host, "parent.example.com");
        assert_eq!(config.port, 1488);
        assert_eq!(config.weight, 1.5);
    }
}
