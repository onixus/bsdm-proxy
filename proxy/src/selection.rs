//! Cache peer selection strategies
//!
//! Different algorithms for choosing which parent cache to use
//! when multiple options are available.

use crate::peers::{CachePeer, PeerType};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Trait for peer selection strategies
pub trait SelectionStrategy: Send + Sync {
    /// Select a peer from the available list
    fn select<'a>(&self, peers: &'a [Arc<CachePeer>], url: &str) -> Option<&'a Arc<CachePeer>>;
    
    /// Strategy name for logging/metrics
    fn name(&self) -> &'static str;
}

/// Round-robin selection - simple rotation through peers
pub struct RoundRobinStrategy {
    counter: AtomicUsize,
}

impl RoundRobinStrategy {
    pub fn new() -> Self {
        Self {
            counter: AtomicUsize::new(0),
        }
    }
}

impl Default for RoundRobinStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl SelectionStrategy for RoundRobinStrategy {
    fn select<'a>(&self, peers: &'a [Arc<CachePeer>], _url: &str) -> Option<&'a Arc<CachePeer>> {
        if peers.is_empty() {
            return None;
        }

        let index = self.counter.fetch_add(1, Ordering::Relaxed) % peers.len();
        Some(&peers[index])
    }

    fn name(&self) -> &'static str {
        "round-robin"
    }
}

/// Weighted selection - choose based on peer weights and health
pub struct WeightedStrategy;

impl WeightedStrategy {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WeightedStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl SelectionStrategy for WeightedStrategy {
    fn select<'a>(&self, peers: &'a [Arc<CachePeer>], _url: &str) -> Option<&'a Arc<CachePeer>> {
        if peers.is_empty() {
            return None;
        }

        // Calculate total score
        let total_score: f64 = peers.iter().map(|p| p.score()).sum();
        
        if total_score == 0.0 {
            return None; // All peers unhealthy
        }

        // Weighted random selection
        let mut rng = rand::random::<f64>() * total_score;
        
        for peer in peers {
            let score = peer.score();
            if rng <= score {
                return Some(peer);
            }
            rng -= score;
        }

        // Fallback to last peer
        peers.last()
    }

    fn name(&self) -> &'static str {
        "weighted"
    }
}

/// Closest selection - choose peer with lowest RTT
pub struct ClosestStrategy;

impl ClosestStrategy {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ClosestStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl SelectionStrategy for ClosestStrategy {
    fn select<'a>(&self, peers: &'a [Arc<CachePeer>], _url: &str) -> Option<&'a Arc<CachePeer>> {
        peers
            .iter()
            .filter(|p| p.is_healthy())
            .min_by_key(|p| p.rtt().as_millis())
    }

    fn name(&self) -> &'static str {
        "closest"
    }
}

/// Hash-based selection - consistent hashing by URL
pub struct HashStrategy;

impl HashStrategy {
    pub fn new() -> Self {
        Self
    }

    fn hash_url(&self, url: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        url.hash(&mut hasher);
        hasher.finish()
    }
}

impl Default for HashStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl SelectionStrategy for HashStrategy {
    fn select<'a>(&self, peers: &'a [Arc<CachePeer>], url: &str) -> Option<&'a Arc<CachePeer>> {
        if peers.is_empty() {
            return None;
        }

        let hash = self.hash_url(url);
        let index = (hash as usize) % peers.len();
        Some(&peers[index])
    }

    fn name(&self) -> &'static str {
        "hash"
    }
}

/// Parse strategy from string
pub fn parse_strategy(name: &str) -> Box<dyn SelectionStrategy> {
    match name.to_lowercase().as_str() {
        "round-robin" | "roundrobin" | "rr" => Box::new(RoundRobinStrategy::new()),
        "weighted" | "weight" | "w" => Box::new(WeightedStrategy::new()),
        "closest" | "rtt" | "latency" => Box::new(ClosestStrategy::new()),
        "hash" | "consistent" | "ch" => Box::new(HashStrategy::new()),
        _ => {
            tracing::warn!("Unknown strategy '{}', defaulting to weighted", name);
            Box::new(WeightedStrategy::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peers::PeerConfig;
    use std::time::Duration;

    fn create_test_peer(host: &str, weight: f64, rtt_ms: u64) -> Arc<CachePeer> {
        let config = PeerConfig {
            host: host.to_string(),
            port: 1488,
            peer_type: PeerType::Parent,
            weight,
            icp_port: None,
            max_connections: 100,
        };
        let peer = Arc::new(CachePeer::new(config));
        peer.update_rtt(Duration::from_millis(rtt_ms));
        peer
    }

    #[test]
    fn test_round_robin() {
        let strategy = RoundRobinStrategy::new();
        let peers = vec![
            create_test_peer("peer1", 1.0, 10),
            create_test_peer("peer2", 1.0, 20),
            create_test_peer("peer3", 1.0, 30),
        ];

        // Should rotate through peers
        let selected1 = strategy.select(&peers, "http://example.com/1");
        let selected2 = strategy.select(&peers, "http://example.com/2");
        let selected3 = strategy.select(&peers, "http://example.com/3");
        let selected4 = strategy.select(&peers, "http://example.com/4");

        assert_eq!(selected1.unwrap().config.host, "peer1");
        assert_eq!(selected2.unwrap().config.host, "peer2");
        assert_eq!(selected3.unwrap().config.host, "peer3");
        assert_eq!(selected4.unwrap().config.host, "peer1"); // Wraps around
    }

    #[test]
    fn test_closest() {
        let strategy = ClosestStrategy::new();
        let peers = vec![
            create_test_peer("peer1", 1.0, 100),
            create_test_peer("peer2", 1.0, 10), // Closest
            create_test_peer("peer3", 1.0, 50),
        ];

        let selected = strategy.select(&peers, "http://example.com/test");
        assert_eq!(selected.unwrap().config.host, "peer2");
    }

    #[test]
    fn test_hash_consistency() {
        let strategy = HashStrategy::new();
        let peers = vec![
            create_test_peer("peer1", 1.0, 10),
            create_test_peer("peer2", 1.0, 20),
            create_test_peer("peer3", 1.0, 30),
        ];

        let url = "http://example.com/test";
        let selected1 = strategy.select(&peers, url);
        let selected2 = strategy.select(&peers, url);
        let selected3 = strategy.select(&peers, url);

        // Same URL should always select same peer
        assert_eq!(selected1.unwrap().id, selected2.unwrap().id);
        assert_eq!(selected2.unwrap().id, selected3.unwrap().id);
    }

    #[test]
    fn test_weighted() {
        let strategy = WeightedStrategy::new();
        let peers = vec![
            create_test_peer("peer1", 1.0, 10),
            create_test_peer("peer2", 2.0, 20), // Higher weight
            create_test_peer("peer3", 0.5, 30),
        ];

        // Run multiple selections and verify peer2 is selected more often
        let mut counts = std::collections::HashMap::new();
        for i in 0..100 {
            let url = format!("http://example.com/{}", i);
            if let Some(peer) = strategy.select(&peers, &url) {
                *counts.entry(peer.config.host.clone()).or_insert(0) += 1;
            }
        }

        // peer2 should be selected more than peer3 (higher weight)
        assert!(counts.get("peer2").unwrap_or(&0) > counts.get("peer3").unwrap_or(&0));
    }

    #[test]
    fn test_parse_strategy() {
        assert_eq!(parse_strategy("round-robin").name(), "round-robin");
        assert_eq!(parse_strategy("weighted").name(), "weighted");
        assert_eq!(parse_strategy("closest").name(), "closest");
        assert_eq!(parse_strategy("hash").name(), "hash");
        assert_eq!(parse_strategy("unknown").name(), "weighted"); // Default
    }
}
