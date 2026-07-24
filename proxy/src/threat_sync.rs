//! Real-Time P2P & Redis Pub/Sub Threat Sync Engine.

use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

/// Represent an IoC threat synchronization event passed between proxy nodes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThreatSyncEvent {
    pub id: String,
    pub ioc_type: String, // "domain", "ip", "cidr"
    pub value: String,
    pub threat_score: f64,
    pub action: String, // "block", "flag", "challenge"
    pub ttl_secs: u64,
    pub origin_node: String,
    pub timestamp: u64,
}

/// Threat Sync Engine managing P2P and Redis Pub/Sub broadcasting of threat indicators.
#[derive(Clone)]
pub struct ThreatSyncEngine {
    node_id: String,
    redis_conn: Option<ConnectionManager>,
    recent_events: Arc<RwLock<Vec<ThreatSyncEvent>>>,
    known_peers: Arc<RwLock<Vec<String>>>,
    pubsub_channel: String,
}

impl ThreatSyncEngine {
    /// Create a new `ThreatSyncEngine`.
    pub fn new(node_id: String, redis_conn: Option<ConnectionManager>) -> Self {
        let pubsub_channel =
            std::env::var("THREAT_SYNC_CHANNEL").unwrap_or_else(|_| "bsdm:threat:sync".to_string());

        Self {
            node_id,
            redis_conn,
            recent_events: Arc::new(RwLock::new(Vec::new())),
            known_peers: Arc::new(RwLock::new(Vec::new())),
            pubsub_channel,
        }
    }

    /// Return current node ID.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Check if Redis PubSub sync is available.
    pub fn is_sync_enabled(&self) -> bool {
        self.redis_conn.is_some()
    }

    /// Get recent synchronized threat events (up to last 50).
    pub fn get_recent_events(&self) -> Vec<ThreatSyncEvent> {
        self.recent_events.read().unwrap().clone()
    }

    /// Get list of active threat sync peers.
    pub fn get_peers(&self) -> Vec<String> {
        let peers = self.known_peers.read().unwrap().clone();
        if peers.is_empty() {
            vec![format!("local-node ({})", self.node_id)]
        } else {
            peers
        }
    }

    /// Record a received event locally.
    pub fn record_event(&self, event: ThreatSyncEvent) {
        let mut peers = self.known_peers.write().unwrap();
        if !peers.contains(&event.origin_node) && event.origin_node != self.node_id {
            peers.push(event.origin_node.clone());
        }

        let mut events = self.recent_events.write().unwrap();
        if !events.iter().any(|e| e.id == event.id) {
            events.insert(0, event);
            if events.len() > 50 {
                events.pop();
            }
        }
    }

    /// Broadcast an IoC threat event across the cluster.
    pub async fn broadcast(&self, mut event: ThreatSyncEvent) -> Result<(), String> {
        if event.id.is_empty() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            event.id = format!("ioc-{}-{}", self.node_id, now);
        }

        if event.origin_node.is_empty() {
            event.origin_node = self.node_id.clone();
        }

        if event.timestamp == 0 {
            event.timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }

        // Record locally
        self.record_event(event.clone());

        // Publish to Redis if connected
        if let Some(ref conn) = self.redis_conn {
            let mut conn = conn.clone();
            let payload = serde_json::to_string(&event)
                .map_err(|e| format!("Failed to serialize ThreatSyncEvent: {}", e))?;

            conn.publish::<_, _, ()>(&self.pubsub_channel, payload)
                .await
                .map_err(|e| format!("Redis PUBLISH failed: {}", e))?;

            info!(
                "Broadcasted threat event {} for {} ({}) via Redis",
                event.id, event.value, event.ioc_type
            );
        } else {
            info!(
                "Recorded threat event {} locally (standalone mode)",
                event.id
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_threat_sync_engine_local() {
        let engine = ThreatSyncEngine::new("node-1".to_string(), None);
        assert_eq!(engine.node_id(), "node-1");
        assert!(!engine.is_sync_enabled());

        let event = ThreatSyncEvent {
            id: "".to_string(),
            ioc_type: "domain".to_string(),
            value: "malicious-phishing.com".to_string(),
            threat_score: 0.95,
            action: "block".to_string(),
            ttl_secs: 3600,
            origin_node: "".to_string(),
            timestamp: 0,
        };

        let result = engine.broadcast(event).await;
        assert!(result.is_ok());

        let events = engine.get_recent_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].value, "malicious-phishing.com");
        assert_eq!(events[0].origin_node, "node-1");
    }
}
