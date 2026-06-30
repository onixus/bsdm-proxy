//! Multicast peer discovery for hierarchical caching siblings.

use crate::cache_digest::DigestRegistry;
use crate::peers::{PeerConfig, PeerRegistry, PeerType};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

#[derive(Clone, Debug)]
pub struct PeerDiscoveryConfig {
    pub enabled: bool,
    pub multicast_addr: String,
    pub announce_interval: Duration,
    pub node_id: String,
    pub advertise_host: String,
    pub http_port: u16,
    pub icp_port: u16,
    pub weight: f64,
    pub include_digest_every: u64,
}

impl PeerDiscoveryConfig {
    pub fn from_env(http_port: u16, icp_port: u16) -> Self {
        let enabled = std::env::var("PEER_DISCOVERY_ENABLED")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        let multicast_addr = std::env::var("PEER_DISCOVERY_MULTICAST")
            .unwrap_or_else(|_| "239.255.255.1:3131".to_string());
        let announce_secs = std::env::var("PEER_DISCOVERY_INTERVAL_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        let advertise_host = std::env::var("PEER_DISCOVERY_HOST")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "127.0.0.1".to_string());
        let node_id = std::env::var("PEER_DISCOVERY_NODE_ID")
            .unwrap_or_else(|_| format!("{advertise_host}:{http_port}"));
        let weight = std::env::var("PEER_DISCOVERY_WEIGHT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1.0);
        let include_digest_every = std::env::var("PEER_DISCOVERY_DIGEST_EVERY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);

        Self {
            enabled,
            multicast_addr,
            announce_interval: Duration::from_secs(announce_secs),
            node_id,
            advertise_host,
            http_port,
            icp_port,
            weight,
            include_digest_every,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PeerAnnouncement {
    node_id: String,
    host: String,
    http_port: u16,
    icp_port: u16,
    weight: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    digest_b64: Option<String>,
}

pub async fn run_peer_discovery(
    config: PeerDiscoveryConfig,
    registry: PeerRegistry,
    digest_registry: Arc<DigestRegistry>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !config.enabled {
        return Ok(());
    }

    let multicast: SocketAddr = config.multicast_addr.parse()?;
    let bind_addr = match multicast {
        SocketAddr::V4(addr) => format!("0.0.0.0:{}", addr.port()),
        SocketAddr::V6(addr) => format!("[::]:{}", addr.port()),
    };

    let announce_socket = UdpSocket::bind("0.0.0.0:0").await?;
    announce_socket.set_broadcast(true)?;

    let listen_socket = UdpSocket::bind(&bind_addr).await?;
    if let SocketAddr::V4(addr) = multicast {
        listen_socket
            .join_multicast_v4(*addr.ip(), Ipv4Addr::UNSPECIFIED)
            .map_err(|e| format!("multicast join failed: {e}"))?;
    }

    info!(
        "Peer discovery enabled (multicast={}, node_id={})",
        config.multicast_addr, config.node_id
    );

    let announce_counter = Arc::new(AtomicU64::new(0));
    let announce_cfg = config.clone();
    let announce_digest = digest_registry.clone();
    let announce_multicast = multicast;
    let mut announce_shutdown = shutdown_rx.clone();
    let announce_task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(announce_cfg.announce_interval);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let tick = announce_counter.fetch_add(1, Ordering::Relaxed);
                    let digest_b64 = if announce_cfg.include_digest_every > 0
                        && tick.is_multiple_of(announce_cfg.include_digest_every)
                    {
                        Some(announce_digest.local_snapshot_base64().await)
                    } else {
                        None
                    };
                    let payload = PeerAnnouncement {
                        node_id: announce_cfg.node_id.clone(),
                        host: announce_cfg.advertise_host.clone(),
                        http_port: announce_cfg.http_port,
                        icp_port: announce_cfg.icp_port,
                        weight: announce_cfg.weight,
                        digest_b64,
                    };
                    if let Ok(json) = serde_json::to_string(&payload) {
                        let _ = announce_socket.send_to(json.as_bytes(), announce_multicast).await;
                    }
                }
                changed = announce_shutdown.changed() => {
                    if changed.is_ok() && *announce_shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    });

    let listen_cfg = config.clone();
    let listen_registry = registry.clone();
    let listen_digest = digest_registry.clone();
    let listen_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let (len, _) = match listen_socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    warn!("Peer discovery recv error: {}", e);
                    continue;
                }
            };
            let Ok(text) = std::str::from_utf8(&buf[..len]) else {
                continue;
            };
            let Ok(announcement) = serde_json::from_str::<PeerAnnouncement>(text) else {
                continue;
            };
            if announcement.node_id == listen_cfg.node_id {
                continue;
            }
            debug!(
                "Discovered peer {} at {}:{}",
                announcement.node_id, announcement.host, announcement.http_port
            );
            let peer_config = PeerConfig {
                host: announcement.host,
                port: announcement.http_port,
                peer_type: PeerType::Sibling,
                weight: announcement.weight,
                icp_port: Some(announcement.icp_port),
                max_connections: 100,
            };
            let peer = listen_registry.upsert_sibling(peer_config).await;
            if let Some(digest_b64) = announcement.digest_b64 {
                listen_digest.update_remote(&peer.id, &digest_b64).await;
            }
        }
    });

    let _ = shutdown_rx.changed().await;
    announce_task.abort();
    listen_task.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announcement_json_roundtrip() {
        let announcement = PeerAnnouncement {
            node_id: "node-1".to_string(),
            host: "10.0.0.5".to_string(),
            http_port: 1488,
            icp_port: 3130,
            weight: 1.0,
            digest_b64: None,
        };
        let json = serde_json::to_string(&announcement).unwrap();
        let decoded: PeerAnnouncement = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.node_id, "node-1");
        assert_eq!(decoded.http_port, 1488);
    }
}
