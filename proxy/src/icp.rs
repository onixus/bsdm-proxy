//! ICP (Internet Cache Protocol) Implementation
//!
//! RFC 2186: https://datatracker.ietf.org/doc/html/rfc2186
//!
//! Lightweight UDP-based protocol for querying cache peers
//! about the presence of cached objects.

use bytes::{Buf, BufMut, BytesMut};
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, error, warn};

/// ICP protocol version
const ICP_VERSION: u8 = 2;

/// ICP message opcodes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcpOpcode {
    Invalid = 0,
    Query = 1,
    Hit = 2,
    Miss = 3,
    Error = 4,
    // Extended opcodes
    Denied = 22,
}

impl From<u8> for IcpOpcode {
    fn from(value: u8) -> Self {
        match value {
            1 => IcpOpcode::Query,
            2 => IcpOpcode::Hit,
            3 => IcpOpcode::Miss,
            4 => IcpOpcode::Error,
            22 => IcpOpcode::Denied,
            _ => IcpOpcode::Invalid,
        }
    }
}

impl std::fmt::Display for IcpOpcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IcpOpcode::Query => write!(f, "QUERY"),
            IcpOpcode::Hit => write!(f, "HIT"),
            IcpOpcode::Miss => write!(f, "MISS"),
            IcpOpcode::Error => write!(f, "ERROR"),
            IcpOpcode::Denied => write!(f, "DENIED"),
            IcpOpcode::Invalid => write!(f, "INVALID"),
        }
    }
}

/// ICP message structure
#[derive(Debug, Clone)]
pub struct IcpMessage {
    pub opcode: IcpOpcode,
    pub version: u8,
    pub request_number: u32,
    pub url: String,
    pub requester: SocketAddr,
}

impl IcpMessage {
    /// Create a new ICP query
    pub fn query(request_number: u32, url: String, requester: SocketAddr) -> Self {
        Self {
            opcode: IcpOpcode::Query,
            version: ICP_VERSION,
            request_number,
            url,
            requester,
        }
    }

    /// Create an ICP hit response
    pub fn hit(request_number: u32, requester: SocketAddr) -> Self {
        Self {
            opcode: IcpOpcode::Hit,
            version: ICP_VERSION,
            request_number,
            url: String::new(),
            requester,
        }
    }

    /// Create an ICP miss response
    pub fn miss(request_number: u32, requester: SocketAddr) -> Self {
        Self {
            opcode: IcpOpcode::Miss,
            version: ICP_VERSION,
            request_number,
            url: String::new(),
            requester,
        }
    }

    /// Encode message to bytes
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::with_capacity(1024);

        // Header (20 bytes)
        buf.put_u8(self.opcode as u8);
        buf.put_u8(self.version);
        buf.put_u16(self.url.len() as u16);
        buf.put_u32(self.request_number);
        buf.put_u32(0); // Options (unused)
        buf.put_u32(0); // Option data (unused)
        buf.put_u32(0); // Sender host (unused)

        // URL
        if !self.url.is_empty() {
            buf.put(self.url.as_bytes());
            buf.put_u8(0); // Null terminator
        }

        Ok(buf.to_vec())
    }

    /// Decode message from bytes
    pub fn decode(mut data: &[u8], sender: SocketAddr) -> Result<Self> {
        if data.len() < 20 {
            return Err(Error::new(ErrorKind::InvalidData, "ICP message too short"));
        }

        let opcode = IcpOpcode::from(data.get_u8());
        let version = data.get_u8();
        let url_len = data.get_u16() as usize;
        let request_number = data.get_u32();
        let _ = data.get_u32(); // options
        let _ = data.get_u32(); // option_data
        let _ = data.get_u32(); // sender_host

        if version != ICP_VERSION {
            warn!("Unsupported ICP version: {}", version);
        }

        let url = if url_len > 0 && data.len() >= url_len {
            let url_bytes = &data[..url_len];
            String::from_utf8_lossy(url_bytes)
                .trim_end_matches('\0')
                .to_string()
        } else {
            String::new()
        };

        Ok(Self {
            opcode,
            version,
            request_number,
            url,
            requester: sender,
        })
    }
}

/// ICP query result
#[derive(Debug, Clone)]
pub struct IcpResult {
    pub peer: SocketAddr,
    pub response: IcpOpcode,
    pub latency: Duration,
}

/// ICP client for querying cache peers
pub struct IcpClient {
    socket: Arc<UdpSocket>,
    request_counter: AtomicU32,
    local_addr: SocketAddr,
}

impl IcpClient {
    /// Create a new ICP client
    pub async fn new(bind_addr: &str) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;
        
        Ok(Self {
            socket: Arc::new(socket),
            request_counter: AtomicU32::new(1),
            local_addr,
        })
    }

    /// Query a single peer
    pub async fn query_peer(
        &self,
        peer: SocketAddr,
        url: &str,
        query_timeout: Duration,
    ) -> Result<IcpResult> {
        let request_number = self.request_counter.fetch_add(1, Ordering::Relaxed);
        let query = IcpMessage::query(request_number, url.to_string(), self.local_addr);
        let encoded = query.encode()?;

        let start = std::time::Instant::now();

        // Send query
        self.socket.send_to(&encoded, peer).await?;
        debug!("ICP query sent to {} for URL: {}", peer, url);

        // Wait for response
        let mut buf = vec![0u8; 1024];
        let result = timeout(query_timeout, async {
            loop {
                let (len, addr) = self.socket.recv_from(&mut buf).await?;
                if addr == peer {
                    let response = IcpMessage::decode(&buf[..len], addr)?;
                    if response.request_number == request_number {
                        return Ok(response);
                    }
                }
            }
        }).await;

        match result {
            Ok(Ok(response)) => {
                let latency = start.elapsed();
                debug!("ICP response from {}: {} ({}ms)", peer, response.opcode, latency.as_millis());
                Ok(IcpResult {
                    peer,
                    response: response.opcode,
                    latency,
                })
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::new(ErrorKind::TimedOut, "ICP query timeout")),
        }
    }

    /// Query multiple peers in parallel
    pub async fn query_peers(
        &self,
        peers: &[SocketAddr],
        url: &str,
        query_timeout: Duration,
    ) -> Vec<IcpResult> {
        let mut tasks = Vec::new();

        for &peer in peers {
            let client = self.clone();
            let url = url.to_string();
            let task = tokio::spawn(async move {
                client.query_peer(peer, &url, query_timeout).await.ok()
            });
            tasks.push(task);
        }

        let mut results = Vec::new();
        for task in tasks {
            if let Ok(Some(result)) = task.await {
                results.push(result);
            }
        }

        results
    }

    /// Find first peer with a HIT
    pub async fn find_hit(
        &self,
        peers: &[SocketAddr],
        url: &str,
        query_timeout: Duration,
    ) -> Option<SocketAddr> {
        let results = self.query_peers(peers, url, query_timeout).await;
        
        results
            .into_iter()
            .find(|r| r.response == IcpOpcode::Hit)
            .map(|r| r.peer)
    }
}

impl Clone for IcpClient {
    fn clone(&self) -> Self {
        Self {
            socket: self.socket.clone(),
            request_counter: AtomicU32::new(
                self.request_counter.load(Ordering::Relaxed)
            ),
            local_addr: self.local_addr,
        }
    }
}

/// ICP server for responding to cache queries
pub struct IcpServer {
    socket: Arc<UdpSocket>,
    query_handler: Arc<dyn Fn(&str) -> bool + Send + Sync>,
}

impl IcpServer {
    /// Create a new ICP server
    pub async fn new<F>(
        bind_addr: &str,
        query_handler: F,
    ) -> Result<Self>
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;
        
        debug!("ICP server listening on {}", local_addr);

        Ok(Self {
            socket: Arc::new(socket),
            query_handler: Arc::new(query_handler),
        })
    }

    /// Start serving ICP queries
    pub async fn serve(self: Arc<Self>) {
        let mut buf = vec![0u8; 1024];

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    let data = buf[..len].to_vec();
                    let server = self.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_query(&data, addr).await {
                            error!("ICP query handling error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("ICP socket error: {}", e);
                }
            }
        }
    }

    async fn handle_query(&self, data: &[u8], sender: SocketAddr) -> Result<()> {
        let query = IcpMessage::decode(data, sender)?;

        if query.opcode != IcpOpcode::Query {
            return Ok(()); // Ignore non-query messages
        }

        debug!("ICP query from {}: {}", sender, query.url);

        // Check if we have the object in cache
        let has_object = (self.query_handler)(&query.url);

        let response = if has_object {
            IcpMessage::hit(query.request_number, sender)
        } else {
            IcpMessage::miss(query.request_number, sender)
        };

        let encoded = response.encode()?;
        self.socket.send_to(&encoded, sender).await?;

        debug!("ICP response sent to {}: {}", sender, response.opcode);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_encoding() {
        let msg = IcpMessage::query(
            12345,
            "http://example.com/test".to_string(),
            "127.0.0.1:3130".parse().unwrap(),
        );

        let encoded = msg.encode().unwrap();
        assert!(encoded.len() > 20);
        
        let decoded = IcpMessage::decode(
            &encoded,
            "127.0.0.1:3130".parse().unwrap()
        ).unwrap();
        
        assert_eq!(decoded.opcode, IcpOpcode::Query);
        assert_eq!(decoded.request_number, 12345);
        assert_eq!(decoded.url, "http://example.com/test");
    }

    #[test]
    fn test_hit_miss_encoding() {
        let hit = IcpMessage::hit(999, "127.0.0.1:3130".parse().unwrap());
        let encoded = hit.encode().unwrap();
        let decoded = IcpMessage::decode(
            &encoded,
            "127.0.0.1:3130".parse().unwrap()
        ).unwrap();
        assert_eq!(decoded.opcode, IcpOpcode::Hit);
        assert_eq!(decoded.request_number, 999);
    }

    #[tokio::test]
    async fn test_client_server() {
        // Create server that always returns HIT
        let server = Arc::new(
            IcpServer::new("127.0.0.1:0", |_url| true)
                .await
                .unwrap()
        );
        
        let server_addr = server.socket.local_addr().unwrap();
        
        // Start server
        let server_clone = server.clone();
        tokio::spawn(async move {
            server_clone.serve().await;
        });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Create client
        let client = IcpClient::new("127.0.0.1:0").await.unwrap();

        // Query server
        let result = client
            .query_peer(
                server_addr,
                "http://example.com/test",
                Duration::from_millis(100),
            )
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.response, IcpOpcode::Hit);
        assert_eq!(result.peer, server_addr);
    }
}
