//! HTCP (Hypertext Caching Protocol) — simplified UDP implementation for peer queries.
//!
//! Wire format (BSDM subset, inspired by RFC 2756 TST):
//! `HTCP` magic + version + opcode + request_number + url

use bytes::{Buf, BufMut, BytesMut};
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, error};

const HTCP_MAGIC: &[u8; 4] = b"HTCP";
const HTCP_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HtcpOpcode {
    Query = 1,
    Hit = 2,
    Miss = 3,
    Error = 4,
}

impl From<u8> for HtcpOpcode {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Query,
            2 => Self::Hit,
            3 => Self::Miss,
            _ => Self::Error,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HtcpMessage {
    pub opcode: HtcpOpcode,
    pub version: u8,
    pub request_number: u32,
    pub url: String,
}

impl HtcpMessage {
    pub fn query(request_number: u32, url: String) -> Self {
        Self {
            opcode: HtcpOpcode::Query,
            version: HTCP_VERSION,
            request_number,
            url,
        }
    }

    pub fn hit(request_number: u32) -> Self {
        Self {
            opcode: HtcpOpcode::Hit,
            version: HTCP_VERSION,
            request_number,
            url: String::new(),
        }
    }

    pub fn miss(request_number: u32) -> Self {
        Self {
            opcode: HtcpOpcode::Miss,
            version: HTCP_VERSION,
            request_number,
            url: String::new(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::with_capacity(16 + self.url.len());
        buf.put_slice(HTCP_MAGIC);
        buf.put_u8(self.version);
        buf.put_u8(self.opcode as u8);
        buf.put_u32(self.request_number);
        buf.put_u16(self.url.len() as u16);
        if !self.url.is_empty() {
            buf.put_slice(self.url.as_bytes());
        }
        Ok(buf.to_vec())
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 12 {
            return Err(Error::new(ErrorKind::InvalidData, "HTCP message too short"));
        }
        if &data[..4] != HTCP_MAGIC {
            return Err(Error::new(ErrorKind::InvalidData, "invalid HTCP magic"));
        }
        let mut cursor = &data[4..];
        let version = cursor.get_u8();
        let opcode = HtcpOpcode::from(cursor.get_u8());
        let request_number = cursor.get_u32();
        let url_len = cursor.get_u16() as usize;
        let url = if url_len > 0 && cursor.len() >= url_len {
            String::from_utf8_lossy(&cursor[..url_len]).to_string()
        } else {
            String::new()
        };
        Ok(Self {
            opcode,
            version,
            request_number,
            url,
        })
    }
}

#[derive(Debug, Clone)]
pub struct HtcpResult {
    pub peer: SocketAddr,
    pub response: HtcpOpcode,
    pub latency: Duration,
}

pub struct HtcpClient {
    socket: Arc<UdpSocket>,
    request_counter: AtomicU32,
}

impl HtcpClient {
    pub async fn new(bind_addr: &str) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        Ok(Self {
            socket: Arc::new(socket),
            request_counter: AtomicU32::new(1),
        })
    }

    pub async fn query_peer(
        &self,
        peer: SocketAddr,
        url: &str,
        query_timeout: Duration,
    ) -> Result<HtcpResult> {
        let request_number = self.request_counter.fetch_add(1, Ordering::Relaxed);
        let query = HtcpMessage::query(request_number, url.to_string());
        let encoded = query.encode()?;
        let start = std::time::Instant::now();
        self.socket.send_to(&encoded, peer).await?;

        let mut buf = vec![0u8; 1024];
        let response = timeout(query_timeout, async {
            loop {
                let (len, addr) = self.socket.recv_from(&mut buf).await?;
                if addr == peer {
                    let message = HtcpMessage::decode(&buf[..len])?;
                    if message.request_number == request_number {
                        return Ok(message);
                    }
                }
            }
        })
        .await;

        match response {
            Ok(Ok(message)) => Ok(HtcpResult {
                peer,
                response: message.opcode,
                latency: start.elapsed(),
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::new(ErrorKind::TimedOut, "HTCP query timeout")),
        }
    }

    pub async fn query_peers(
        &self,
        peers: &[SocketAddr],
        url: &str,
        query_timeout: Duration,
    ) -> Vec<HtcpResult> {
        let mut tasks = Vec::new();
        for &peer in peers {
            let client = self.clone();
            let url = url.to_string();
            tasks.push(tokio::spawn(async move {
                client.query_peer(peer, &url, query_timeout).await.ok()
            }));
        }
        let mut results = Vec::new();
        for task in tasks {
            if let Ok(Some(result)) = task.await {
                results.push(result);
            }
        }
        results
    }
}

impl Clone for HtcpClient {
    fn clone(&self) -> Self {
        Self {
            socket: self.socket.clone(),
            request_counter: AtomicU32::new(self.request_counter.load(Ordering::Relaxed)),
        }
    }
}

pub struct HtcpServer {
    socket: Arc<UdpSocket>,
    query_handler: Arc<dyn Fn(&str) -> bool + Send + Sync>,
}

impl HtcpServer {
    pub async fn new<F>(bind_addr: &str, query_handler: F) -> Result<Self>
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        let socket = UdpSocket::bind(bind_addr).await?;
        Ok(Self {
            socket: Arc::new(socket),
            query_handler: Arc::new(query_handler),
        })
    }

    pub async fn serve(self: Arc<Self>) {
        let mut buf = vec![0u8; 1024];
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    let data = buf[..len].to_vec();
                    let server = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_query(&data, addr).await {
                            error!("HTCP query handling error: {}", e);
                        }
                    });
                }
                Err(e) => error!("HTCP socket error: {}", e),
            }
        }
    }

    async fn handle_query(&self, data: &[u8], sender: SocketAddr) -> Result<()> {
        let query = HtcpMessage::decode(data)?;
        if query.opcode != HtcpOpcode::Query {
            return Ok(());
        }
        debug!("HTCP query from {}: {}", sender, query.url);
        let response = if (self.query_handler)(&query.url) {
            HtcpMessage::hit(query.request_number)
        } else {
            HtcpMessage::miss(query.request_number)
        };
        self.socket
            .send_to(&response.encode()?, sender)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn htcp_message_roundtrip() {
        let msg = HtcpMessage::query(42, "http://example.com/x".to_string());
        let encoded = msg.encode().unwrap();
        let decoded = HtcpMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.opcode, HtcpOpcode::Query);
        assert_eq!(decoded.request_number, 42);
        assert_eq!(decoded.url, "http://example.com/x");
    }

    #[tokio::test]
    async fn htcp_client_server() {
        let server = Arc::new(HtcpServer::new("127.0.0.1:0", |_| true).await.unwrap());
        let server_addr = server.socket.local_addr().unwrap();
        let server_clone = server.clone();
        tokio::spawn(async move {
            server_clone.serve().await;
        });
        tokio::time::sleep(Duration::from_millis(10)).await;

        let client = HtcpClient::new("127.0.0.1:0").await.unwrap();
        let result = client
            .query_peer(server_addr, "http://example.com", Duration::from_millis(200))
            .await
            .unwrap();
        assert_eq!(result.response, HtcpOpcode::Hit);
    }
}
