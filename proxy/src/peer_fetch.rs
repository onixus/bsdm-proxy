//! Forward HTTP requests to a parent/sibling cache peer (forward proxy).

use crate::http_types::Body as ProxyBody;
use crate::peers::CachePeer;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::debug;

#[derive(Debug)]
pub enum PeerFetchError {
    Connect(std::io::Error),
    Handshake(hyper::Error),
    Request(hyper::Error),
    Timeout,
}

impl std::fmt::Display for PeerFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "connect failed: {e}"),
            Self::Handshake(e) => write!(f, "TLS/HTTP handshake failed: {e}"),
            Self::Request(e) => write!(f, "request failed: {e}"),
            Self::Timeout => write!(f, "peer request timed out"),
        }
    }
}

impl std::error::Error for PeerFetchError {}

/// Send an HTTP forward-proxy request through a cache peer.
pub async fn fetch_via_peer(
    peer: &CachePeer,
    req: Request<ProxyBody>,
    timeout: Duration,
) -> Result<Response<Incoming>, PeerFetchError> {
    let (parts, body) = req.into_parts();
    let body_bytes = BodyExt::collect(body)
        .await
        .map_err(PeerFetchError::Request)?
        .to_bytes();
    let req = Request::from_parts(parts, Full::new(body_bytes));

    let addr = format!("{}:{}", peer.config.host, peer.config.port);
    debug!("Fetching via peer {} ({})", peer.id, addr);

    let stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| PeerFetchError::Timeout)?
        .map_err(PeerFetchError::Connect)?;

    let io = TokioIo::new(stream);
    let (mut sender, conn) =
        tokio::time::timeout(timeout, hyper::client::conn::http1::handshake(io))
            .await
            .map_err(|_| PeerFetchError::Timeout)?
            .map_err(PeerFetchError::Handshake)?;

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("Peer connection closed: {}", e);
        }
    });

    tokio::time::timeout(timeout, sender.send_request(req))
        .await
        .map_err(|_| PeerFetchError::Timeout)?
        .map_err(PeerFetchError::Request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peers::{CachePeer, PeerConfig, PeerType};
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use hyper::service::service_fn;
    use hyper::{Method, StatusCode};
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use tokio::net::TcpListener;

    async fn spawn_echo_proxy() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(|req: Request<Incoming>| async move {
                        let path = req.uri().path();
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
                            "peer:{path}"
                        )))))
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        });

        (port, handle)
    }

    #[tokio::test]
    async fn fetch_via_peer_returns_peer_response() {
        let (port, _task) = spawn_echo_proxy().await;
        let peer = CachePeer::new(PeerConfig {
            host: "127.0.0.1".to_string(),
            port,
            peer_type: PeerType::Parent,
            weight: 1.0,
            icp_port: None,
            max_connections: 10,
        });

        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/via-peer")
            .body(crate::http_types::empty())
            .unwrap();

        let response = fetch_via_peer(&peer, req, Duration::from_secs(5))
            .await
            .expect("peer fetch");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"peer:/via-peer");
    }
}
