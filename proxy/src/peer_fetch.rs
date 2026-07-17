//! Forward HTTP requests to a parent/sibling cache peer (forward proxy).
//!
//! Plain TCP by default; optional peer mTLS (`HIERARCHY_PEER_MTLS_*`) wraps the
//! connection in TLS with a client certificate before the HTTP/1 handshake.

use crate::http_types::Body as ProxyBody;
use crate::peers::CachePeer;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info};

#[derive(Debug)]
pub enum PeerFetchError {
    Connect(std::io::Error),
    Handshake(hyper::Error),
    Tls(String),
    Request(hyper::Error),
    Timeout,
    Config(String),
}

impl std::fmt::Display for PeerFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "connect failed: {e}"),
            Self::Handshake(e) => write!(f, "HTTP handshake failed: {e}"),
            Self::Tls(e) => write!(f, "TLS failed: {e}"),
            Self::Request(e) => write!(f, "request failed: {e}"),
            Self::Timeout => write!(f, "peer request timed out"),
            Self::Config(e) => write!(f, "peer TLS config: {e}"),
        }
    }
}

impl std::error::Error for PeerFetchError {}

/// Optional mutual TLS for hierarchy peer HTTP fetch.
#[derive(Clone, Debug, Default)]
pub struct PeerTlsConfig {
    pub enabled: bool,
    pub ca_file: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
}

impl PeerTlsConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("HIERARCHY_PEER_MTLS_ENABLED")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        let ca_file = env_path("HIERARCHY_PEER_CA_FILE");
        let cert_file = env_path("HIERARCHY_PEER_CERT_FILE");
        let key_file = env_path("HIERARCHY_PEER_KEY_FILE");
        if enabled {
            info!(
                "Hierarchy peer mTLS enabled (ca={:?}, cert={:?})",
                ca_file, cert_file
            );
        }
        Self {
            enabled,
            ca_file,
            cert_file,
            key_file,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.ca_file.is_none() {
            return Err("HIERARCHY_PEER_CA_FILE required when mTLS enabled".into());
        }
        if self.cert_file.is_none() || self.key_file.is_none() {
            return Err(
                "HIERARCHY_PEER_CERT_FILE and HIERARCHY_PEER_KEY_FILE required when mTLS enabled"
                    .into(),
            );
        }
        Ok(())
    }

    fn build_connector(&self) -> Result<TlsConnector, PeerFetchError> {
        self.validate().map_err(PeerFetchError::Config)?;
        let ca_path = self.ca_file.as_ref().unwrap();
        let cert_path = self.cert_file.as_ref().unwrap();
        let key_path = self.key_file.as_ref().unwrap();

        let ca_pem = std::fs::read(ca_path)
            .map_err(|e| PeerFetchError::Config(format!("read CA {ca_path}: {e}")))?;
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut Cursor::new(ca_pem))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PeerFetchError::Config(format!("parse CA: {e}")))?
            .into_iter()
            .map(|c| c.into_owned())
            .collect();
        if certs.is_empty() {
            return Err(PeerFetchError::Config(format!(
                "no certificates in {ca_path}"
            )));
        }
        let mut roots = rustls::RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err(PeerFetchError::Config(format!(
                "failed to add CA certs from {ca_path}"
            )));
        }

        let cert_pem = std::fs::read(cert_path)
            .map_err(|e| PeerFetchError::Config(format!("read cert {cert_path}: {e}")))?;
        let client_certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut Cursor::new(&cert_pem))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| PeerFetchError::Config(format!("parse client cert: {e}")))?
                .into_iter()
                .map(|c| c.into_owned())
                .collect();
        if client_certs.is_empty() {
            return Err(PeerFetchError::Config(format!(
                "no client certificates in {cert_path}"
            )));
        }

        let key_pem = std::fs::read(key_path)
            .map_err(|e| PeerFetchError::Config(format!("read key {key_path}: {e}")))?;
        let key = rustls_pemfile::private_key(&mut Cursor::new(&key_pem))
            .map_err(|e| PeerFetchError::Config(format!("parse key: {e}")))?
            .ok_or_else(|| PeerFetchError::Config(format!("no private key in {key_path}")))?;

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(client_certs, key)
            .map_err(|e| PeerFetchError::Config(format!("client auth: {e}")))?;
        Ok(TlsConnector::from(Arc::new(config)))
    }
}

fn env_path(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Send an HTTP forward-proxy request through a cache peer.
pub async fn fetch_via_peer(
    peer: &CachePeer,
    req: Request<ProxyBody>,
    timeout: Duration,
    tls: Option<&PeerTlsConfig>,
) -> Result<Response<Incoming>, PeerFetchError> {
    let (parts, body) = req.into_parts();
    let body_bytes = BodyExt::collect(body)
        .await
        .map_err(PeerFetchError::Request)?
        .to_bytes();
    let req = Request::from_parts(parts, Full::new(body_bytes));

    let addr = format!("{}:{}", peer.config.host, peer.config.port);
    debug!(
        "Fetching via peer {} ({}) mtls={}",
        peer.id,
        addr,
        tls.map(|t| t.enabled).unwrap_or(false)
    );

    let stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| PeerFetchError::Timeout)?
        .map_err(PeerFetchError::Connect)?;

    if let Some(cfg) = tls.filter(|t| t.enabled) {
        let connector = cfg.build_connector()?;
        let server_name = match peer.config.host.parse::<std::net::IpAddr>() {
            Ok(ip) => ServerName::IpAddress(ip.into()),
            Err(_) => ServerName::try_from(peer.config.host.clone())
                .map_err(|e| PeerFetchError::Tls(format!("invalid peer hostname: {e}")))?,
        };
        let tls_stream = tokio::time::timeout(timeout, connector.connect(server_name, stream))
            .await
            .map_err(|_| PeerFetchError::Timeout)?
            .map_err(|e| PeerFetchError::Tls(e.to_string()))?;
        http1_exchange(tls_stream, req, timeout).await
    } else {
        http1_exchange(stream, req, timeout).await
    }
}

async fn http1_exchange<S>(
    stream: S,
    req: Request<Full<bytes::Bytes>>,
    timeout: Duration,
) -> Result<Response<Incoming>, PeerFetchError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
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
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };
    use rustls::server::WebPkiClientVerifier;
    use std::convert::Infallible;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

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

    fn write_pem(dir: &TempDir, name: &str, pem: &str) -> String {
        let path = dir.path().join(name);
        std::fs::write(&path, pem).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn gen_peer_mtls_material(dir: &TempDir) -> PeerTlsConfig {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "BSDM Peer Test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let server_key = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "peer-server");
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params
            .distinguished_name
            .push(DnType::CommonName, "peer-client");
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();

        // Persist server material for the TLS acceptor test helper via env-like paths.
        write_pem(dir, "server.crt", &server_cert.pem());
        write_pem(dir, "server.key", &server_key.serialize_pem());

        PeerTlsConfig {
            enabled: true,
            ca_file: Some(write_pem(dir, "ca.crt", &ca_cert.pem())),
            cert_file: Some(write_pem(dir, "client.crt", &client_cert.pem())),
            key_file: Some(write_pem(dir, "client.key", &client_key.serialize_pem())),
        }
    }

    async fn spawn_mtls_echo_proxy(dir: &TempDir) -> (u16, tokio::task::JoinHandle<()>) {
        let server_cert_pem = std::fs::read(dir.path().join("server.crt")).unwrap();
        let server_key_pem = std::fs::read(dir.path().join("server.key")).unwrap();
        let ca_pem = std::fs::read(dir.path().join("ca.crt")).unwrap();

        let server_certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut Cursor::new(&server_cert_pem))
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .into_iter()
                .map(|c| c.into_owned())
                .collect();
        let server_key = rustls_pemfile::private_key(&mut Cursor::new(&server_key_pem))
            .unwrap()
            .unwrap();

        let ca_certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut Cursor::new(&ca_pem))
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .into_iter()
                .map(|c| c.into_owned())
                .collect();
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(ca_certs);
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_certs, server_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls_stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let io = TokioIo::new(tls_stream);
                    let service = service_fn(|req: Request<Incoming>| async move {
                        let path = req.uri().path();
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
                            "mtls:{path}"
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

        let response = fetch_via_peer(&peer, req, Duration::from_secs(5), None)
            .await
            .expect("peer fetch");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"peer:/via-peer");
    }

    #[tokio::test]
    async fn fetch_via_peer_mtls_with_test_ca() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = TempDir::new().unwrap();
        let tls = gen_peer_mtls_material(&dir);
        let (port, _task) = spawn_mtls_echo_proxy(&dir).await;

        let peer = CachePeer::new(PeerConfig {
            host: "localhost".to_string(),
            port,
            peer_type: PeerType::Parent,
            weight: 1.0,
            icp_port: None,
            max_connections: 10,
        });

        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/secure")
            .body(crate::http_types::empty())
            .unwrap();

        let response = fetch_via_peer(&peer, req, Duration::from_secs(5), Some(&tls))
            .await
            .expect("mtls peer fetch");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"mtls:/secure");
    }

    #[test]
    fn mtls_validate_requires_paths() {
        let cfg = PeerTlsConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
}
