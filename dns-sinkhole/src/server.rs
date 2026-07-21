//! UDP DNS proxy loop.

use crate::config::{BlockAction, Config};
use crate::dns::{
    a_rdata, aaaa_rdata, build_response, formerr, parse_query, Query, CLASS_IN, RCODE_NXDOMAIN,
    RCODE_SERVFAIL, TYPE_A, TYPE_AAAA,
};
use crate::zone::{Zone, ZoneAction};
use crate::doh_dot::{decode_doh_base64url, encode_dot_frame, parse_dot_length};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus::{IntCounter, Registry};
use std::convert::Infallible;
use std::fs::File;
use std::io::BufReader;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

pub struct Metrics {
    pub queries: IntCounter,
    pub blocked: IntCounter,
    pub forwarded: IntCounter,
    pub errors: IntCounter,
    pub registry: Registry,
}

impl Metrics {
    pub fn new() -> Result<Self, String> {
        let registry = Registry::new();
        let queries = IntCounter::new("dns_sinkhole_queries_total", "DNS queries received")
            .map_err(|e| e.to_string())?;
        let blocked = IntCounter::new("dns_sinkhole_blocked_total", "Queries blocked by zone")
            .map_err(|e| e.to_string())?;
        let forwarded =
            IntCounter::new("dns_sinkhole_forwarded_total", "Queries forwarded upstream")
                .map_err(|e| e.to_string())?;
        let errors = IntCounter::new("dns_sinkhole_errors_total", "Handler errors")
            .map_err(|e| e.to_string())?;
        registry
            .register(Box::new(queries.clone()))
            .map_err(|e| e.to_string())?;
        registry
            .register(Box::new(blocked.clone()))
            .map_err(|e| e.to_string())?;
        registry
            .register(Box::new(forwarded.clone()))
            .map_err(|e| e.to_string())?;
        registry
            .register(Box::new(errors.clone()))
            .map_err(|e| e.to_string())?;
        Ok(Self {
            queries,
            blocked,
            forwarded,
            errors,
            registry,
        })
    }
}

pub async fn run(cfg: Config, zone: Arc<Zone>, metrics: Arc<Metrics>) -> Result<(), String> {
    let sock = Arc::new(
        UdpSocket::bind(cfg.bind)
            .await
            .map_err(|e| format!("bind {}: {e}", cfg.bind))?,
    );
    info!(
        bind = %cfg.bind,
        upstream = %cfg.upstream,
        zone_rules = zone.len(),
        action = ?cfg.action,
        "dns-sinkhole listening"
    );

    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!("recv: {e}");
                metrics.errors.inc();
                continue;
            }
        };
        metrics.queries.inc();
        let packet = buf[..n].to_vec();
        let sock = sock.clone();
        let zone = zone.clone();
        let metrics = metrics.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_one(&sock, peer, &packet, &cfg, &zone, &metrics).await {
                debug!("handle {peer}: {e}");
                metrics.errors.inc();
            }
        });
    }
}

async fn handle_one(
    sock: &UdpSocket,
    peer: SocketAddr,
    packet: &[u8],
    cfg: &Config,
    zone: &Zone,
    metrics: &Metrics,
) -> Result<(), String> {
    let resp = process_dns_query(packet, cfg, zone, metrics).await?;
    sock.send_to(&resp, peer)
        .await
        .map_err(|e| format!("send: {e}"))?;
    Ok(())
}

pub async fn process_dns_query(
    packet: &[u8],
    cfg: &Config,
    zone: &Zone,
    metrics: &Metrics,
) -> Result<Vec<u8>, String> {
    let query = match parse_query(packet) {
        Ok(q) => q,
        Err(_) => {
            let id = if packet.len() >= 2 {
                u16::from_be_bytes([packet[0], packet[1]])
            } else {
                0
            };
            return Ok(formerr(id));
        }
    };

    if query.question.qclass != CLASS_IN {
        return Ok(build_response(&query, 0, &[]));
    }

    if let Some(action) = zone.lookup(&query.question.name) {
        metrics.blocked.inc();
        return Ok(build_block_response(cfg, &query, action));
    }

    metrics.forwarded.inc();
    forward(cfg, packet).await
}

fn build_block_response(cfg: &Config, query: &Query, action: &ZoneAction) -> Vec<u8> {
    match action {
        ZoneAction::A(ip) if query.question.qtype == TYPE_A || query.question.qtype == 255 => {
            let rdata = a_rdata(*ip);
            build_response(query, 0, &[(TYPE_A, cfg.ttl, &rdata)])
        }
        ZoneAction::Aaaa(ip)
            if query.question.qtype == TYPE_AAAA || query.question.qtype == 255 =>
        {
            let rdata = aaaa_rdata(*ip);
            build_response(query, 0, &[(TYPE_AAAA, cfg.ttl, &rdata)])
        }
        ZoneAction::A(_) | ZoneAction::Aaaa(_) => {
            // Wrong type for explicit RR — empty NOERROR (NODATA)
            build_response(query, 0, &[])
        }
        ZoneAction::Policy => match cfg.action {
            BlockAction::NxDomain => build_response(query, RCODE_NXDOMAIN, &[]),
            BlockAction::Sinkhole => match query.question.qtype {
                TYPE_A => {
                    let ip = Ipv4Addr::from(cfg.sinkhole_a);
                    let rdata = a_rdata(ip);
                    build_response(query, 0, &[(TYPE_A, cfg.ttl, &rdata)])
                }
                TYPE_AAAA => {
                    let ip = Ipv6Addr::from(cfg.sinkhole_aaaa);
                    let rdata = aaaa_rdata(ip);
                    build_response(query, 0, &[(TYPE_AAAA, cfg.ttl, &rdata)])
                }
                _ => build_response(query, RCODE_NXDOMAIN, &[]),
            },
        },
    }
}

async fn forward(cfg: &Config, packet: &[u8]) -> Result<Vec<u8>, String> {
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("upstream bind: {e}"))?;
    sock.send_to(packet, cfg.upstream)
        .await
        .map_err(|e| format!("upstream send: {e}"))?;
    let mut buf = vec![0u8; 4096];
    let result = tokio::time::timeout(cfg.upstream_timeout, sock.recv_from(&mut buf)).await;
    match result {
        Ok(Ok((n, _))) => Ok(buf[..n].to_vec()),
        Ok(Err(e)) => Err(format!("upstream recv: {e}")),
        Err(_) => Err("upstream timeout".into()),
    }
}

pub fn load_certs(cert_path: &str, key_path: &str) -> Result<ServerConfig, String> {
    let cert_file = File::open(cert_path).map_err(|e| format!("cert open: {e}"))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .map(|r| r.unwrap().into_owned())
        .collect();

    let key_file = File::open(key_path).map_err(|e| format!("key open: {e}"))?;
    let mut key_reader = BufReader::new(key_file);
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .map(|r| PrivateKeyDer::Pkcs8(r.unwrap().into_owned()))
        .collect::<Vec<_>>();
    if keys.is_empty() {
        let key_file = File::open(key_path).map_err(|e| format!("key open: {e}"))?;
        let mut key_reader = BufReader::new(key_file);
        keys = rustls_pemfile::rsa_private_keys(&mut key_reader)
            .map(|r| PrivateKeyDer::Pkcs1(r.unwrap().into_owned()))
            .collect::<Vec<_>>();
    }
    if keys.is_empty() {
        return Err("No private keys found".into());
    }

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))
        .map_err(|e| format!("tls config: {e}"))
}

pub async fn run_dot(
    cfg: Config,
    zone: Arc<Zone>,
    metrics: Arc<Metrics>,
    tls_config: Arc<ServerConfig>,
) -> Result<(), String> {
    let acceptor = TlsAcceptor::from(tls_config);
    let listener = TcpListener::bind(cfg.dot_bind)
        .await
        .map_err(|e| format!("bind dot {}: {e}", cfg.dot_bind))?;
    info!(bind = %cfg.dot_bind, "dns-sinkhole DoT listening");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("dot accept: {e}");
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let zone = zone.clone();
        let metrics = metrics.clone();
        let cfg = cfg.clone();

        tokio::spawn(async move {
            let mut tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    debug!("dot tls handshake {peer}: {e}");
                    return;
                }
            };

            let mut len_buf = [0u8; 2];
            loop {
                if tls_stream.read_exact(&mut len_buf).await.is_err() {
                    break;
                }
                let len = match parse_dot_length(&len_buf) {
                    Some(l) => l,
                    None => break,
                };
                let mut buf = vec![0u8; len];
                if tls_stream.read_exact(&mut buf).await.is_err() {
                    break;
                }

                metrics.queries.inc();
                let resp = match process_dns_query(&buf, &cfg, &zone, &metrics).await {
                    Ok(r) => r,
                    Err(e) => {
                        debug!("dot query error {peer}: {e}");
                        break;
                    }
                };

                let frame = encode_dot_frame(&resp);
                if tls_stream.write_all(&frame).await.is_err() {
                    break;
                }
            }
        });
    }
}

pub async fn run_doh(
    cfg: Config,
    zone: Arc<Zone>,
    metrics: Arc<Metrics>,
    tls_config: Arc<ServerConfig>,
) -> Result<(), String> {
    let acceptor = TlsAcceptor::from(tls_config);
    let listener = TcpListener::bind(cfg.doh_bind)
        .await
        .map_err(|e| format!("bind doh {}: {e}", cfg.doh_bind))?;
    info!(bind = %cfg.doh_bind, path = %cfg.doh_path, "dns-sinkhole DoH listening");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("doh accept: {e}");
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let zone = zone.clone();
        let metrics = metrics.clone();
        let cfg = cfg.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    debug!("doh tls handshake {peer}: {e}");
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let service = service_fn(move |req: Request<Incoming>| {
                let zone = zone.clone();
                let metrics = metrics.clone();
                let cfg = cfg.clone();
                async move {
                    if req.uri().path() != cfg.doh_path {
                        return Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Full::new(Bytes::from("Not Found")))
                                .unwrap(),
                        );
                    }

                    let packet = if req.method() == Method::GET {
                        let query = req.uri().query().unwrap_or("");
                        let mut dns_param = None;
                        for pair in query.split('&') {
                            if let Some(val) = pair.strip_prefix("dns=") {
                                dns_param = Some(val);
                                break;
                            }
                        }
                        match dns_param {
                            Some(val) => match decode_doh_base64url(val) {
                                Ok(p) => p,
                                Err(_) => {
                                    return Ok::<_, Infallible>(
                                        Response::builder()
                                            .status(StatusCode::BAD_REQUEST)
                                            .body(Full::new(Bytes::from("Invalid dns param")))
                                            .unwrap(),
                                    );
                                }
                            },
                            None => {
                                return Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Full::new(Bytes::from("Missing dns param")))
                                        .unwrap(),
                                );
                            }
                        }
                    } else if req.method() == Method::POST {
                        if req.headers().get("content-type").map(|v| v.as_bytes())
                            != Some(b"application/dns-message")
                        {
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                                    .body(Full::new(Bytes::from("Unsupported media type")))
                                    .unwrap(),
                            );
                        }
                        match req.into_body().collect().await {
                            Ok(body) => body.to_bytes().to_vec(),
                            Err(_) => {
                                return Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Full::new(Bytes::from("Body error")))
                                        .unwrap(),
                                );
                            }
                        }
                    } else {
                        return Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::METHOD_NOT_ALLOWED)
                                .body(Full::new(Bytes::from("Method not allowed")))
                                .unwrap(),
                        );
                    };

                    metrics.queries.inc();
                    match process_dns_query(&packet, &cfg, &zone, &metrics).await {
                        Ok(resp) => Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/dns-message")
                                .header("cache-control", format!("max-age={}", cfg.ttl))
                                .body(Full::new(Bytes::from(resp)))
                                .unwrap(),
                        ),
                        Err(_) => Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Full::new(Bytes::from("Server error")))
                                .unwrap(),
                        ),
                    }
                }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                debug!("doh http error {peer}: {e}");
            }
        });
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{encode_name, CLASS_IN, TYPE_A};
    use std::time::Duration;

    fn sample_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&0xABCDu16.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&encode_name(name));
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }

    #[tokio::test]
    async fn blocks_zone_name_with_sinkhole() {
        let zone = Arc::new(Zone::parse("blocked.test CNAME .\n").unwrap());
        let metrics = Arc::new(Metrics::new().unwrap());
        let cfg = Config {
            enabled: true,
            bind: "127.0.0.1:0".parse().unwrap(),
            upstream: "1.1.1.1:53".parse().unwrap(),
            zone_path: String::new(),
            action: BlockAction::Sinkhole,
            sinkhole_a: [127, 0, 0, 1],
            sinkhole_aaaa: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ttl: 60,
            metrics_port: 0,
            upstream_timeout: Duration::from_millis(500),
            doh_enabled: true,
            doh_bind: "127.0.0.1:0".parse().unwrap(),
            doh_path: "/dns-query".into(),
            dot_enabled: true,
            dot_bind: "127.0.0.1:0".parse().unwrap(),
            tls_cert_path: None,
            tls_key_path: None,
        };
        let sock = Arc::new(UdpSocket::bind(cfg.bind).await.unwrap());
        let addr = sock.local_addr().unwrap();
        let zone_c = zone.clone();
        let metrics_c = metrics.clone();
        let cfg_c = cfg.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
            handle_one(&sock, peer, &buf[..n], &cfg_c, &zone_c, &metrics_c)
                .await
                .unwrap();
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let q = sample_query("blocked.test", TYPE_A);
        client.send_to(&q, addr).await.unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 12);
        assert_eq!(buf[3] & 0x0f, 0); // NOERROR
        assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 1); // ANCOUNT
        assert_eq!(&buf[n - 4..n], &[127, 0, 0, 1]);
        assert_eq!(metrics.blocked.get(), 1);
    }
}
