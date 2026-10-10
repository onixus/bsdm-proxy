//! UDP DNS proxy loop.

use crate::config::{BlockAction, Config};
use crate::dns::{
    a_rdata, aaaa_rdata, build_response, formerr, parse_query, Query, CLASS_IN, RCODE_NXDOMAIN,
    TYPE_A, TYPE_AAAA,
};
use crate::doh_dot::{decode_doh_base64url, encode_dot_frame, parse_dot_length};
use crate::zone::{Zone, ZoneAction};
use std::sync::RwLock;

/// Hot-reloadable zone (swap Arc on reload).
pub type SharedZone = Arc<RwLock<Arc<Zone>>>;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use prometheus::{IntCounter, IntCounterVec, Opts, Registry};
use std::convert::Infallible;
use std::fs::File;
use std::io::BufReader;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

pub struct Metrics {
    pub queries: IntCounter,
    pub blocked: IntCounter,
    pub forwarded: IntCounter,
    pub errors: IntCounter,
    /// Queries / connections shed by concurrency limits (AS-13).
    pub dropped: IntCounter,
    /// Upstream datagrams discarded because ID / question did not match (AS-12).
    pub upstream_mismatch: IntCounter,
    pub policy_decision_source: IntCounterVec,
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
        let dropped = IntCounter::new(
            "dns_sinkhole_dropped_total",
            "Queries or connections dropped by concurrency limits",
        )
        .map_err(|e| e.to_string())?;
        let upstream_mismatch = IntCounter::new(
            "dns_sinkhole_upstream_mismatch_total",
            "Upstream responses discarded: ID or question did not match the query",
        )
        .map_err(|e| e.to_string())?;
        let policy_decision_source = IntCounterVec::new(
            Opts::new(
                "bsdm_proxy_policy_decision_source_total",
                "Total policy decisions by decision source",
            ),
            &["source"],
        )
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
        registry
            .register(Box::new(dropped.clone()))
            .map_err(|e| e.to_string())?;
        registry
            .register(Box::new(upstream_mismatch.clone()))
            .map_err(|e| e.to_string())?;
        registry
            .register(Box::new(policy_decision_source.clone()))
            .map_err(|e| e.to_string())?;
        Ok(Self {
            queries,
            blocked,
            forwarded,
            errors,
            dropped,
            upstream_mismatch,
            policy_decision_source,
            registry,
        })
    }
}

pub async fn run(cfg: Config, zone: SharedZone, metrics: Arc<Metrics>) -> Result<(), String> {
    let sock = Arc::new(
        UdpSocket::bind(cfg.bind)
            .await
            .map_err(|e| format!("bind {}: {e}", cfg.bind))?,
    );
    info!(
        bind = %cfg.bind,
        upstream = %cfg.upstream,
        zone_rules = zone.read().map(|z| z.len()).unwrap_or(0),
        action = ?cfg.action,
        "dns-sinkhole listening"
    );

    serve_udp(sock, cfg, zone, metrics).await
}

async fn serve_udp(
    sock: Arc<UdpSocket>,
    cfg: Config,
    zone: SharedZone,
    metrics: Arc<Metrics>,
) -> Result<(), String> {
    // Each in-flight query owns a task and an upstream socket for up to
    // `upstream_timeout`; bound them so a flood cannot exhaust FDs (AS-13).
    let inflight = Arc::new(Semaphore::new(cfg.max_inflight));
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
        let Ok(permit) = inflight.clone().try_acquire_owned() else {
            // Shed load: the client retries, the server stays responsive.
            metrics.dropped.inc();
            debug!("dropping query from {peer}: in-flight limit reached");
            continue;
        };
        let packet = buf[..n].to_vec();
        let sock = sock.clone();
        let zone = zone.clone();
        let metrics = metrics.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            let _permit = permit;
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
    zone: &SharedZone,
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
    zone: &SharedZone,
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

    let zone_snap = zone.read().map_err(|e| format!("zone lock: {e}"))?.clone();
    if let Some(action) = zone_snap.lookup(&query.question.name) {
        metrics.blocked.inc();
        metrics
            .policy_decision_source
            .with_label_values(&["dns"])
            .inc();
        info!(
            domain = %query.question.name,
            decision_source = "dns",
            action = "block",
            "DNS policy decision"
        );
        return Ok(build_block_response(cfg, &query, action));
    }

    metrics.forwarded.inc();
    forward(cfg, packet, &query, metrics).await
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

async fn forward(
    cfg: &Config,
    packet: &[u8],
    query: &Query,
    metrics: &Metrics,
) -> Result<Vec<u8>, String> {
    let local: SocketAddr = if cfg.upstream.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(local)
        .await
        .map_err(|e| format!("upstream bind: {e}"))?;
    // connect(): the kernel now drops datagrams from any source other than
    // the configured upstream (AS-12).
    sock.connect(cfg.upstream)
        .await
        .map_err(|e| format!("upstream connect: {e}"))?;
    sock.send(packet)
        .await
        .map_err(|e| format!("upstream send: {e}"))?;
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + cfg.upstream_timeout;
    loop {
        let n = match tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(format!("upstream recv: {e}")),
            Err(_) => return Err("upstream timeout".into()),
        };
        if is_matching_response(&buf[..n], query) {
            return Ok(buf[..n].to_vec());
        }
        // Wrong ID / question: a forged or stale datagram — keep waiting
        // for the real answer until the deadline.
        metrics.upstream_mismatch.inc();
        debug!(
            "discarding mismatched upstream response for {}",
            query.question.name
        );
    }
}

/// True when `resp` is a response (QR=1) to `query`: same ID and the same
/// single question (name compared case-insensitively — resolvers may echo
/// 0x20-randomised case).
fn is_matching_response(resp: &[u8], query: &Query) -> bool {
    if resp.len() < 12 {
        return false;
    }
    let id = u16::from_be_bytes([resp[0], resp[1]]);
    let qr = resp[2] & 0x80 != 0;
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]);
    let q = &query.question_bytes;
    id == query.id
        && qr
        && qdcount == 1
        && resp
            .get(12..12 + q.len())
            .is_some_and(|echoed| echoed.eq_ignore_ascii_case(q))
}

pub fn load_certs(cert_path: &str, key_path: &str) -> Result<ServerConfig, String> {
    let cert_file = File::open(cert_path).map_err(|e| format!("cert open: {e}"))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .map(|r| r.map(|c| c.into_owned()))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("cert parse: {e}"))?;

    let key_file = File::open(key_path).map_err(|e| format!("key open: {e}"))?;
    let mut key_reader = BufReader::new(key_file);
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .map(|r| r.map(|k| PrivateKeyDer::Pkcs8(k.clone_key())))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("key parse: {e}"))?;
    if keys.is_empty() {
        let key_file = File::open(key_path).map_err(|e| format!("key open: {e}"))?;
        let mut key_reader = BufReader::new(key_file);
        keys = rustls_pemfile::rsa_private_keys(&mut key_reader)
            .map(|r| r.map(|k| PrivateKeyDer::Pkcs1(k.clone_key())))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("key parse: {e}"))?;
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
    zone: SharedZone,
    metrics: Arc<Metrics>,
    tls_config: Arc<ServerConfig>,
) -> Result<(), String> {
    let acceptor = TlsAcceptor::from(tls_config);
    let listener = TcpListener::bind(cfg.dot_bind)
        .await
        .map_err(|e| format!("bind dot {}: {e}", cfg.dot_bind))?;
    info!(bind = %cfg.dot_bind, "dns-sinkhole DoT listening");
    serve_dot(listener, acceptor, cfg, zone, metrics).await
}

async fn serve_dot(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    cfg: Config,
    zone: SharedZone,
    metrics: Arc<Metrics>,
) -> Result<(), String> {
    let conn_limit = Arc::new(Semaphore::new(cfg.max_tcp_connections));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("dot accept: {e}");
                continue;
            }
        };
        let Ok(permit) = conn_limit.clone().try_acquire_owned() else {
            metrics.dropped.inc();
            debug!("dot: connection limit reached, dropping {peer}");
            continue;
        };

        let acceptor = acceptor.clone();
        let zone = zone.clone();
        let metrics = metrics.clone();
        let cfg = cfg.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let tls_stream = match tls_accept(&acceptor, stream, cfg.tls_handshake_timeout).await {
                Ok(s) => s,
                Err(e) => {
                    debug!("dot tls handshake {peer}: {e}");
                    return;
                }
            };
            serve_dot_conn(tls_stream, peer, &cfg, &zone, &metrics).await;
        });
    }
}

/// TLS handshake bounded by `timeout` so silent clients cannot pin a
/// connection slot forever (AS-13).
async fn tls_accept(
    acceptor: &TlsAcceptor,
    stream: tokio::net::TcpStream,
    timeout: Duration,
) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, String> {
    match tokio::time::timeout(timeout, acceptor.accept(stream)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("handshake timeout".into()),
    }
}

/// Serves DNS-over-TLS frames on one (already decrypted) stream. Every read
/// and write is bounded by `cfg.tcp_idle_timeout` (slowloris, AS-13).
async fn serve_dot_conn<S>(
    mut stream: S,
    peer: SocketAddr,
    cfg: &Config,
    zone: &SharedZone,
    metrics: &Metrics,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let idle = cfg.tcp_idle_timeout;
    let mut len_buf = [0u8; 2];
    loop {
        match tokio::time::timeout(idle, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => break,
            Err(_) => {
                debug!("dot idle timeout {peer}");
                break;
            }
        }
        let len = match parse_dot_length(&len_buf) {
            Some(l) => l,
            None => break,
        };
        let mut buf = vec![0u8; len];
        if !matches!(
            tokio::time::timeout(idle, stream.read_exact(&mut buf)).await,
            Ok(Ok(_))
        ) {
            break;
        }

        metrics.queries.inc();
        let resp = match process_dns_query(&buf, cfg, zone, metrics).await {
            Ok(r) => r,
            Err(e) => {
                debug!("dot query error {peer}: {e}");
                break;
            }
        };

        let frame = encode_dot_frame(&resp);
        if !matches!(
            tokio::time::timeout(idle, stream.write_all(&frame)).await,
            Ok(Ok(()))
        ) {
            break;
        }
    }
}

pub async fn run_doh(
    cfg: Config,
    zone: SharedZone,
    metrics: Arc<Metrics>,
    tls_config: Arc<ServerConfig>,
) -> Result<(), String> {
    let acceptor = TlsAcceptor::from(tls_config);
    let listener = TcpListener::bind(cfg.doh_bind)
        .await
        .map_err(|e| format!("bind doh {}: {e}", cfg.doh_bind))?;
    info!(bind = %cfg.doh_bind, path = %cfg.doh_path, "dns-sinkhole DoH listening");
    let conn_limit = Arc::new(Semaphore::new(cfg.max_tcp_connections));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("doh accept: {e}");
                continue;
            }
        };
        let Ok(permit) = conn_limit.clone().try_acquire_owned() else {
            metrics.dropped.inc();
            debug!("doh: connection limit reached, dropping {peer}");
            continue;
        };

        let acceptor = acceptor.clone();
        let zone = zone.clone();
        let metrics = metrics.clone();
        let cfg = cfg.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let tls_stream = match tls_accept(&acceptor, stream, cfg.tls_handshake_timeout).await {
                Ok(s) => s,
                Err(e) => {
                    debug!("doh tls handshake {peer}: {e}");
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            // hyper (re)arms the header-read timer whenever it waits for the
            // next request head, so this is also the keep-alive idle timeout.
            let idle = cfg.tcp_idle_timeout;
            let service = service_fn(move |req: Request<Incoming>| {
                let zone = zone.clone();
                let metrics = metrics.clone();
                let cfg = cfg.clone();
                async move { Ok::<_, Infallible>(handle_doh_request(req, &cfg, &zone, &metrics).await) }
            });

            if let Err(e) = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(idle)
                .serve_connection(io, service)
                .await
            {
                debug!("doh http error {peer}: {e}");
            }
        });
    }
}

/// Upper bound for a DoH POST body. A DNS message cannot exceed 65 535 bytes
/// (RFC 8484 §6 / RFC 1035), so anything larger is rejected before it is
/// buffered — otherwise an unauthenticated client could exhaust memory.
const MAX_DOH_BODY_BYTES: usize = 65_535;

fn doh_text_response(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
    *resp.status_mut() = status;
    resp
}

/// Serves one DoH request (RFC 8484 GET `?dns=` or POST `application/dns-message`).
async fn handle_doh_request<B>(
    req: Request<B>,
    cfg: &Config,
    zone: &SharedZone,
    metrics: &Metrics,
) -> Response<Full<Bytes>>
where
    B: hyper::body::Body,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    if req.uri().path() != cfg.doh_path {
        return doh_text_response(StatusCode::NOT_FOUND, "Not Found");
    }

    let packet = if req.method() == Method::GET {
        let query = req.uri().query().unwrap_or("");
        let dns_param = query.split('&').find_map(|pair| pair.strip_prefix("dns="));
        match dns_param {
            Some(val) => match decode_doh_base64url(val) {
                Ok(p) => p,
                Err(_) => return doh_text_response(StatusCode::BAD_REQUEST, "Invalid dns param"),
            },
            None => return doh_text_response(StatusCode::BAD_REQUEST, "Missing dns param"),
        }
    } else if req.method() == Method::POST {
        if req.headers().get("content-type").map(|v| v.as_bytes())
            != Some(b"application/dns-message")
        {
            return doh_text_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Unsupported media type");
        }
        let limited = http_body_util::Limited::new(req.into_body(), MAX_DOH_BODY_BYTES);
        // A trickled body must not hold the connection open (AS-13).
        match tokio::time::timeout(cfg.tcp_idle_timeout, limited.collect()).await {
            Ok(Ok(body)) => body.to_bytes().to_vec(),
            Ok(Err(e))
                if e.downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some() =>
            {
                return doh_text_response(StatusCode::PAYLOAD_TOO_LARGE, "Payload too large");
            }
            Ok(Err(_)) => return doh_text_response(StatusCode::BAD_REQUEST, "Body error"),
            Err(_) => return doh_text_response(StatusCode::REQUEST_TIMEOUT, "Body timeout"),
        }
    } else {
        return doh_text_response(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed");
    };

    metrics.queries.inc();
    match process_dns_query(&packet, cfg, zone, metrics).await {
        Ok(resp) => {
            let mut response = Response::new(Full::new(Bytes::from(resp)));
            let headers = response.headers_mut();
            headers.insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/dns-message"),
            );
            // "max-age=<u32>" is always a valid header value.
            if let Ok(v) = hyper::header::HeaderValue::from_str(&format!("max-age={}", cfg.ttl)) {
                headers.insert(hyper::header::CACHE_CONTROL, v);
            }
            response
        }
        Err(_) => doh_text_response(StatusCode::INTERNAL_SERVER_ERROR, "Server error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{encode_name, CLASS_IN, TYPE_A};

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
        let zone: SharedZone = Arc::new(RwLock::new(Arc::new(
            Zone::parse("blocked.test CNAME .\n").unwrap(),
        )));
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
            max_inflight: 64,
            max_tcp_connections: 8,
            tls_handshake_timeout: Duration::from_millis(300),
            tcp_idle_timeout: Duration::from_millis(300),
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
        assert_eq!(
            metrics
                .policy_decision_source
                .with_label_values(&["dns"])
                .get(),
            1
        );
    }

    fn doh_fixture() -> (Config, SharedZone, Metrics) {
        let zone: SharedZone = Arc::new(RwLock::new(Arc::new(
            Zone::parse("blocked.test CNAME .\n").unwrap(),
        )));
        let cfg = Config {
            enabled: true,
            bind: "127.0.0.1:0".parse().unwrap(),
            upstream: "127.0.0.1:9".parse().unwrap(),
            zone_path: String::new(),
            action: BlockAction::Sinkhole,
            sinkhole_a: [127, 0, 0, 1],
            sinkhole_aaaa: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ttl: 60,
            metrics_port: 0,
            upstream_timeout: Duration::from_millis(200),
            doh_enabled: true,
            doh_bind: "127.0.0.1:0".parse().unwrap(),
            doh_path: "/dns-query".into(),
            dot_enabled: false,
            dot_bind: "127.0.0.1:0".parse().unwrap(),
            tls_cert_path: None,
            tls_key_path: None,
            max_inflight: 64,
            max_tcp_connections: 8,
            tls_handshake_timeout: Duration::from_millis(300),
            tcp_idle_timeout: Duration::from_millis(300),
        };
        (cfg, zone, Metrics::new().unwrap())
    }

    fn doh_post(body: Vec<u8>) -> Request<Full<Bytes>> {
        Request::builder()
            .method(Method::POST)
            .uri("/dns-query")
            .header("content-type", "application/dns-message")
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }

    #[tokio::test]
    async fn doh_post_answers_blocked_query() {
        let (cfg, zone, metrics) = doh_fixture();
        let resp = handle_doh_request(
            doh_post(sample_query("blocked.test", TYPE_A)),
            &cfg,
            &zone,
            &metrics,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/dns-message"
        );
        assert_eq!(resp.headers().get("cache-control").unwrap(), "max-age=60");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[body.len() - 4..], &[127, 0, 0, 1]);
        assert_eq!(metrics.blocked.get(), 1);
    }

    #[tokio::test]
    async fn doh_post_rejects_oversized_body_without_processing() {
        let (cfg, zone, metrics) = doh_fixture();
        let resp = handle_doh_request(
            doh_post(vec![0u8; MAX_DOH_BODY_BYTES + 1]),
            &cfg,
            &zone,
            &metrics,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(metrics.queries.get(), 0);
    }

    #[tokio::test]
    async fn doh_rejects_wrong_path_method_and_media_type() {
        let (cfg, zone, metrics) = doh_fixture();
        let wrong_path = Request::builder()
            .uri("/other")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(
            handle_doh_request(wrong_path, &cfg, &zone, &metrics)
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        let put = Request::builder()
            .method(Method::PUT)
            .uri("/dns-query")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(
            handle_doh_request(put, &cfg, &zone, &metrics)
                .await
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        let bad_type = Request::builder()
            .method(Method::POST)
            .uri("/dns-query")
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(
            handle_doh_request(bad_type, &cfg, &zone, &metrics)
                .await
                .status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        let missing = Request::builder()
            .uri("/dns-query?foo=bar")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(
            handle_doh_request(missing, &cfg, &zone, &metrics)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(metrics.queries.get(), 0);
    }

    #[test]
    fn load_certs_rejects_malformed_pem_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let bad = "-----BEGIN CERTIFICATE-----\n!!! not base64 !!!\n-----END CERTIFICATE-----\n";
        let cert = dir.path().join("tls.crt");
        let key = dir.path().join("tls.key");
        std::fs::write(&cert, bad).unwrap();
        std::fs::write(&key, bad.replace("CERTIFICATE", "PRIVATE KEY")).unwrap();

        let err = load_certs(cert.to_str().unwrap(), key.to_str().unwrap()).unwrap_err();
        assert!(err.contains("parse"), "unexpected error: {err}");
    }

    fn response_for(query: &[u8], id: u16) -> Vec<u8> {
        let mut r = query.to_vec();
        r[0..2].copy_from_slice(&id.to_be_bytes());
        r[2] |= 0x80; // QR
        r
    }

    /// AS-12: forged datagrams (foreign source, wrong ID, wrong question) are
    /// ignored; the genuine upstream answer is returned.
    #[tokio::test]
    async fn forward_ignores_foreign_source_and_mismatched_responses() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (mut cfg, _zone, metrics) = doh_fixture();
        cfg.upstream = upstream.local_addr().unwrap();
        cfg.upstream_timeout = Duration::from_secs(2);
        let raw = sample_query("clean.test", TYPE_A);
        let query = parse_query(&raw).unwrap();

        let fake = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, forwarder) = upstream.recv_from(&mut buf).await.unwrap();
            let q = buf[..n].to_vec();
            // Off-path attacker: correct ID + question, but a foreign source.
            let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut forged = response_for(&q, 0xABCD);
            forged.push(0xEE);
            attacker.send_to(&forged, forwarder).await.unwrap();
            // From the upstream address but wrong ID / wrong question.
            upstream
                .send_to(&response_for(&q, 0x1111), forwarder)
                .await
                .unwrap();
            let other = response_for(&sample_query("other.test", TYPE_A), 0xABCD);
            upstream.send_to(&other, forwarder).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            // Genuine answer (0x20 case-randomised name is still accepted).
            let mut genuine = response_for(&q, 0xABCD);
            genuine[13] = genuine[13].to_ascii_uppercase();
            upstream.send_to(&genuine, forwarder).await.unwrap();
            genuine
        });

        let resp = forward(&cfg, &raw, &query, &metrics).await.unwrap();
        let genuine = fake.await.unwrap();
        assert_eq!(resp, genuine);
        assert_eq!(metrics.upstream_mismatch.get(), 2);
    }

    #[tokio::test]
    async fn forward_times_out_when_only_mismatched_responses_arrive() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (mut cfg, _zone, metrics) = doh_fixture();
        cfg.upstream = upstream.local_addr().unwrap();
        let raw = sample_query("clean.test", TYPE_A);
        let query = parse_query(&raw).unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, forwarder) = upstream.recv_from(&mut buf).await.unwrap();
            let bad = response_for(&buf[..n], 0x2222);
            upstream.send_to(&bad, forwarder).await.unwrap();
            // Not a response at all (QR=0) with the right ID.
            upstream.send_to(&buf[..n], forwarder).await.unwrap();
        });
        let err = forward(&cfg, &raw, &query, &metrics).await.unwrap_err();
        assert_eq!(err, "upstream timeout");
        assert_eq!(metrics.upstream_mismatch.get(), 2);
    }

    #[test]
    fn matching_response_requires_id_qr_and_question() {
        let raw = sample_query("clean.test", TYPE_A);
        let query = parse_query(&raw).unwrap();
        assert!(is_matching_response(&response_for(&raw, 0xABCD), &query));
        assert!(!is_matching_response(&raw, &query)); // QR=0
        assert!(!is_matching_response(&response_for(&raw, 1), &query));
        assert!(!is_matching_response(&raw[..11], &query));
        let truncated = response_for(&raw, 0xABCD);
        assert!(!is_matching_response(&truncated[..14], &query));
        let aaaa = response_for(&sample_query("clean.test", TYPE_AAAA), 0xABCD);
        assert!(!is_matching_response(&aaaa, &query));
    }

    /// AS-13: with the in-flight limit reached, extra datagrams are shed and
    /// the server keeps answering once the slot frees up.
    #[tokio::test]
    async fn udp_inflight_limit_sheds_excess_queries() {
        // Upstream that never answers: each forwarded query pins its slot.
        let black_hole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (mut cfg, zone, metrics) = doh_fixture();
        cfg.upstream = black_hole.local_addr().unwrap();
        cfg.upstream_timeout = Duration::from_millis(400);
        cfg.max_inflight = 1;
        let metrics = Arc::new(metrics);
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        tokio::spawn(serve_udp(sock, cfg, zone, metrics.clone()));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&sample_query("slow.test", TYPE_A), addr)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        for _ in 0..3 {
            client
                .send_to(&sample_query("blocked.test", TYPE_A), addr)
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(metrics.dropped.get(), 3);

        // After the upstream timeout the slot is released.
        tokio::time::sleep(Duration::from_millis(500)).await;
        client
            .send_to(&sample_query("blocked.test", TYPE_A), addr)
            .await
            .unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[n - 4..n], &[127, 0, 0, 1]);
        assert_eq!(metrics.dropped.get(), 3);
    }

    #[tokio::test]
    async fn dot_conn_answers_queries_and_closes_when_idle() {
        let (cfg, zone, metrics) = doh_fixture();
        let (mut client, server) = tokio::io::duplex(4096);
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let started = std::time::Instant::now();
        let srv = tokio::spawn(async move {
            serve_dot_conn(server, peer, &cfg, &zone, &metrics).await;
        });
        client
            .write_all(&encode_dot_frame(&sample_query("blocked.test", TYPE_A)))
            .await
            .unwrap();
        let mut len = [0u8; 2];
        client.read_exact(&mut len).await.unwrap();
        let mut resp = vec![0u8; u16::from_be_bytes(len) as usize];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp[resp.len() - 4..], &[127, 0, 0, 1]);

        // Client goes silent but keeps the connection open: the server must
        // hang up after the idle timeout (300 ms in the fixture).
        tokio::time::timeout(Duration::from_secs(2), srv)
            .await
            .expect("idle DoT connection was not closed")
            .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(300));
    }

    #[tokio::test]
    async fn dot_conn_closes_on_trickled_frame() {
        let (cfg, zone, metrics) = doh_fixture();
        let (mut client, server) = tokio::io::duplex(4096);
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let srv = tokio::spawn(async move {
            serve_dot_conn(server, peer, &cfg, &zone, &metrics).await;
        });
        // Announce a 100-byte frame, deliver 1 byte, then stall.
        client.write_all(&[0, 100, 0]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), srv)
            .await
            .expect("stalled DoT frame did not time out")
            .unwrap();
    }

    /// Request body that never yields a frame (a stalled client).
    struct StalledBody;

    impl hyper::body::Body for StalledBody {
        type Data = Bytes;
        type Error = Infallible;
        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Infallible>>> {
            std::task::Poll::Pending
        }
    }

    #[tokio::test]
    async fn doh_post_with_stalled_body_times_out() {
        let (cfg, zone, metrics) = doh_fixture();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/dns-query")
            .header("content-type", "application/dns-message")
            .body(StalledBody)
            .unwrap();
        let resp = tokio::time::timeout(
            Duration::from_secs(2),
            handle_doh_request(req, &cfg, &zone, &metrics),
        )
        .await
        .expect("stalled DoH body was not cut off");
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(metrics.queries.get(), 0);
    }

    fn test_tls_acceptor() -> TlsAcceptor {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = CertificateDer::from(ck.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        TlsAcceptor::from(Arc::new(config))
    }

    /// AS-13: silent clients are cut at the handshake deadline and cannot
    /// hold more than `max_tcp_connections` slots.
    #[tokio::test]
    async fn dot_listener_limits_connections_and_times_out_handshake() {
        let (mut cfg, zone, metrics) = doh_fixture();
        cfg.max_tcp_connections = 2;
        let metrics = Arc::new(metrics);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_dot(
            listener,
            test_tls_acceptor(),
            cfg,
            zone,
            metrics.clone(),
        ));

        let mut idle1 = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut idle2 = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Third connection exceeds the limit: closed immediately.
        let mut over = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_millis(200), over.read(&mut b))
            .await
            .expect("over-limit connection was not closed")
            .unwrap_or(0);
        assert_eq!(n, 0);
        assert_eq!(metrics.dropped.get(), 1);

        // Silent clients are disconnected by the 300 ms handshake timeout.
        for s in [&mut idle1, &mut idle2] {
            let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut b))
                .await
                .expect("silent connection survived the handshake timeout")
                .unwrap_or(0);
            assert_eq!(n, 0);
        }
        // Slots are free again: a new connection is accepted (not shed).
        let _fresh = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(metrics.dropped.get(), 1);
    }
}
