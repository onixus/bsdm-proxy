//! UDP DNS proxy loop.

use crate::config::{BlockAction, Config};
use crate::dns::{
    a_rdata, aaaa_rdata, build_response, formerr, parse_query, Query, CLASS_IN, RCODE_NXDOMAIN,
    RCODE_SERVFAIL, TYPE_A, TYPE_AAAA,
};
use crate::zone::{Zone, ZoneAction};
use prometheus::{IntCounter, Registry};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

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
    let query = match parse_query(packet) {
        Ok(q) => q,
        Err(e) => {
            let id = if packet.len() >= 2 {
                u16::from_be_bytes([packet[0], packet[1]])
            } else {
                0
            };
            let _ = sock.send_to(&formerr(id), peer).await;
            return Err(e);
        }
    };

    if query.question.qclass != CLASS_IN {
        let resp = build_response(&query, 0, &[]);
        sock.send_to(&resp, peer)
            .await
            .map_err(|e| format!("send: {e}"))?;
        return Ok(());
    }

    if let Some(action) = zone.lookup(&query.question.name) {
        metrics.blocked.inc();
        let resp = build_block_response(cfg, &query, action);
        sock.send_to(&resp, peer)
            .await
            .map_err(|e| format!("send: {e}"))?;
        return Ok(());
    }

    metrics.forwarded.inc();
    let upstream = forward(cfg, packet).await?;
    sock.send_to(&upstream, peer)
        .await
        .map_err(|e| format!("send: {e}"))?;
    Ok(())
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

/// SERVFAIL helper for tests / callers.
#[allow(dead_code)]
pub fn servfail(query: &Query) -> Vec<u8> {
    build_response(query, RCODE_SERVFAIL, &[])
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
