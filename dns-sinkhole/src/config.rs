//! Runtime config from environment.

use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockAction {
    /// Answer A/AAAA with configured sinkhole addresses.
    Sinkhole,
    /// Answer NXDOMAIN (RCODE=3).
    NxDomain,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub enabled: bool,
    pub bind: SocketAddr,
    pub upstream: SocketAddr,
    pub zone_path: String,
    pub action: BlockAction,
    pub sinkhole_a: [u8; 4],
    pub sinkhole_aaaa: [u8; 16],
    pub ttl: u32,
    pub metrics_port: u16,
    pub upstream_timeout: Duration,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let enabled = env_bool("DNS_SINKHOLE_ENABLED", true);
        let bind = std::env::var("DNS_SINKHOLE_BIND")
            .unwrap_or_else(|_| "0.0.0.0:53".into())
            .parse()
            .map_err(|e| format!("DNS_SINKHOLE_BIND: {e}"))?;
        let upstream = std::env::var("DNS_SINKHOLE_UPSTREAM")
            .unwrap_or_else(|_| "1.1.1.1:53".into())
            .parse()
            .map_err(|e| format!("DNS_SINKHOLE_UPSTREAM: {e}"))?;
        let zone_path = std::env::var("DNS_SINKHOLE_ZONE_PATH")
            .map_err(|_| "DNS_SINKHOLE_ZONE_PATH is required".to_string())?;
        let action = match std::env::var("DNS_SINKHOLE_ACTION")
            .unwrap_or_else(|_| "sinkhole".into())
            .to_ascii_lowercase()
            .as_str()
        {
            "sinkhole" | "a" => BlockAction::Sinkhole,
            "nxdomain" | "nx" => BlockAction::NxDomain,
            other => return Err(format!("DNS_SINKHOLE_ACTION invalid: {other}")),
        };
        let sinkhole_a =
            parse_ipv4(&std::env::var("DNS_SINKHOLE_A").unwrap_or_else(|_| "127.0.0.1".into()))?;
        let sinkhole_aaaa =
            parse_ipv6(&std::env::var("DNS_SINKHOLE_AAAA").unwrap_or_else(|_| "::1".into()))?;
        let ttl = std::env::var("DNS_SINKHOLE_TTL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300_u32);
        let metrics_port = std::env::var("METRICS_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8092_u16);
        let timeout_ms = std::env::var("DNS_SINKHOLE_UPSTREAM_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2_000_u64);
        Ok(Self {
            enabled,
            bind,
            upstream,
            zone_path,
            action,
            sinkhole_a,
            sinkhole_aaaa,
            ttl: ttl.max(1),
            metrics_port,
            upstream_timeout: Duration::from_millis(timeout_ms.max(1)),
        })
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(default)
}

fn parse_ipv4(s: &str) -> Result<[u8; 4], String> {
    let ip: std::net::Ipv4Addr = s.parse().map_err(|e| format!("DNS_SINKHOLE_A: {e}"))?;
    Ok(ip.octets())
}

fn parse_ipv6(s: &str) -> Result<[u8; 16], String> {
    let ip: std::net::Ipv6Addr = s.parse().map_err(|e| format!("DNS_SINKHOLE_AAAA: {e}"))?;
    Ok(ip.octets())
}
