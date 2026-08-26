mod config;
mod dns;
mod doh_dot;
mod server;
mod zone;

use config::Config;
use prometheus::{Encoder, TextEncoder};
use server::Metrics;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use zone::{Zone, ZoneError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,dns_sinkhole=info".into()),
        )
        .init();

    let cfg = Config::from_env().map_err(|e| {
        error!("{e}");
        e
    })?;
    if !cfg.enabled {
        info!("DNS_SINKHOLE_ENABLED=false — exiting");
        return Ok(());
    }

    let zone_path = Path::new(&cfg.zone_path);
    let zone = match Zone::load_path(zone_path) {
        Ok(z) => z,
        // A shadow artifact is a misconfiguration, not a missing file: falling
        // back would hide the fact that someone pointed the sinkhole at
        // observe-only threat-intel output (ADR 0008).
        Err(e @ ZoneError::ShadowArtifact(_)) => {
            error!("{e}");
            return Err(e.into());
        }
        Err(e) => {
            // First boot: fall back to image/example blocklist if compiled zone missing.
            let fallback = Path::new("/etc/bsdm-proxy/blocklist.rpz");
            if fallback.exists() {
                warn!(
                    path = %cfg.zone_path,
                    fallback = %fallback.display(),
                    err = %e,
                    "primary zone missing; loading fallback"
                );
                Zone::load_path(fallback).map_err(|e2| {
                    error!("{e2}");
                    e2
                })?
            } else {
                error!("{e}");
                return Err(e.into());
            }
        }
    };
    info!(
        path = %cfg.zone_path,
        rules = zone.len(),
        "zone loaded"
    );

    let zone: server::SharedZone = Arc::new(std::sync::RwLock::new(Arc::new(zone)));
    let metrics = Arc::new(Metrics::new()?);
    {
        let metrics = metrics.clone();
        let port = cfg.metrics_port;
        let zone_admin = zone.clone();
        let zone_path = cfg.zone_path.clone();
        tokio::spawn(async move {
            run_admin(port, metrics, zone_admin, zone_path).await;
        });
    }

    if cfg.doh_enabled || cfg.dot_enabled {
        if let (Some(cert), Some(key)) = (&cfg.tls_cert_path, &cfg.tls_key_path) {
            match server::load_certs(cert, key) {
                Ok(tls_config) => {
                    let tls_config = Arc::new(tls_config);
                    if cfg.doh_enabled {
                        let c = cfg.clone();
                        let z = zone.clone();
                        let m = metrics.clone();
                        let t = tls_config.clone();
                        tokio::spawn(async move {
                            if let Err(e) = server::run_doh(c, z, m, t).await {
                                error!("DoH server error: {e}");
                            }
                        });
                    }
                    if cfg.dot_enabled {
                        let c = cfg.clone();
                        let z = zone.clone();
                        let m = metrics.clone();
                        let t = tls_config.clone();
                        tokio::spawn(async move {
                            if let Err(e) = server::run_dot(c, z, m, t).await {
                                error!("DoT server error: {e}");
                            }
                        });
                    }
                }
                Err(e) => {
                    error!("Failed to load TLS certificates for DoH/DoT: {e}");
                }
            }
        } else {
            error!("DoH/DoT enabled but TLS_CERT or TLS_KEY path is not set");
        }
    }

    server::run(cfg, zone, metrics).await?;
    Ok(())
}

async fn run_admin(port: u16, metrics: Arc<Metrics>, zone: server::SharedZone, zone_path: String) {
    let addr = format!("0.0.0.0:{port}");
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("admin bind {addr}: {e}");
            return;
        }
    };
    info!("admin http://{addr}/health · POST /api/zone/reload");
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            continue;
        };
        let metrics = metrics.clone();
        let zone = zone.clone();
        let zone_path = zone_path.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let req = String::from_utf8_lossy(&buf);
            let (status, body, ctype) = if req.starts_with("GET /health") {
                ("200 OK", b"ok\n".as_slice(), "text/plain")
            } else if req.starts_with("POST /api/zone/reload")
                || req.starts_with("GET /api/zone/reload")
            {
                match Zone::load_path(Path::new(&zone_path)) {
                    Ok(z) => {
                        let n = z.len();
                        let swapped = {
                            if let Ok(mut g) = zone.write() {
                                *g = Arc::new(z);
                                true
                            } else {
                                false
                            }
                        };
                        if swapped {
                            info!(rules = n, path = %zone_path, "zone reloaded");
                            let msg = format!("{{\"status\":\"reloaded\",\"rules\":{n}}}\n");
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}",
                                msg.len()
                            );
                            let _ = sock.write_all(resp.as_bytes()).await;
                            return;
                        }
                        (
                            "500 Internal Server Error",
                            b"{\"error\":\"lock\"}\n".as_slice(),
                            "application/json",
                        )
                    }
                    Err(e) => {
                        error!("zone reload failed: {e}");
                        let msg = format!("{{\"error\":\"{e}\"}}\n");
                        let resp = format!(
                            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}",
                            msg.len()
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                        return;
                    }
                }
            } else if req.starts_with("GET /metrics") {
                let encoder = TextEncoder::new();
                let families = metrics.registry.gather();
                let mut buf = Vec::new();
                if encoder.encode(&families, &mut buf).is_ok() {
                    let body = String::from_utf8_lossy(&buf).into_owned();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    return;
                }
                (
                    "500 Internal Server Error",
                    b"encode error\n".as_slice(),
                    "text/plain",
                )
            } else {
                ("404 Not Found", b"not found\n".as_slice(), "text/plain")
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.write_all(body).await;
        });
    }
}
