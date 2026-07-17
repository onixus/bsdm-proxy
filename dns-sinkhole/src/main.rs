mod config;
mod dns;
mod server;
mod zone;

use config::Config;
use prometheus::{Encoder, TextEncoder};
use server::Metrics;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info};
use zone::Zone;

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

    let zone = Zone::load_path(Path::new(&cfg.zone_path)).map_err(|e| {
        error!("{e}");
        e
    })?;
    info!(
        path = %cfg.zone_path,
        rules = zone.len(),
        "zone loaded"
    );

    let metrics = Arc::new(Metrics::new()?);
    {
        let metrics = metrics.clone();
        let port = cfg.metrics_port;
        tokio::spawn(async move {
            run_admin(port, metrics).await;
        });
    }

    let zone = Arc::new(zone);
    server::run(cfg, zone, metrics).await?;
    Ok(())
}

async fn run_admin(port: u16, metrics: Arc<Metrics>) {
    let addr = format!("0.0.0.0:{port}");
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("admin bind {addr}: {e}");
            return;
        }
    };
    info!("admin http://{addr}/health");
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            continue;
        };
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let req = String::from_utf8_lossy(&buf);
            let (status, body, ctype) = if req.starts_with("GET /health") {
                ("200 OK", b"ok\n".as_slice(), "text/plain")
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
