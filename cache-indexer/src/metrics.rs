//! Prometheus metrics for cache-indexer backends.

use prometheus::{CounterVec, Encoder, Histogram, HistogramOpts, Opts, Registry, TextEncoder};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info};

#[derive(Clone)]
pub struct IndexerMetrics {
    registry: Registry,
    pub inserts_total: CounterVec,
    pub insert_errors_total: CounterVec,
    pub batch_duration_seconds: Histogram,
}

impl IndexerMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();
        let inserts_total = CounterVec::new(
            Opts::new(
                "cache_indexer_inserts_total",
                "Cache events successfully indexed per backend",
            ),
            &["backend"],
        )?;
        let insert_errors_total = CounterVec::new(
            Opts::new(
                "cache_indexer_insert_errors_total",
                "Cache indexer insert failures per backend",
            ),
            &["backend"],
        )?;
        let batch_duration_seconds = Histogram::with_opts(HistogramOpts::new(
            "cache_indexer_batch_duration_seconds",
            "Time spent flushing a Kafka batch to a backend",
        ))?;

        registry.register(Box::new(inserts_total.clone()))?;
        registry.register(Box::new(insert_errors_total.clone()))?;
        registry.register(Box::new(batch_duration_seconds.clone()))?;

        Ok(Self {
            registry,
            inserts_total,
            insert_errors_total,
            batch_duration_seconds,
        })
    }

    pub fn record_success(&self, backend: &str, count: usize, started: Instant) {
        self.inserts_total
            .with_label_values(&[backend])
            .inc_by(count as f64);
        self.batch_duration_seconds
            .observe(started.elapsed().as_secs_f64());
    }

    pub fn record_error(&self, backend: &str) {
        self.insert_errors_total.with_label_values(&[backend]).inc();
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

pub async fn run_metrics_server(port: u16, metrics: Arc<IndexerMetrics>) {
    let bind_addr = format!("0.0.0.0:{port}");
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind cache-indexer metrics on {bind_addr}: {e}");
            return;
        }
    };
    info!("cache-indexer metrics on {bind_addr} (/metrics, /health)");

    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            continue;
        };
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
            let (status, content_type, body): (&str, &str, Vec<u8>) =
                if req.starts_with("GET /metrics") {
                    let encoder = TextEncoder::new();
                    let mut buffer = Vec::new();
                    if encoder
                        .encode(&metrics.registry().gather(), &mut buffer)
                        .is_err()
                    {
                        return;
                    }
                    ("200 OK", "text/plain; version=0.0.4; charset=utf-8", buffer)
                } else if req.starts_with("GET /health") {
                    ("200 OK", "application/json", br#"{"status":"ok"}"#.to_vec())
                } else {
                    ("404 Not Found", "text/plain", b"not found".to_vec())
                };

            let header = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(header.as_bytes()).await;
            let _ = socket.write_all(&body).await;
        });
    }
}
